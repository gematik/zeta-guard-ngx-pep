/*-
 * #%L
 * ngx_pep
 * %%
 * (C) tech@Spree GmbH, 2026, licensed for gematik GmbH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 * #L%
 */

//! OTEL metric instruments.
//!
//! Instruments bind to the *global* meter provider at first use and never
//! re-bind. They must not be touched before `otel::install` has registered
//! the provider in worker init — otherwise they are permanently no-op for
//! that worker. Request handlers and cache tasks all start after worker
//! init, so this holds naturally; don't use these from `postconfiguration`.
//!
//! Attribute values must come from small closed sets — every distinct
//! attribute combination is a separate time series, held and exported for
//! the rest of the worker's life. Never put cids, kids, URLs or other
//! unbounded/client-controlled values here.

use std::sync::LazyLock;

use opentelemetry::metrics::{Counter, Histogram};

/// JWKS refresh attempts, by `target` (pdp|popp) and `outcome`
/// (ok|err_in_grace|err_dropped).
pub static JWK_REFRESH: LazyLock<Counter<u64>> = LazyLock::new(|| {
    opentelemetry::global::meter("ngx_pep")
        .u64_counter("zeta.jwk_cache.refresh")
        .with_description("JWKS refresh attempts by target and outcome")
        .build()
});

/// Sessions added to the block list, counted on insert only. Extending a block
/// (a later `until` for a sid already held) is the same revocation arriving with
/// a different bound — the reporting pod learns `until` from the token's `exp`,
/// a session-end event derives it from `accessTokenLifespan` — so counting it
/// would double-count one blocked session.
///
/// **Replicated, not sharded**: every pod's subscriber receives every block, so
/// each pod counts all of them. Query with `max`, never `sum` — the same rule as
/// `zeta.session.blocked`. Exported as `zeta_session_blocked_count_total`.
pub static SESSION_BLOCKED_COUNT: LazyLock<Counter<u64>> = LazyLock::new(|| {
    opentelemetry::global::meter("ngx_pep")
        .u64_counter("zeta.session.blocked_count")
        .with_description("Access sessions added to the block list")
        .build()
});

/// Requests denied because their `sid` is on the block list. One per request, so
/// a single block can produce many. Sharded per worker, so `sum` is correct.
/// Exported as `zeta_blocked_request_count_total`.
pub static BLOCKED_REQUEST_COUNT: LazyLock<Counter<u64>> = LazyLock::new(|| {
    opentelemetry::global::meter("ngx_pep")
        .u64_counter("zeta.blocked_request_count")
        .with_description("Requests rejected because their session is blocked")
        .build()
});

/// Impossible-travel detections: the token's `ip_address` claim did not match the
/// request's client IP. Counted whether or not `pep_revocation_url` is set — the
/// request is rejected either way, only the report to the PDP depends on it.
/// Sharded per worker, so `sum` is correct.
/// Exported as `zeta_impossible_travel_count_total`.
pub static IMPOSSIBLE_TRAVEL_COUNT: LazyLock<Counter<u64>> = LazyLock::new(|| {
    opentelemetry::global::meter("ngx_pep")
        .u64_counter("zeta.impossible_travel_count")
        .with_description("Requests whose token IP did not match the client IP")
        .build()
});

/// Stable HTTP semconv server-request duration. Fed from the log-phase
/// handler so it covers the full request (access phase + content/upstream),
/// for every request, with the final response status. Bucket boundaries are
/// the semconv-recommended set — the SDK defaults are ms-scaled and wrong
/// for a seconds-unit instrument.
pub static HTTP_SERVER_REQUEST_DURATION: LazyLock<Histogram<f64>> = LazyLock::new(|| {
    opentelemetry::global::meter("ngx_pep")
        .f64_histogram("http.server.request.duration")
        .with_unit("s")
        .with_description("Duration of HTTP server requests")
        .with_boundaries(vec![
            0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0,
        ])
        .build()
});

#[cfg(not(test))]
static OBSERVABLES_REGISTERED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

/// Register the observable (pull-style) gauges. Their callbacks run on the
/// metrics PeriodicReader thread once per export interval — never on the
/// request path.
///
/// Call once per worker from `init_worker`, *after* `otel::install` (the
/// global meter must be live, see module docs) and after the caches exist.
/// Every worker registers; the per-worker `service.instance.id` resource
/// attribute keeps the series apart — query with `max by (...)`. The session
/// gauge reads shared shm, so all workers report the same (correct) value.
///
/// Each callback skips its observation when the underlying value is
/// unavailable (feature unconfigured, never fetched, lock contended) — gaps
/// in a gauge series are well-defined, wrong values are not.
#[cfg(not(test))]
pub fn register_observables() {
    use crate::asl::SESSION_CACHE;
    use crate::jwk_cache::JWK_CACHE;
    use crate::pep::BLOCK_LIST;

    if OBSERVABLES_REGISTERED.set(()).is_err() {
        return;
    }
    let meter = opentelemetry::global::meter("ngx_pep");

    // Initialize the LazyLock on this (the event-loop) thread: the first
    // deref touches ngx_cycle, which must not happen on the reader thread.
    let session_cache = LazyLock::force(&SESSION_CACHE);
    let _sessions = meter
        .u64_observable_gauge("zeta.asl.sessions.active")
        .with_description("Entries (handshakes + sessions) in the shared ASL session cache")
        .with_callback(move |observer| {
            observer.observe(session_cache.session_count(), &[]);
        })
        .build();

    // Initialize the LazyLock on this (the event-loop) thread: the first
    // deref touches ngx_cycle, which must not happen on the reader thread.
    let block_list = LazyLock::force(&BLOCK_LIST);
    let _sessions = meter
        .u64_observable_gauge("zeta.session.blocked")
        .with_description("Number of currently blocked access sessions")
        .with_callback(move |observer| {
            observer.observe(block_list.blocked_count(), &[]);
        })
        .build();

    // Staleness gauges: the alertable signal is *absence* of refresh activity
    // (responder down, IdP unreachable) — which produces no spans or logs,
    // only a climbing age. Alert thresholds: refresh interval/TTL + grace.
    let _jwk_age = meter
        .u64_observable_gauge("zeta.jwk_cache.age")
        .with_unit("s")
        .with_description("Seconds since the last successful JWKS refresh, by target")
        .with_callback(|observer| {
            if let Some(cache) = JWK_CACHE.get() {
                for (target, age) in cache.staleness_secs() {
                    if let Some(age) = age {
                        observer.observe(age, &[opentelemetry::KeyValue::new("target", target)]);
                    }
                }
            }
        })
        .build();

    let _ocsp_age = meter
        .u64_observable_gauge("zeta.ocsp.response.age")
        .with_unit("s")
        .with_description("Seconds since the last successful OCSP fetch")
        .with_callback(|observer| {
            use crate::ocsp_cache::OCSP_CACHE;

            if let Some(age) = OCSP_CACHE.get().and_then(|c| c.response_age_secs()) {
                observer.observe(age, &[]);
            }
        })
        .build();

    let _cert_expiry = meter
        .i64_observable_gauge("zeta.asl.signer_cert.expiry")
        .with_unit("s")
        .with_description("not_after of the ASL signer certificate, epoch seconds")
        .with_callback(|observer| {
            use crate::asl_keys::SIGNER_NOT_AFTER_EPOCH;

            if let Some(&epoch) = SIGNER_NOT_AFTER_EPOCH.get() {
                observer.observe(epoch, &[]);
            }
        })
        .build();
}
