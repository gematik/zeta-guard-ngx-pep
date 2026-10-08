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

use std::env;
use std::sync::OnceLock;

use bytes::Bytes;
use nginx_sys::{
    ngx_conf_t, ngx_hash_key_t, ngx_http_compile_complex_value, ngx_http_compile_complex_value_t,
    ngx_http_complex_value_t, ngx_int_t, ngx_str_t,
};
use ngx::http::HttpModuleMainConf;
use ngx::http::{NgxHttpCoreModule, Request};
use ngx::ngx_string;
use opentelemetry::trace::{
    SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState, TracerProvider,
};
use opentelemetry::{Context, KeyValue};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{LogExporter, MetricExporter, SpanExporter};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::resource::{EnvResourceDetector, TelemetryResourceDetector};
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use reqwest::header::HeaderMap;
use reqwest::{RequestBuilder, StatusCode};
use tracing::{Instrument, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::fmt::FormatEvent;
use tracing_subscriber::fmt::FormatFields;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

use crate::request_ops::RequestOps;

static PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();
static LOGGER_PROVIDER: OnceLock<SdkLoggerProvider> = OnceLock::new();
static METER_PROVIDER: OnceLock<SdkMeterProvider> = OnceLock::new();

static mut OTEL_TRACE_ID_CV: ngx_http_complex_value_t = ngx_http_complex_value_t {
    value: ngx_str_t {
        len: 0,
        data: std::ptr::null_mut(),
    },
    ..unsafe { std::mem::zeroed() }
};
static mut OTEL_SPAN_ID_CV: ngx_http_complex_value_t = ngx_http_complex_value_t {
    value: ngx_str_t {
        len: 0,
        data: std::ptr::null_mut(),
    },
    ..unsafe { std::mem::zeroed() }
};
static mut OTEL_PARENT_SAMPLED_CV: ngx_http_complex_value_t = ngx_http_complex_value_t {
    value: ngx_str_t {
        len: 0,
        data: std::ptr::null_mut(),
    },
    ..unsafe { std::mem::zeroed() }
};
static ANCHOR_ENABLED: OnceLock<bool> = OnceLock::new();

/// Postconfiguration: pre-compile complex values for the three nginx-otel
/// variables, so per-request anchoring is a cheap lookup. Auto-degrades to a
/// no-op if nginx-otel isn't loaded (variables not registered). Returns the
/// underlying compile error only if the variables exist but compilation fails.
///
/// # Safety
/// `cf` must be a valid pointer to an `ngx_conf_t` during postconfiguration.
pub unsafe fn compile_anchor_cvs(cf: *mut ngx_conf_t) -> ngx_int_t {
    if !unsafe { variable_registered(cf, b"otel_trace_id") } {
        tracing::info!("nginx-otel not loaded — skipping span anchoring");
        return 0;
    }

    let cvs: [(ngx_str_t, *mut ngx_http_complex_value_t); 3] = [
        (ngx_string!("$otel_trace_id"), &raw mut OTEL_TRACE_ID_CV),
        (ngx_string!("$otel_span_id"), &raw mut OTEL_SPAN_ID_CV),
        (
            ngx_string!("$otel_parent_sampled"),
            &raw mut OTEL_PARENT_SAMPLED_CV,
        ),
    ];
    for (mut value, cv) in cvs {
        let mut ccv: ngx_http_compile_complex_value_t = unsafe { std::mem::zeroed() };
        ccv.cf = cf;
        ccv.value = &mut value;
        ccv.complex_value = cv;
        let rc = unsafe { ngx_http_compile_complex_value(&mut ccv) };
        if rc != 0 {
            return rc;
        }
    }
    let _ = ANCHOR_ENABLED.set(true);
    0
}

unsafe fn variable_registered(cf: *mut ngx_conf_t, name: &[u8]) -> bool {
    let cmcf = match unsafe { NgxHttpCoreModule::main_conf_mut(&*cf) } {
        Some(c) => c,
        None => return false,
    };
    let vk = cmcf.variables_keys;
    if vk.is_null() {
        return false;
    }
    let keys = unsafe { &(*vk).keys };
    let elts = keys.elts as *const ngx_hash_key_t;
    for i in 0..keys.nelts {
        let entry = unsafe { &*elts.add(i) };
        let entry_name = unsafe { std::slice::from_raw_parts(entry.key.data, entry.key.len) };
        if entry_name == name {
            return true;
        }
    }
    false
}

/// Build the outer handler tracing span for an inbound request — fully
/// configured: parent attached (nginx-otel server span → W3C traceparent → root),
/// `otel.kind` set (`internal` under nginx-otel, `server` otherwise, for local dev without
/// nginx-otel)
///
/// ```ignore
/// let span = otel::request_span!("pep::request", request);
/// ```
macro_rules! request_span {
    ($name:expr, $request:expr) => {{
        // Reborrow as shared reference so the caller's `&mut Request` survives.
        let req: &::ngx::http::Request = $request;
        match $crate::otel::InboundParent::from_request(req) {
            $crate::otel::InboundParent::NginxOtel(ctx) => {
                // Attach the OTEL Context as current *before* creating the
                // tracing span; tracing-opentelemetry's on_new_span picks up
                // the parent — and crucially the parent's trace_id — from
                // the active OTEL Context. Calling set_parent on an already-
                // created span only updates the parent reference, not the
                // span's trace_id (tracing-opentelemetry 0.31 behavior).
                // _attached lives until the end of this match arm; long
                // enough for info_span! to capture the parent.
                let _attached = ::opentelemetry::Context::attach(ctx);
                ::tracing::info_span!(
                    $name,
                    otel.kind = "internal",
                )
            }
            inbound => {
                // Same context-attach trick — Option-mapped because there may
                // be no inbound parent (root SERVER) for the InboundParent::None
                // case.
                let _attached = inbound.into_context().map(::opentelemetry::Context::attach);
                // NOTE: this span is only for when there is no nginx-otel, e.g. local dev.
                // Semconv delibrately ignored here, as it isn't trivial to figure out all the
                // required items like http.route.
                let span = ::tracing::info_span!(
                    $name,
                    otel.kind = "server",
                );
                span
            }
        }
    }};
}
pub(crate) use request_span;

/// Wrap an outbound `reqwest::RequestBuilder` in a CLIENT span: creates the
/// span (parented at the current span), injects its context as a W3C
/// `traceparent` header, and returns `(builder, span)`. Hand both to
/// [`traced_request`], which drives the send inside the span and records the
/// response fields — see `asl::handle_subrequest` for the full pattern.
///
/// CLIENT spans pair with the downstream server span, giving the trace
/// service-graph edges and per-hop RED metrics. The `http.response.status_code`
/// field is pre-declared `Empty` so the late `record` in `traced_request` has a
/// slot.
///
/// NOTE: We fill these via the tracing `record()` API rather than the
/// OpenTelemetry-specific `set_attribute()`. `record()` feeds tracing's field
/// machinery, so the value reaches *every* subscriber layer (the OTel span
/// export *and* the stdout formatter); `set_attribute()` writes straight to the
/// OTel `SpanData` and is invisible to anything that isn't the OTel layer.
///
/// The catch: the field names in `info_span!` must be *literals* (bare dotted
/// idents or string literals) — they become static callsite metadata, so a
/// `const`/`static` won't do. That rules out the opentelemetry-semantic-
/// conventions constants here; for consistency we don't use that crate at all.
macro_rules! traced_outbound {
    ( $client:expr, $method:expr, $url:expr, $name:literal ) => {{
        use ::tracing::field::Empty;

        let builder = $client.request($method.clone(), $url.clone());
        let span = ::tracing::info_span!(
            $name,
            otel.kind = "client",
            http.request.method = $method.to_string(),
            server.address = $url.host_str().unwrap().to_string(),
            server.port = Empty,
            url.full = $url.to_string(),
            http.response.status_code = Empty,
            http.response.body.size = Empty,
            error.type = Empty,
        );

        if let Some(port) = $url.port_or_known_default() {
            span.record("server.port", port as i64);
        }

        match $crate::otel::span_traceparent(&span) {
            Some(traceparent) => (builder.header("traceparent", traceparent), span),
            None => (builder, span),
        }
    }};
}
pub(crate) use traced_outbound;

/// Drive an outbound request to completion *inside* its CLIENT span: the span
/// brackets `send()` *and* the streamed `bytes()`, and records
/// `http.response.status_code` / `http.response.body.size` on success.
///
/// Returns `(status, headers, body)` for *any* completed response — the
/// response is consumed to read the streamed body, so anything the caller still
/// needs from it (status, cache headers) is handed back here.
///
/// **Transport-neutral**: a non-2xx HTTP status is *not* an error here, so this
/// is safe for the proxy relay path (`asl::handle_subrequest` forwards the
/// upstream's status verbatim). Whether a bad status is fatal is the caller's
/// policy — `jwk_cache`/`ocsp_cache` check `status` and bail themselves.
///
/// Errors carry `#[instrument(err)]`-style semantics: **silent on success**,
/// but on a genuine transport/body failure the span gets `error.type` and an
/// `error!` event (`status_code` is recorded first when a response arrived).
pub async fn traced_request(
    builder: RequestBuilder,
    span: Span,
) -> reqwest::Result<(StatusCode, HeaderMap, Bytes)> {
    async move {
        // current span == the instrumented `span`; record while still inside it
        let span = Span::current();

        let result = async {
            let response = builder.send().await?;
            let status = response.status();
            span.record("http.response.status_code", status.as_u16() as i64);

            let headers = response.headers().clone();
            let body = response.bytes().await?; // still bracketed — body is streamed here
            span.record("http.response.body.size", body.len() as i64);

            Ok::<_, reqwest::Error>((status, headers, body))
        }
        .await;

        if let Err(err) = &result {
            span.record("error.type", classify_error(err));
            // Same event shape as `#[instrument(err)]`: the `error` field carries
            // the text and the message body is empty, so the collector's
            // `transform/error_body` (body ← attributes["error"]) fills it in.
            tracing::error!(error = %err);
        }
        result
    }
    .instrument(span)
    .await
}

/// Low-cardinality `error.type` value (OTel semconv) for a failed outbound
/// request. `traced_request` is transport-neutral (no `error_for_status`), so
/// these are always send/body failures — never carry an HTTP status.
fn classify_error(err: &reqwest::Error) -> &'static str {
    if err.is_timeout() {
        "timeout"
    } else if err.is_connect() {
        "connection_error"
    } else if err.is_body() {
        "body_error"
    } else {
        "request_error"
    }
}

/// Result of inspecting an inbound request for trace context. Drives both the
/// parent to attach to the outer handler span and the `SpanKind` it should
/// declare:
///
/// - [`InboundParent::NginxOtel`]: nginx-otel created a `SERVER` span for this
///   request already. Our outer handler should be `INTERNAL` (work *inside*
///   the server) and skip HTTP semconv attributes (nginx-otel records them).
/// - [`InboundParent::Traceparent`]: no nginx-otel, but a W3C `traceparent`
///   header is present. *We* are the `SERVER` entry point, parented at the
///   inbound context. Our outer handler should set HTTP semconv attrs.
/// - [`InboundParent::None`]: no upstream trace context. We are the `SERVER`
///   root.
pub enum InboundParent {
    NginxOtel(Context),
    Traceparent(Context),
    None,
}

impl InboundParent {
    pub fn from_request(request: &Request) -> Self {
        if let Some(ctx) = nginx_otel_parent(request) {
            return Self::NginxOtel(ctx);
        }
        if let Some(ctx) = traceparent_header_parent(request) {
            return Self::Traceparent(ctx);
        }
        Self::None
    }

    /// The parent OTEL `Context`, or `None` if this is a root. For callers
    /// that build a span themselves but want the same inbound parent
    /// resolution as [`request_span`] (e.g. response-filter spans).
    pub fn into_context(self) -> Option<Context> {
        match self {
            Self::NginxOtel(c) | Self::Traceparent(c) => Some(c),
            Self::None => None,
        }
    }
}

fn nginx_otel_parent(request: &Request) -> Option<Context> {
    if !ANCHOR_ENABLED.get().copied().unwrap_or(false) {
        return None;
    }

    let trace_id = read_cv(request, &raw const OTEL_TRACE_ID_CV)?;
    let span_id = read_cv(request, &raw const OTEL_SPAN_ID_CV)?;
    let sampled = matches!(
        read_cv(request, &raw const OTEL_PARENT_SAMPLED_CV).as_deref(),
        Some("1")
    );

    // The sampled bit here only affects what we propagate downstream — our
    // own export decision is governed by the SDK sampler (configured AlwaysOn
    // in `try_install`), since the project's model is producer-side
    // always-on with tail sampling at the telemetry gateway.
    span_context_from_parts(&trace_id, &span_id, sampled)
        .map(|sc| Context::new().with_remote_span_context(sc))
}

fn traceparent_header_parent(request: &Request) -> Option<Context> {
    parse_traceparent(request.get_header_in("traceparent")?)
        .map(|sc| Context::new().with_remote_span_context(sc))
}

/// Parse a W3C `traceparent` header: `version-trace_id-parent_id-flags`,
/// where version is `00` (only version supported by this spec), trace_id is
/// 32 hex, parent_id is 16 hex, flags is 2 hex (lsb = sampled).
fn parse_traceparent(s: &str) -> Option<SpanContext> {
    let mut parts = s.trim().split('-');
    let version = parts.next()?;
    let trace_id = parts.next()?;
    let span_id = parts.next()?;
    let flags = parts.next()?;
    if parts.next().is_some() || version != "00" {
        return None;
    }
    let sampled = u8::from_str_radix(flags, 16).ok()? & 1 != 0;
    span_context_from_parts(trace_id, span_id, sampled)
}

fn span_context_from_parts(trace_id: &str, span_id: &str, sampled: bool) -> Option<SpanContext> {
    let trace_id = TraceId::from_hex(trace_id).ok()?;
    let span_id = SpanId::from_hex(span_id).ok()?;
    if trace_id == TraceId::INVALID || span_id == SpanId::INVALID {
        return None;
    }
    let flags = if sampled {
        TraceFlags::SAMPLED
    } else {
        TraceFlags::default()
    };
    Some(SpanContext::new(
        trace_id,
        span_id,
        flags,
        true,
        TraceState::default(),
    ))
}

/// Render a W3C `traceparent` for `span`, for injecting context into outbound
/// HTTP calls so the downstream service chains under it — typically the
/// CLIENT span from [`traced_outbound!`]. Returns `None` when the span has no
/// valid OTEL context (e.g. no OTLP exporter installed). For the ambient
/// span, pass `&tracing::Span::current()`.
pub fn span_traceparent(span: &Span) -> Option<String> {
    let otel_ctx = span.context();
    let span_ref = otel_ctx.span();
    let sc = span_ref.span_context();
    if !sc.is_valid() {
        return None;
    }
    let flags = if sc.is_sampled() { 1u8 } else { 0u8 };
    Some(format!(
        "00-{}-{}-{:02x}",
        sc.trace_id(),
        sc.span_id(),
        flags
    ))
}

// Takes a raw pointer (not `&`) so callers can pass `&raw const STATIC_MUT_CV`
// directly: taking a reference to a `static mut` is a hard error in edition
// 2024, and `&*&raw const …` at the call site trips clippy::borrow_deref_ref.
fn read_cv(request: &Request, cv: *const ngx_http_complex_value_t) -> Option<String> {
    let cv = unsafe { &*cv };
    let s = request.get_complex_value(cv)?.to_str().ok()?;
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// `<time> <LEVEL> <span:name:path:> <event fields> <message>`.
struct PepStdoutFormat;

impl<S, N> FormatEvent<S, N> for PepStdoutFormat
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        SystemTime.format_time(&mut writer)?;
        write!(writer, " {:>5} ", event.metadata().level())?;

        // full span name path, root → leaf, names only (no span fields)
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                write!(writer, "{}:", span.name())?;
            }
            write!(writer, " ")?;
        }

        let mut visitor = FieldsThenMessage::default();
        event.record(&mut visitor);
        visitor.write(&mut writer)?;

        writeln!(writer)
    }
}

/// Field visitor that buffers the special `message` field and emits it *after*
/// the other fields, yielding `field=value … message`.
#[derive(Default)]
struct FieldsThenMessage {
    fields: String,
    message: Option<String>,
}

impl tracing::field::Visit for FieldsThenMessage {
    // The typed `record_*` methods default to forwarding here, so this catches
    // every field. `message` is recorded as `fmt::Arguments`, whose Debug is the
    // plain rendered text (no quotes); other values keep their Debug form, so
    // string fields stay quoted (e.g. `etag="…"`) exactly as before.
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write as _;
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        } else {
            let _ = write!(self.fields, "{}={:?} ", field.name(), value);
        }
    }
}

impl FieldsThenMessage {
    fn write(&self, writer: &mut Writer<'_>) -> std::fmt::Result {
        let fields = self.fields.trim_end();
        write!(writer, "{fields}")?;
        if let Some(msg) = &self.message {
            if !fields.is_empty() {
                write!(writer, " ")?;
            }
            write!(writer, "{msg}")?;
        }
        Ok(())
    }
}

/// Per-worker exit: flush in-flight spans and log records, tear down the OTLP
/// exporters. Both providers' `shutdown` are sync with built-in 5s timeouts
/// that propagate to their respective `BatchProcessor`s, so worst case this
/// blocks the nginx main thread for ~10s — within nginx's default
/// `worker_shutdown_timeout`. No-op if the providers were never installed.
pub fn shutdown() {
    if let Some(provider) = METER_PROVIDER.get() {
        // Final collect + export of all instruments, then exporter teardown.
        match provider.shutdown() {
            Ok(()) => tracing::info!("OTLP metric exporter shut down"),
            Err(err) => tracing::warn!(?err, "OTLP metric exporter shutdown failed"),
        }
    }
    if let Some(provider) = PROVIDER.get() {
        match provider.shutdown() {
            Ok(()) => tracing::info!("OTLP trace exporter shut down"),
            Err(err) => tracing::warn!(?err, "OTLP trace exporter shutdown failed"),
        }
    }
    if let Some(provider) = LOGGER_PROVIDER.get() {
        // Log *before* shutting down — afterwards the bridge would feed a
        // dead processor, which (correctly) warns about lifecycle misuse.
        tracing::info!("shutting down OTLP log exporter");
        if let Err(err) = provider.shutdown() {
            eprintln!("OTLP log exporter shutdown failed: {err:?}");
        }
    }
}

/// Per-worker subscriber init. Builds fmt + EnvFilter and, if
/// `OTEL_EXPORTER_OTLP_ENDPOINT` was set at config time, the OTEL traces
/// layer alongside; then `try_init`'s the whole chain. Must be called from
/// inside the worker process before any tracing event is emitted.
///
/// The OTEL layer is installed *directly* (not behind a `reload::Layer`)
/// because `reload::Layer::downcast_raw` deliberately returns `None` for
/// anything but `NoneLayerMarker` — which silently breaks
/// `OpenTelemetrySpanExt::context()` (it can't reach the inner layer's
/// `WithContext` extension) and therefore `current_traceparent()`.
///
/// The OTEL SDK's `BatchSpanProcessor::new` calls `tokio::spawn` to start
/// the drain task, so we wrap the SDK build in `Compat` and drive it with
/// `futures::executor::block_on` so the spawn lands on async-compat's
/// per-worker aux-thread runtime. The block is bounded by the build steps;
/// after this returns, exports happen asynchronously on the aux thread.
pub fn install() {
    let log_filter = EnvFilter::try_from_default_env().unwrap_or(EnvFilter::new("info"));
    if env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_err() {
        let _ = tracing_subscriber::registry()
            .with(log_filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stdout)
                    .event_format(PepStdoutFormat),
            )
            .try_init();
        return;
    };

    let mut resource = Resource::builder_empty()
        .with_attributes([
            // default value (precedence OTEL_SERVICE_NAME → OTEL_RESOURCE_ATTRIBUTES -> default)
            KeyValue::new("service.name", "ZETA Guard PEP HTTP proxy"),
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
            KeyValue::new("service.instance.id", std::process::id().to_string()),
        ])
        .with_detectors(&[
            Box::new(TelemetryResourceDetector),
            Box::new(EnvResourceDetector::new()),
        ]);
    if let Ok(service_name) = env::var("OTEL_SERVICE_NAME") {
        resource = resource.with_service_name(service_name);
    }
    let resource = resource.build();

    let built = futures::executor::block_on(async_compat::Compat::new(async move {
        let span_exporter = SpanExporter::builder()
            .with_tonic()
            .build()
            .map_err(|e| format!("OTLP span exporter build: {e}"))?;
        let log_exporter = LogExporter::builder()
            .with_tonic()
            .build()
            .map_err(|e| format!("OTLP log exporter build: {e}"))?;
        let metric_exporter = MetricExporter::builder()
            .with_tonic()
            .build()
            .map_err(|e| format!("OTLP metric exporter build: {e}"))?;

        let tracer_provider = SdkTracerProvider::builder()
            .with_sampler(Sampler::AlwaysOn)
            .with_batch_exporter(span_exporter)
            .with_resource(resource.clone())
            .build();
        let logger_provider = SdkLoggerProvider::builder()
            .with_batch_exporter(log_exporter)
            .with_resource(resource.clone())
            .build();
        let meter_provider = SdkMeterProvider::builder()
            .with_reader(PeriodicReader::builder(metric_exporter).build())
            .with_resource(resource)
            .build();

        let tracer = tracer_provider.tracer("ngx_pep");
        let trace_layer = tracing_opentelemetry::layer().with_tracer(tracer);
        let log_layer = OpenTelemetryTracingBridge::new(&logger_provider);
        Ok::<_, String>((
            tracer_provider,
            logger_provider,
            meter_provider,
            trace_layer,
            log_layer,
        ))
    }));

    match built {
        Ok((tracer_provider, logger_provider, meter_provider, trace_layer, log_layer)) => {
            let _ = PROVIDER.set(tracer_provider);
            let _ = LOGGER_PROVIDER.set(logger_provider);
            // Register globally so `metrics::*` instruments bind to this
            // provider on first use (see src/metrics.rs ordering constraint).
            opentelemetry::global::set_meter_provider(meter_provider.clone());
            let _ = METER_PROVIDER.set(meter_provider);
            // The OTEL SDK emits its *own* diagnostics (export errors,
            // emit-after-shutdown, …) as tracing events. If those reach the
            // logs bridge, each one triggers another emit → another
            // diagnostic → unbounded recursion → stack overflow. Filter the
            // SDK's targets out of the OTEL layers; they still reach stdout
            // via the fmt layer. Same treatment for the gRPC export stack
            // (tonic/hyper/h2): its events during export would otherwise
            // generate telemetry-about-telemetry.
            let telemetry_loop_guard = |meta: &tracing::Metadata<'_>| {
                let t = meta.target();
                !(t.starts_with("opentelemetry")
                    || t.starts_with("tonic")
                    || t.starts_with("hyper")
                    || t.starts_with("h2"))
            };
            // Both OTEL layers are innermost (first `.with()`s). The traces
            // layer's `S` must be `Registry`; the logs bridge can wrap anything.
            // The filter+fmt above gate both.
            let trace_filter = EnvFilter::try_from_env("RUST_TRACE")
                .unwrap_or(EnvFilter::new("info,ngx_pep=debug"));
            let _ = tracing_subscriber::registry()
                .with(
                    trace_layer
                        .with_filter(filter_fn(telemetry_loop_guard))
                        .with_filter(trace_filter),
                )
                .with(
                    log_layer
                        .with_filter(filter_fn(telemetry_loop_guard))
                        .with_filter(log_filter.clone()),
                )
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(std::io::stdout)
                        .event_format(PepStdoutFormat)
                        .with_filter(log_filter),
                )
                .try_init();
            tracing::info!(endpoint = ?env::var("OTEL_EXPORTER_OTLP_ENDPOINT"), "OTLP exporters installed");
        }
        Err(err) => {
            // Subscriber still needs to be initialized even on OTLP failure,
            // otherwise all subsequent tracing events vanish.
            let _ = tracing_subscriber::registry()
                .with(log_filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(std::io::stdout)
                        .event_format(PepStdoutFormat),
                )
                .try_init();

            tracing::error!(error = %err, endpoint = ?env::var("OTEL_EXPORTER_OTLP_ENDPOINT"), "OTLP exporter init failed");
        }
    }
}

#[cfg(test)]
mod stdout_fmt_tests {
    use super::PepStdoutFormat;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    struct BufWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for BufWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for BufWriter {
        type Writer = BufWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    // `<time> <LEVEL> <span:path:> <fields> <message>`: full span-name path,
    // no per-span field dumps, event fields kept, message last.
    #[test]
    fn formats_path_fields_then_message() {
        let buf = BufWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .event_format(PepStdoutFormat)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let outer = tracing::info_span!("pep_handler", http.method = "GET");
            let _o = outer.enter();
            let inner = tracing::info_span!("refresh_popp", force = true);
            let _i = inner.enter();
            tracing::info!(meta = "@x", etag = "abc", "JWKS refreshed");
        });

        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        let line = out.trim_end();

        // span name path present, root → leaf
        assert!(
            line.contains("pep_handler:refresh_popp:"),
            "path missing: {line}"
        );
        // span FIELDS must not leak onto stdout
        assert!(!line.contains("force="), "span field leaked: {line}");
        assert!(!line.contains("http.method"), "span field leaked: {line}");
        // event fields kept, strings stay quoted
        assert!(line.contains(r#"meta="@x""#), "event field missing: {line}");
        assert!(
            line.contains(r#"etag="abc""#),
            "event field missing: {line}"
        );
        // message rendered last, unquoted
        assert!(
            line.ends_with("JWKS refreshed"),
            "message not last/clean: {line}"
        );
    }
}
