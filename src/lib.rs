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

use std::cell::RefCell;
use std::ptr::addr_of;
use std::sync::OnceLock;
use std::time::SystemTime;

use async_compat::Compat;
use std::{env, ptr};
use tracing::Span;

use nginx_sys::{
    NGX_HTTP_VAR_NOCACHEABLE, NGX_LOG_EMERG, NGX_LOG_WARN, ngx_http_add_variable,
    ngx_http_compile_complex_value, ngx_http_compile_complex_value_t, ngx_http_complex_value_t,
    ngx_http_phases_NGX_HTTP_PRECONTENT_PHASE, ngx_http_request_t, ngx_http_variable_value_t,
    ngx_str_t,
};
use ngx::core::Status;
use ngx::ffi::{
    NGX_HTTP_MODULE, ngx_array_push, ngx_conf_t, ngx_http_handler_pt, ngx_http_module_t,
    ngx_http_phases_NGX_HTTP_ACCESS_PHASE, ngx_http_phases_NGX_HTTP_LOG_PHASE, ngx_int_t,
    ngx_module_t, ngx_uint_t,
};
use ngx::http::{self, HttpModule, Request};
use ngx::http::{HttpModuleMainConf, NgxHttpCoreModule};
use ngx::ngx_conf_log_error;
use ngx::{http_request_handler, ngx_string};
use ngx_tickle::{Task, spawn};
use reqwest::Client;

use crate::conf::NGX_HTTP_PEP_COMMANDS;
use crate::error::ZetaResult;
use crate::request_body::RequestBody;

mod asl;
mod asl_keys;
pub mod block_list;
mod buffer;
mod capec;
mod conf;
mod error;
mod headers;
mod jwk_cache;
mod metrics;
mod ocsp_cache;
mod ossl_store;
mod otel;
mod pep;
mod proxy_conf;
mod request_body;
mod request_ops;
mod response;
#[cfg_attr(test, allow(unused))]
pub mod revocation;
mod session_cache;
mod zeta_cause;

#[cfg(test)]
mod tests;

// tarpc control server embedded into the nginx module for integration tests
#[cfg(feature = "its")]
pub mod its;

// contains nginx stubs for tests and purl which are built as a binary, which means that the linker
// requires all symbols to be present.
#[cfg(any(test, feature = "stubs"))]
mod stubs;

// contains client code used in purl and integration tests
#[cfg(any(test, feature = "client"))]
pub mod client;

#[allow(dead_code, clippy::all)]
mod typify {
    include!(concat!(env!("OUT_DIR"), "/typify.rs"));
}

pub fn spawn_compat<F, T>(future: F) -> Task<T>
where
    F: Future<Output = T> + 'static,
    T: 'static,
{
    spawn(Compat::new(future))
}

// Shared between asl and pep modules — technically it's only a single nginx module, so there can
// be only one, *per Request*
#[derive(Debug, Default)]
struct ModuleCtx {
    pep: RefCell<PepCtx>,
    body: RequestBody,
    // re-entrance guard for the zeta-cause response interceptor; we call send_header in it,
    // entering the filter again, and we must short-circuit
    zeta_cause_intercepted: std::cell::Cell<bool>,
    // "everything after authz" span: opened when the pep access phase allows
    // the request, finalized (with response status) in the log phase. If the
    // log phase never takes it, the pool-cleanup drop of ModuleCtx closes it
    // unrecorded — the span is never lost, only its status attribute.
    upstream_span: RefCell<Option<Span>>,
}

// Slots for the PEP-provided `$zeta_*` nginx variables. The PEP computes their per-request
// values during the access phase; `proxy_set_header ZETA-… $zeta_…;` (in proxy_headers.conf)
// reads them when building the upstream request — which also drops any client-supplied copy of
// that header by name. See the getter `pep_zeta_variable` and `proxy_headers.conf`.
pub(crate) const ZETA_VAR_USER_INFO: usize = 0;
pub(crate) const ZETA_VAR_CLIENT_DATA: usize = 1;
pub(crate) const ZETA_VAR_POPP_TOKEN: usize = 2;
pub(crate) const ZETA_VAR_FORWARDED: usize = 3;
// $zeta_client_id / $zeta_client_address are NOT forwarded upstream (no
// proxy_set_header reads them). They exist only so the nginx-otel SERVER span
// can pick them up via `otel_span_attr` for the TI-SIEM telemetry required by
// gemSpec_ZETA A_28783 (app.installation.id / client.address). Same per-request
// slot machinery as the header vars, just a different consumer.
pub(crate) const ZETA_VAR_CLIENT_ID: usize = 4;
pub(crate) const ZETA_VAR_CLIENT_ADDRESS: usize = 5;
// $zeta_is_asl gets picked up by nginx-otel and attached to its server span, which we can't write
// directly. See also pep::handler, which sets the same data on the "upstream" span. This is useful
// for spanmetrics maths to determine true "self-time" under ASL.
pub(crate) const ZETA_VAR_IS_ASL: usize = 6;
// A_27496: client monitoring data — picked up by nginx-otel `otel_span_attr` on
// the SERVER span (same mechanism as CLIENT_ID / CLIENT_ADDRESS above).
pub(crate) const ZETA_VAR_PRODUCT_VERSION: usize = 7;
pub(crate) const ZETA_VAR_PRODUCT_ID: usize = 8;
pub(crate) const ZETA_VAR_PROFESSION_OID: usize = 9;
const ZETA_VAR_COUNT: usize = 10;

fn zeta_var_name(slot: usize) -> ngx_str_t {
    match slot {
        ZETA_VAR_USER_INFO => ngx_string!("zeta_user_info"),
        ZETA_VAR_CLIENT_DATA => ngx_string!("zeta_client_data"),
        ZETA_VAR_POPP_TOKEN => ngx_string!("zeta_popp_token_content"),
        ZETA_VAR_FORWARDED => ngx_string!("zeta_forwarded"),
        ZETA_VAR_CLIENT_ID => ngx_string!("zeta_client_id"),
        ZETA_VAR_CLIENT_ADDRESS => ngx_string!("zeta_client_address"),
        ZETA_VAR_IS_ASL => ngx_string!("zeta_is_asl"),
        ZETA_VAR_PRODUCT_VERSION => ngx_string!("zeta_product_version"),
        ZETA_VAR_PRODUCT_ID => ngx_string!("zeta_product_id"),
        ZETA_VAR_PROFESSION_OID => ngx_string!("zeta_profession_oid"),
        _ => panic!("Unknown var slot {slot}"),
    }
}

#[derive(Debug, Default)]
struct PepCtx {
    // Access-phase result paired with the outer "pep::request" tracing span it was produced
    // under — created on first entry, taken on re-entry so finalize/send happen inside the
    // same span as the async pep_handler work.
    outcome: Option<(ZetaResult<()>, Span)>,
    // pool-allocated values for the `$zeta_*` variables; `None` → the variable resolves empty,
    // so `proxy_set_header` omits the header. Re-populated on each access-phase run (the ctx is
    // cleared on internal redirect), and read at content-phase time by `pep_zeta_variable`.
    zeta_vars: [Option<ngx_str_t>; ZETA_VAR_COUNT],
}

impl ModuleCtx {
    fn get(request: &Request) -> &ModuleCtx {
        unsafe { request.get_module_ctx::<ModuleCtx>(&*addr_of!(ngx_http_pep_module)) }
            .unwrap_or_else(|| {
                let ctx = request.pool().allocate(ModuleCtx::default());

                unsafe {
                    request.set_module_ctx(ctx.cast(), &*addr_of!(ngx_http_pep_module));
                    &*ctx
                }
            })
    }

    pub fn take_pep(request: &Request) -> Option<(ZetaResult<()>, Span)> {
        Self::get(request).pep.borrow_mut().outcome.take()
    }

    pub fn insert_pep(request: &Request, result: ZetaResult<()>, span: Span) {
        Self::get(request).pep.borrow_mut().outcome = Some((result, span));
    }

    pub fn insert_upstream_span(request: &Request, span: Span) {
        *Self::get(request).upstream_span.borrow_mut() = Some(span);
    }

    pub fn take_upstream_span(request: &Request) -> Option<Span> {
        let ctx = Self::get(request);
        ctx.upstream_span.borrow_mut().take()
    }

    /// OTEL context of the upstream span, if the access phase opened one.
    /// Content-phase spans parent under it so the whole request shares one
    /// trace even without nginx-otel or an inbound traceparent.
    pub fn upstream_otel_context(request: &Request) -> Option<opentelemetry::Context> {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        Self::get(request)
            .upstream_span
            .borrow()
            .as_ref()
            .map(|span| span.context())
    }

    /// Stash a `$zeta_*` variable's value for this request (pool-allocated so it stays valid
    /// until `proxy_pass` reads it at content-phase time).
    pub fn set_zeta_var(request: &Request, slot: usize, value: &str) {
        // SAFETY: `request.pool()` is the live request pool; `from_str` copies `value` into it.
        let s = unsafe { ngx_str_t::from_str(request.pool().as_ptr(), value) };
        Self::get(request).pep.borrow_mut().zeta_vars[slot] = Some(s);
    }

    fn zeta_var(request: &Request, slot: usize) -> Option<ngx_str_t> {
        Self::get(request).pep.borrow().zeta_vars[slot]
    }

    pub fn set_is_asl(request: &Request, value: &str) {
        let ctx = Self::get(request);
        if let Some(upstream) = ctx.upstream_span.borrow().as_ref() {
            upstream.record("is_asl", value);
        }
        ModuleCtx::set_zeta_var(request, ZETA_VAR_IS_ASL, value);
    }
}

/// `get_handler` for the `$zeta_user_info` / `$zeta_client_data` / `$zeta_popp_token_content`
/// variables. `data` is the `ZETA_VAR_*` slot. Returns the value the PEP stashed for this
/// request, or empty (→ header omitted by `proxy_set_header`) if it set nothing.
unsafe extern "C" fn pep_zeta_variable(
    r: *mut ngx_http_request_t,
    v: *mut ngx_http_variable_value_t,
    data: usize,
) -> ngx_int_t {
    let request: &Request = unsafe { Request::from_ngx_http_request(r) };
    let v = unsafe { &mut *v };
    v.set_valid(1);
    v.set_no_cacheable(1);
    v.set_not_found(0);
    match ModuleCtx::zeta_var(request, data) {
        Some(s) => {
            v.data = s.data;
            v.set_len(s.len as _);
        }
        None => {
            v.data = ptr::null_mut();
            v.set_len(0);
        }
    }
    Status::NGX_OK.into()
}

// init: postconfiguration
static mut SELF_URL_CV: ngx_http_complex_value_t = ngx_http_complex_value_t {
    value: ngx_str_t {
        len: 0,
        data: std::ptr::null_mut(),
    },
    ..unsafe { std::mem::zeroed() }
};

struct Module;

impl http::HttpModule for Module {
    fn module() -> &'static ngx_module_t {
        unsafe { &*::core::ptr::addr_of!(ngx_http_pep_module) }
    }

    unsafe extern "C" fn postconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        unsafe {
            let cf = &mut *cf;

            // Subscriber init is deferred to per-worker `ngx_http_pep_init_worker`
            // because the OTEL layer must be installed *directly* (not behind a
            // `reload::Layer`). `reload::Layer`'s `downcast_raw` doesn't forward
            // for any `TypeId` except `NoneLayerMarker`, which silently breaks
            // `OpenTelemetrySpanExt::context()` — it can't find the inner
            // OTEL layer's `WithContext` extension, so `current_traceparent()`
            // and similar return empty. The OTEL `BatchSpanProcessor` needs a
            // tokio runtime at construction, which only exists post-fork via
            // async-compat. Hence: full subscriber chain in worker init.

            let conf = Module::main_conf_mut(cf).expect("main conf");
            if let Err(e) = conf.validate() {
                ngx_conf_log_error!(NGX_LOG_EMERG, cf, "{e}");
                return Status::NGX_ERROR.into();
            }
            if conf.http_client_accept_invalid_certs {
                ngx_conf_log_error!(
                    NGX_LOG_WARN,
                    cf,
                    "http_client_accept_invalid_certs = true, will accept *any* cert!"
                );
            }

            let cmcf = NgxHttpCoreModule::main_conf_mut(cf).expect("http core main conf");

            // hook access phase
            let h = ngx_array_push(
                &mut cmcf.phases[ngx_http_phases_NGX_HTTP_ACCESS_PHASE as usize].handlers,
            ) as *mut ngx_http_handler_pt;
            if h.is_null() {
                return Status::NGX_ERROR.into();
            }
            *h = Some(pep_handler);

            // install asl content handler
            let h = ngx_array_push(
                &mut cmcf.phases[ngx_http_phases_NGX_HTTP_PRECONTENT_PHASE as usize].handlers,
            ) as *mut ngx_http_handler_pt;
            if h.is_null() {
                return Status::NGX_ERROR.into();
            }
            *h = Some(asl_handler);

            // log phase: record http.server.request.duration and finalize the
            // upstream span — the request is complete here, status is final
            let h = ngx_array_push(
                &mut cmcf.phases[ngx_http_phases_NGX_HTTP_LOG_PHASE as usize].handlers,
            ) as *mut ngx_http_handler_pt;
            if h.is_null() {
                return Status::NGX_ERROR.into();
            }
            *h = Some(telemetry_log_handler);

            // install zeta-cause: proxy response interceptor
            zeta_cause::install();

            // register the $zeta_* variables that proxy_headers.conf forwards as ZETA-* headers
            let cf_ptr: *mut ngx_conf_t = cf;
            for slot in [
                ZETA_VAR_USER_INFO,
                ZETA_VAR_CLIENT_DATA,
                ZETA_VAR_POPP_TOKEN,
                ZETA_VAR_FORWARDED,
                ZETA_VAR_CLIENT_ID,
                ZETA_VAR_CLIENT_ADDRESS,
                ZETA_VAR_IS_ASL,
                ZETA_VAR_PRODUCT_ID,
                ZETA_VAR_PRODUCT_VERSION,
                ZETA_VAR_PROFESSION_OID,
            ] {
                let mut name = zeta_var_name(slot);
                let var = ngx_http_add_variable(
                    cf_ptr,
                    &mut name,
                    NGX_HTTP_VAR_NOCACHEABLE as ngx_uint_t,
                );
                if var.is_null() {
                    return Status::NGX_ERROR.into();
                }
                (*var).get_handler = Some(pep_zeta_variable);
                (*var).data = slot;
            }

            // This is required in handle_subrequest — a nginx Request doesn't know the original
            // server port (easily), but we want to send inner to the same server that handles
            // outer.
            let mut asl_self_url = ngx_string!("http://localhost:$server_port");
            let mut ccv: ngx_http_compile_complex_value_t = std::mem::zeroed();
            ccv.cf = cf;
            ccv.value = &mut asl_self_url;
            ccv.complex_value = &raw mut SELF_URL_CV;
            let rc = ngx_http_compile_complex_value(&mut ccv);
            if rc != 0 {
                return rc;
            }
            if env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok() {
                let rc = otel::compile_anchor_cvs(cf);
                if rc != 0 {
                    return rc;
                }
            }
            let init_status = session_cache::init(cf);
            if init_status != 0 {
                return init_status;
            }
            block_list::init(cf)
        }
    }
}

static NGX_HTTP_PEP_MODULE_CTX: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: Some(Module::preconfiguration),
    postconfiguration: Some(Module::postconfiguration),
    create_main_conf: Some(Module::create_main_conf),
    init_main_conf: Some(Module::init_main_conf),
    create_srv_conf: None,
    merge_srv_conf: None,
    create_loc_conf: Some(Module::create_loc_conf),
    merge_loc_conf: Some(Module::merge_loc_conf),
};

ngx::ngx_modules!(ngx_http_pep_module);

#[used]
#[allow(non_upper_case_globals)]
pub static mut ngx_http_pep_module: ngx_module_t = ngx_module_t {
    ctx: std::ptr::addr_of!(NGX_HTTP_PEP_MODULE_CTX) as _,
    commands: unsafe { &NGX_HTTP_PEP_COMMANDS[0] as *const _ as *mut _ },
    type_: NGX_HTTP_MODULE as _,
    #[cfg(not(test))]
    init_process: Some(ngx_http_pep_init_worker),
    #[cfg(not(test))]
    exit_process: Some(ngx_http_pep_exit_worker),

    ..ngx_module_t::default()
};

http_request_handler!(pep_handler, pep::handler);
http_request_handler!(asl_handler, asl::handler);
http_request_handler!(telemetry_log_handler, telemetry_log_phase);

/// Log-phase handler: the request is complete and the response status final.
/// Records the stable-semconv `http.server.request.duration` histogram for
/// every request, and finalizes the upstream span (created by `pep::request`
/// on access-grant) with the response status.
fn telemetry_log_phase(request: &mut Request) -> Status {
    let r = unsafe { &*(request as *const Request).cast::<nginx_sys::ngx_http_request_t>() };
    let status = r.headers_out.status as u16;

    if let Some(span) = ModuleCtx::take_upstream_span(request) {
        span.record("http.response.status_code", status as i64);
    }

    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let started_ms = r.start_sec as u128 * 1000 + r.start_msec as u128;
    let elapsed_s = (now.as_millis().saturating_sub(started_ms)) as f64 / 1000.0;

    metrics::HTTP_SERVER_REQUEST_DURATION.record(
        elapsed_s,
        &[
            opentelemetry::KeyValue::new("http.request.method", request.method().to_string()),
            opentelemetry::KeyValue::new("http.response.status_code", status as i64),
        ],
    );

    Status::NGX_DECLINED
}

pub static CLIENT: OnceLock<Client> = OnceLock::new();

#[cfg_attr(test, allow(unused))]
mod prod {

    use std::time::Duration;

    use nginx_sys::ngx_cycle_t;
    use ngx::core::Status;
    use ngx::ffi::ngx_int_t;
    use ngx::http::HttpModuleMainConf;

    use crate::{CLIENT, Module, otel};

    pub extern "C" fn ngx_http_pep_init_worker(cycle: *mut ngx_cycle_t) -> ngx_int_t {
        use reqwest::ClientBuilder;

        ngx_tickle::init();

        let cycle = unsafe { &mut *cycle };

        let process = unsafe { nginx_sys::ngx_process } as u32;
        if !matches!(
            process,
            nginx_sys::NGX_PROCESS_SINGLE | nginx_sys::NGX_PROCESS_WORKER
        ) {
            return Status::NGX_OK.into();
        }

        let conf = Module::main_conf(cycle).expect("main conf");

        otel::install();

        CLIENT.get_or_init(|| {
            ClientBuilder::new()
                .user_agent(concat!("ZETA Guard PEP/", env!("CARGO_PKG_VERSION")))
                .http2_adaptive_window(true)
                .pool_max_idle_per_host(32)
                .pool_idle_timeout(Duration::from_secs(60))
                .tcp_keepalive(Duration::from_secs(30))
                .connect_timeout(conf.http_client_connect_timeout)
                .timeout(conf.http_client_timeout)
                .use_rustls_tls()
                .danger_accept_invalid_certs(conf.http_client_accept_invalid_certs)
                .build()
                .expect("reqwest client")
        });

        #[cfg(not(test))]
        {
            use crate::jwk_cache::JwkCache;
            use crate::metrics::register_observables;
            use crate::ocsp_cache::OcspCache;

            // Per worker, after fork: the cache holds a lock and a cached
            // response, neither of which may be inherited from the master. A
            // reload forks new workers, so this also picks up config changes —
            // unlike the shared zone, which is inherited as-is.
            OcspCache::init(
                crate::session_cache::asl_config(conf)
                    .expect("asl ocsp init")
                    .ocsp,
            );
            JwkCache::init(conf);
            crate::revocation::init(conf);
            // After otel::install (global meter live) and after the caches
            // exist — see the fn docs for threading/ordering constraints.
            register_observables();
        }

        #[cfg(feature = "its")]
        {
            // work up from the pid file path to get to control path dir: ./prefix/test-{port}/control

            use crate::its;
            let ccf: &nginx_sys::ngx_core_conf_t = unsafe {
                &*cycle
                    .conf_ctx
                    .add(nginx_sys::ngx_core_module.index)
                    .read()
                    .cast()
            };
            let pid = unsafe { ngx::core::NgxStr::from_ngx_str(ccf.pid).to_str().unwrap() };
            let control_path = std::path::Path::new(pid)
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("control");
            std::fs::create_dir_all(&control_path).expect("control path created");

            its::start(&control_path);
        }

        Status::NGX_OK.into()
    }

    /// Worker exit: flush in-flight OTLP spans, otherwise the last batch
    /// (up to 5s of spans) is lost when nginx kills the worker.
    pub extern "C" fn ngx_http_pep_exit_worker(_cycle: *mut ngx_cycle_t) {
        let process = unsafe { nginx_sys::ngx_process } as u32;
        if !matches!(
            process,
            nginx_sys::NGX_PROCESS_SINGLE | nginx_sys::NGX_PROCESS_WORKER
        ) {
            return;
        }
        otel::shutdown();
    }
}
#[cfg(not(test))]
use prod::*;
