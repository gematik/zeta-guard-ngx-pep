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
use std::time::Duration;

use async_compat::Compat;
use std::ptr;

use nginx_sys::{
    NGX_HTTP_VAR_NOCACHEABLE, NGX_LOG_EMERG, NGX_LOG_WARN, ngx_http_add_variable,
    ngx_http_compile_complex_value, ngx_http_compile_complex_value_t, ngx_http_complex_value_t,
    ngx_http_phases_NGX_HTTP_PRECONTENT_PHASE, ngx_http_request_t, ngx_http_variable_value_t,
    ngx_str_t,
};
use ngx::core::Status;
use ngx::ffi::{
    NGX_HTTP_MODULE, ngx_array_push, ngx_conf_t, ngx_http_handler_pt, ngx_http_module_t,
    ngx_http_phases_NGX_HTTP_ACCESS_PHASE, ngx_int_t, ngx_module_t, ngx_uint_t,
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
mod buffer;
mod conf;
mod error;
mod headers;
mod jwk_cache;
mod ocsp_cache;
mod ossl_store;
mod pep;
mod proxy_conf;
mod request_body;
mod request_ops;
mod response;
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

#[macro_export]
macro_rules! log_debug {
    ( $($arg:tt)+ ) => {
        println!($($arg)+)
    };
}

// upstream macro uses < instead of <= erroneously
#[macro_export]
macro_rules! ngx_log_error {
    ( $level:expr, $log:expr, $($arg:tt)+ ) => {
        let log = $log;
        let level = $level as ngx::ffi::ngx_uint_t;
        if level <= unsafe { (*log).log_level } {
            let mut buf =
                [const { ::core::mem::MaybeUninit::<u8>::uninit() }; ngx::log::LOG_BUFFER_SIZE];
            let message = ngx::log::write_fmt(&mut buf, format_args!($($arg)+));
            unsafe { ngx::log::log_error(level, log, 0, message) };
        }
    }
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
}

// Slots for the PEP-provided `$zeta_*` nginx variables. The PEP computes their per-request
// values during the access phase; `proxy_set_header ZETA-… $zeta_…;` (in proxy_headers.conf)
// reads them when building the upstream request — which also drops any client-supplied copy of
// that header by name. See the getter `pep_zeta_variable` and `proxy_headers.conf`.
pub(crate) const ZETA_VAR_USER_INFO: usize = 0;
pub(crate) const ZETA_VAR_CLIENT_DATA: usize = 1;
pub(crate) const ZETA_VAR_POPP_TOKEN: usize = 2;
pub(crate) const ZETA_VAR_FORWARDED: usize = 3;
const ZETA_VAR_COUNT: usize = 4;

#[derive(Debug, Default)]
struct PepCtx {
    result: Option<ZetaResult<()>>,
    // pool-allocated values for the `$zeta_*` variables; `None` → the variable resolves empty,
    // so `proxy_set_header` omits the header. Re-populated on each access-phase run (the ctx is
    // cleared on internal redirect), and read at content-phase time by `pep_zeta_variable`.
    zeta_headers: [Option<ngx_str_t>; ZETA_VAR_COUNT],
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

    pub fn take_pep_result(request: &Request) -> Option<ZetaResult<()>> {
        let ctx = Self::get(request);
        ctx.pep.borrow_mut().result.take()
    }

    pub fn insert_pep_result(request: &Request, result: ZetaResult<()>) {
        let ctx = Self::get(request);
        let _ = ctx.pep.borrow_mut().result.insert(result);
    }

    /// Stash a `$zeta_*` variable's value for this request (pool-allocated so it stays valid
    /// until `proxy_pass` reads it at content-phase time).
    pub fn set_zeta_header(request: &Request, slot: usize, value: &str) {
        // SAFETY: `request.pool()` is the live request pool; `from_str` copies `value` into it.
        let s = unsafe { ngx_str_t::from_str(request.pool().as_ptr(), value) };
        Self::get(request).pep.borrow_mut().zeta_headers[slot] = Some(s);
    }

    fn zeta_header(request: &Request, slot: usize) -> Option<ngx_str_t> {
        Self::get(request).pep.borrow().zeta_headers[slot]
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
    match ModuleCtx::zeta_header(request, data) {
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

            let conf = Module::main_conf(cf).expect("main conf");
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

            // install zeta-cause: proxy response interceptor
            zeta_cause::install();

            // register the $zeta_* variables that proxy_headers.conf forwards as ZETA-* headers
            let cf_ptr: *mut ngx_conf_t = cf;
            for (name, slot) in [
                (ngx_string!("zeta_user_info"), ZETA_VAR_USER_INFO),
                (ngx_string!("zeta_client_data"), ZETA_VAR_CLIENT_DATA),
                (ngx_string!("zeta_popp_token_content"), ZETA_VAR_POPP_TOKEN),
                (ngx_string!("zeta_forwarded"), ZETA_VAR_FORWARDED),
            ] {
                let mut name = name;
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
            let mut asl_self_url = ngx_string!("http://127.0.0.1:$server_port");
            let mut ccv: ngx_http_compile_complex_value_t = std::mem::zeroed();
            ccv.cf = cf;
            ccv.value = &mut asl_self_url;
            ccv.complex_value = &raw mut SELF_URL_CV;
            let rc = ngx_http_compile_complex_value(&mut ccv);
            if rc != 0 {
                return rc;
            }
            session_cache::init(cf)
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

    ..ngx_module_t::default()
};

http_request_handler!(pep_handler, pep::handler);
http_request_handler!(asl_handler, asl::handler);

pub static CLIENT: OnceLock<Client> = OnceLock::new();
pub static ASL_CLIENT: OnceLock<Client> = OnceLock::new();

#[inline]
fn format_iso8601(since_epoch: Duration) -> String {
    let t: libc::time_t = since_epoch.as_secs().try_into().unwrap();
    let millis = since_epoch.subsec_millis();
    let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
    let tm = unsafe {
        libc::gmtime_r(&t, tm.as_mut_ptr());
        tm.assume_init()
    };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        millis,
    )
}

#[cfg_attr(test, allow(unused))]
mod prod {

    use std::time::{SystemTime, UNIX_EPOCH};

    use nginx_sys::ngx_cycle_t;
    use ngx::core::Status;
    use ngx::ffi::ngx_int_t;
    use ngx::http::HttpModuleMainConf;

    use crate::{ASL_CLIENT, CLIENT, Module, format_iso8601};

    pub extern "C" fn ngx_http_pep_init_worker(cycle: *mut ngx_cycle_t) -> ngx_int_t {
        use reqwest::ClientBuilder;
        use reqwest::redirect::Policy;

        let ts = format_iso8601(SystemTime::now().duration_since(UNIX_EPOCH).unwrap());
        log_debug!("init worker @ {ts}",);

        let cycle = unsafe { &mut *cycle };

        let process = unsafe { nginx_sys::ngx_process } as u32;
        if !matches!(
            process,
            nginx_sys::NGX_PROCESS_SINGLE | nginx_sys::NGX_PROCESS_WORKER
        ) {
            return Status::NGX_OK.into();
        }

        let conf = Module::main_conf(cycle).expect("main conf");

        log_debug!("conf={conf:#?}");
        log_debug!("initializing http client…");
        CLIENT.get_or_init(|| {
            ClientBuilder::new()
                .user_agent(concat!("ZETA Guard PEP/", env!("CARGO_PKG_VERSION")))
                .redirect(Policy::none())
                .http2_adaptive_window(true)
                .pool_max_idle_per_host(0)
                .tcp_keepalive(None)
                .connect_timeout(conf.http_client_connect_timeout)
                .timeout(conf.http_client_timeout)
                .use_rustls_tls()
                .danger_accept_invalid_certs(conf.http_client_accept_invalid_certs)
                .build()
                .expect("reqwest client")
        });

        // ZF-0034: the ASL loopback hop targets this PEP's own listener only — never follow a
        // redirect off it, never route through a proxy. Separate from CLIENT so PDP/OCSP/upstream
        // fetches keep their proxy.
        ASL_CLIENT.get_or_init(|| {
            ClientBuilder::new()
                .user_agent(concat!("ZETA Guard PEP/", env!("CARGO_PKG_VERSION")))
                .redirect(Policy::none())
                .no_proxy()
                .http2_adaptive_window(true)
                .pool_max_idle_per_host(0)
                .tcp_keepalive(None)
                .connect_timeout(conf.http_client_connect_timeout)
                .timeout(conf.http_client_timeout)
                .use_rustls_tls()
                .danger_accept_invalid_certs(conf.http_client_accept_invalid_certs)
                .build()
                .expect("ASL reqwest client")
        });

        #[cfg(not(test))]
        {
            use crate::jwk_cache::JwkCache;
            log_debug!("initializing jwk cache…");
            JwkCache::init(conf);
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
}
#[cfg(not(test))]
use prod::*;
