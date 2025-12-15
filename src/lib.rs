/*-
 * #%L
 * ngx_pep
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH
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

use anyhow::Result;
use nginx_sys::{
    NGX_LOG_EMERG, NGX_LOG_WARN, ngx_http_compile_complex_value, ngx_http_compile_complex_value_t,
    ngx_http_complex_value_t, ngx_http_phases_NGX_HTTP_PRECONTENT_PHASE, ngx_str_t,
};
use ngx::core::Status;
use ngx::ffi::{
    NGX_HTTP_MODULE, ngx_array_push, ngx_conf_t, ngx_http_handler_pt, ngx_http_module_t,
    ngx_http_phases_NGX_HTTP_ACCESS_PHASE, ngx_int_t, ngx_module_t,
};
use ngx::http::{self, HttpModule, Request};
use ngx::http::{HttpModuleMainConf, NgxHttpCoreModule};
use ngx::ngx_conf_log_error;
use ngx::{http_request_handler, ngx_string};
use ngx_tickle::Task;
use reqwest::Client;

use crate::conf::NGX_HTTP_PEP_COMMANDS;
use crate::request_body::RequestBody;
#[cfg(not(test))]
use {crate::jwk_cache::JwkCache, nginx_sys::ngx_cycle_t};

mod asl;
mod buffer;
mod conf;
mod headers;
mod jwk_cache;
mod pep;
mod request_body;
mod request_ops;
mod response;
mod session_cache;

// contains test helpers and nginx stubs for tests — the harness is built as a binary, which means
// that the linker requires all symbols to be present.
#[cfg(test)]
mod tests;

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

// Shared between asl and pep modules — technically it's only a single nginx module, so there can
// be only one.
#[derive(Debug, Default)]
struct ModuleCtx {
    pep: RefCell<PepCtx>,
    asl: RefCell<AslCtx>,
    body: RequestBody,
}

#[derive(Debug, Default)]
struct PepCtx {
    task: Option<Task<Result<Status>>>,
}

#[derive(Debug, Default)]
struct AslCtx {
    task: Option<Task<()>>,
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

    pub fn take_pep_task(request: &Request) -> Option<Task<Result<Status>>> {
        let ctx = Self::get(request);
        ctx.pep.borrow_mut().task.take()
    }

    pub fn insert_pep_task(request: &Request, task: Task<Result<Status>>) {
        let ctx = Self::get(request);
        #[allow(clippy::let_underscore_future)]
        let _ = ctx.pep.borrow_mut().task.insert(task);
    }

    pub fn insert_asl_task(request: &Request, task: Task<()>) {
        let ctx = Self::get(request);
        #[allow(clippy::let_underscore_future)]
        let _ = ctx.asl.borrow_mut().task.insert(task);
    }
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

            let mut asl_self_url = ngx_string!("http://localhost:$server_port");
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

#[cfg(not(test))]
extern "C" fn ngx_http_pep_init_worker(cycle: *mut ngx_cycle_t) -> ngx_int_t {
    use reqwest::ClientBuilder;
    use reqwest::redirect::Policy;

    let cycle = unsafe { &mut *cycle };
    let process = unsafe { nginx_sys::ngx_process } as u32;
    if !matches!(
        process,
        nginx_sys::NGX_PROCESS_SINGLE | nginx_sys::NGX_PROCESS_WORKER
    ) {
        return Status::NGX_OK.into();
    }

    let conf = Module::main_conf(cycle).expect("main conf");

    log_debug!("pep: conf={conf:#?}");
    log_debug!("pep: initializing http client…");
    CLIENT.get_or_init(|| {
        ClientBuilder::new()
            .redirect(Policy::none())
            .http2_adaptive_window(true)
            .pool_idle_timeout(conf.http_client_idle_timeout)
            .pool_max_idle_per_host(conf.http_client_max_idle_per_host)
            .tcp_keepalive(conf.http_client_tcp_keepalive)
            .connect_timeout(conf.http_client_connect_timeout)
            .timeout(conf.http_client_timeout)
            .use_rustls_tls()
            .danger_accept_invalid_certs(conf.http_client_accept_invalid_certs)
            .build()
            .expect("reqwest client")
    });

    log_debug!("pep: initializing jwk cache…");
    JwkCache::init(conf);

    Status::NGX_OK.into()
}
