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
use nginx_sys::{NGX_LOG_EMERG, NGX_LOG_WARN, ngx_cycle_t};
use ngx::core::{self, Status};
use ngx::ffi::{
    NGX_HTTP_MODULE, ngx_array_push, ngx_conf_t, ngx_http_handler_pt, ngx_http_module_t,
    ngx_http_phases_NGX_HTTP_ACCESS_PHASE, ngx_int_t, ngx_module_t,
};
use ngx::http::{self, HttpModule};
use ngx::http::{HttpModuleMainConf, NgxHttpCoreModule};
use ngx::http_request_handler;
use ngx::ngx_conf_log_error;

use crate::{conf::NGX_HTTP_PEP_COMMANDS, jwk_cache::JwkCache};

mod access_token;
mod conf;
mod jwk_cache;

#[macro_export]
macro_rules! log_debug {
    ( $($arg:tt)+ ) => {
        ngx::ngx_log_debug!(ngx::log::ngx_cycle_log().as_ptr(), $($arg)+)
    }
}

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
                return core::Status::NGX_ERROR.into();
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
                return core::Status::NGX_ERROR.into();
            }
            *h = Some(pep_access_handler);
            core::Status::NGX_OK.into()
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
    init_process: Some(ngx_http_pep_init_worker),

    ..ngx_module_t::default()
};

http_request_handler!(pep_access_handler, access_token::handler);

extern "C" fn ngx_http_pep_init_worker(cycle: *mut ngx_cycle_t) -> ngx_int_t {
    let cycle = unsafe { &mut *cycle };
    let process = unsafe { nginx_sys::ngx_process } as u32;
    if !matches!(
        process,
        nginx_sys::NGX_PROCESS_SINGLE | nginx_sys::NGX_PROCESS_WORKER
    ) {
        return Status::NGX_OK.into();
    }

    let conf = Module::main_conf(cycle).expect("main conf");

    log_debug!("pep: initializing worker, config={conf:?}");
    JwkCache::init(conf);

    Status::NGX_OK.into()
}
