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

//! HSM Proxy Provider - OpenSSL 3.x provider for HSM-backed keys

#[macro_use]
extern crate log;

pub mod grpc_client;

use std::ffi::CString;
use std::sync::{LazyLock, Once};

use openssl_provider_forge::bindings::{
    self, OSSL_ALGORITHM, OSSL_DISPATCH, OSSL_FUNC_PROVIDER_GET_PARAMS,
    OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, OSSL_FUNC_PROVIDER_QUERY_OPERATION,
    OSSL_FUNC_PROVIDER_TEARDOWN, OSSL_FUNC_provider_get_params_fn,
    OSSL_FUNC_provider_gettable_params_fn, OSSL_FUNC_provider_query_operation_fn,
    OSSL_FUNC_provider_teardown_fn, OSSL_OP_KEYMGMT, OSSL_OP_SIGNATURE, OSSL_OP_STORE, OSSL_PARAM,
    OSSL_PROV_PARAM_NAME, OSSL_PROV_PARAM_VERSION, dispatch_table_entry,
};
use openssl_provider_forge::osslparams::OSSLParam;
use openssl_provider_forge::upcalls::OSSL_CORE_HANDLE;

mod hsm_ec;
mod hsm_store;

// ============================================================================
// Provider callbacks
// ============================================================================

fn init_logging() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        env_logger::Builder::from_default_env()
            .format_timestamp(None)
            .try_init()
            .ok();
    });
}

unsafe extern "C" fn provider_teardown(provctx: *mut libc::c_void) {
    info!("[ossl_hsm] teardown");
    if !provctx.is_null() {
        drop(unsafe { Box::from_raw(provctx as *mut *const OSSL_CORE_HANDLE) });
    }
}

unsafe extern "C" fn gettable_params(_: *mut libc::c_void) -> *const OSSL_PARAM {
    static PARAMS: &[bindings::CONST_OSSL_PARAM] = &[
        bindings::CONST_OSSL_PARAM {
            key: OSSL_PROV_PARAM_NAME.as_ptr(),
            data_type: bindings::OSSL_PARAM_UTF8_PTR,
            data: std::ptr::null(),
            data_size: 0,
            return_size: bindings::OSSL_PARAM_UNMODIFIED,
        },
        bindings::CONST_OSSL_PARAM {
            key: OSSL_PROV_PARAM_VERSION.as_ptr(),
            data_type: bindings::OSSL_PARAM_UTF8_PTR,
            data: std::ptr::null(),
            data_size: 0,
            return_size: bindings::OSSL_PARAM_UNMODIFIED,
        },
        bindings::CONST_OSSL_PARAM::END,
    ];
    PARAMS.as_ptr() as *const _
}

static VERSION: LazyLock<CString> =
    LazyLock::new(|| CString::new(env!("CARGO_PKG_VERSION")).unwrap());

unsafe extern "C" fn get_params(_: *mut libc::c_void, params: *mut OSSL_PARAM) -> libc::c_int {
    let Ok(params) = OSSLParam::try_from(params) else {
        return 0;
    };

    for mut p in params {
        let Some(key) = p.get_key() else { continue };
        if key == OSSL_PROV_PARAM_NAME {
            let _ = p.set(c"ossl_hsm");
        } else if key == OSSL_PROV_PARAM_VERSION {
            let _ = p.set(VERSION.as_c_str());
        }
    }
    1
}

unsafe extern "C" fn query_operation(
    _: *mut libc::c_void,
    operation_id: libc::c_int,
    no_cache: *mut libc::c_int,
) -> *const OSSL_ALGORITHM {
    if !no_cache.is_null() {
        unsafe { *no_cache = 0 };
    }

    match operation_id as u32 {
        OSSL_OP_KEYMGMT => hsm_ec::KEYMGMT_ALGORITHMS
            .get()
            .map_or(std::ptr::null(), |p| p.0),
        OSSL_OP_SIGNATURE => hsm_ec::SIGNATURE_ALGORITHMS
            .get()
            .map_or(std::ptr::null(), |p| p.0),
        OSSL_OP_STORE => hsm_store::STORE_ALGORITHMS
            .get()
            .map_or(std::ptr::null(), |p| p.0),
        _ => std::ptr::null(),
    }
}

// ============================================================================
// Provider entry point
// ============================================================================

#[unsafe(no_mangle)]
unsafe extern "C" fn OSSL_provider_init(
    handle: *const OSSL_CORE_HANDLE,
    _in: *const OSSL_DISPATCH,
    out: *mut *const OSSL_DISPATCH,
    provctx: *mut *mut libc::c_void,
) -> libc::c_int {
    init_logging();
    info!("[ossl_hsm] init");

    grpc_client::init();

    hsm_ec::init_algorithms();
    hsm_store::init_algorithms();

    static DISPATCH: &[OSSL_DISPATCH] = &[
        dispatch_table_entry!(
            OSSL_FUNC_PROVIDER_TEARDOWN,
            OSSL_FUNC_provider_teardown_fn,
            provider_teardown
        ),
        dispatch_table_entry!(
            OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
            OSSL_FUNC_provider_gettable_params_fn,
            gettable_params
        ),
        dispatch_table_entry!(
            OSSL_FUNC_PROVIDER_GET_PARAMS,
            OSSL_FUNC_provider_get_params_fn,
            get_params
        ),
        dispatch_table_entry!(
            OSSL_FUNC_PROVIDER_QUERY_OPERATION,
            OSSL_FUNC_provider_query_operation_fn,
            query_operation
        ),
        OSSL_DISPATCH::END,
    ];

    // Store handle as our context (we don't actually use it in this MVP)
    unsafe {
        *provctx = Box::into_raw(Box::new(handle)) as *mut _;
        *out = DISPATCH.as_ptr()
    };

    info!("[ossl_hsm] ready");
    1
}
