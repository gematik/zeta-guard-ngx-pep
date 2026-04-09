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

//! STORE loader for hsm: URIs
//!
//! Handles URIs like: hsm:keyid

use std::ffi::CStr;
use std::sync::OnceLock;

use openssl_provider_forge::bindings::{
    OSSL_ALGORITHM, OSSL_CALLBACK, OSSL_DISPATCH, OSSL_FUNC_STORE_CLOSE, OSSL_FUNC_STORE_EOF,
    OSSL_FUNC_STORE_LOAD, OSSL_FUNC_STORE_OPEN, OSSL_FUNC_store_close_fn, OSSL_FUNC_store_eof_fn,
    OSSL_FUNC_store_load_fn, OSSL_FUNC_store_open_fn, OSSL_OBJECT_PARAM_DATA_TYPE,
    OSSL_OBJECT_PARAM_REFERENCE, OSSL_OBJECT_PARAM_TYPE, OSSL_PARAM, OSSL_PARAM_INTEGER,
    OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UTF8_STRING, OSSL_PASSPHRASE_CALLBACK,
    dispatch_table_entry,
};
use openssl_provider_forge::ossl_callback::OSSLCallback;

use crate::hsm_ec::AlgPtr;

/// Object type for private key (from OpenSSL's core_object.h: OSSL_OBJECT_PKEY = 2)
const OSSL_OBJECT_PKEY: libc::c_int = 2;

/// Store loader context - tracks state during loading
struct StoreCtx {
    key_id: String,
    loaded: bool,
}

// ============================================================================
// STORE operations
// ============================================================================

/// Open a store URI like "hsm:mykeyid"
unsafe extern "C" fn store_open(
    _provctx: *mut libc::c_void,
    uri: *const libc::c_char,
) -> *mut libc::c_void {
    if uri.is_null() {
        eprintln!("[ossl_hsm] store_open: null URI");
        return std::ptr::null_mut();
    }

    let uri_str = match unsafe { CStr::from_ptr(uri).to_str() } {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[ossl_hsm] store_open: invalid UTF-8 in URI: {}", e);
            return std::ptr::null_mut();
        }
    };

    eprintln!("[ossl_hsm] store_open('{}')", uri_str);

    // Parse the URI
    let key_id = if let Some(rest) = uri_str.strip_prefix("hsm:") {
        rest.to_string()
    } else {
        eprintln!("[ossl_hsm] store_open: URI must start with 'hsm:'");
        return std::ptr::null_mut();
    };

    if key_id.is_empty() {
        eprintln!("[ossl_hsm] store_open: empty key ID in URI");
        return std::ptr::null_mut();
    }

    eprintln!("[ossl_hsm] store_open: key_id='{}'", key_id);

    let ctx = Box::new(StoreCtx {
        key_id,
        loaded: false,
    });

    Box::into_raw(ctx) as *mut _
}

/// Load the next object from the store (we only have one: the key)
unsafe extern "C" fn store_load(
    loaderctx: *mut libc::c_void,
    object_cb: OSSL_CALLBACK,
    object_cbarg: *mut libc::c_void,
    _pw_cb: OSSL_PASSPHRASE_CALLBACK,
    _pw_cbarg: *mut libc::c_void,
) -> libc::c_int {
    if loaderctx.is_null() {
        eprintln!("[ossl_hsm] store_load: null context");
        return 0;
    }

    let ctx = unsafe { &mut *(loaderctx as *mut StoreCtx) };

    // Only load once
    if ctx.loaded {
        eprintln!("[ossl_hsm] store_load: already loaded, returning EOF");
        return 1;
    }

    eprintln!("[ossl_hsm] store_load: loading key '{}'", ctx.key_id);

    let cb = match OSSLCallback::try_new(object_cb, object_cbarg) {
        Ok(cb) => cb,
        Err(_) => {
            eprintln!("[ossl_hsm] store_load: no callback provided");
            return 0;
        }
    };

    // Create a KeyHandle and pass it by reference
    // The keymgmt_load function will receive this reference
    use crate::hsm_ec::KeyHandle;

    let key_handle = Box::new(KeyHandle::new(ctx.key_id.clone()));
    let key_handle_ptr = Box::into_raw(key_handle);
    let reference_size = std::mem::size_of::<KeyHandle>();

    eprintln!(
        "[ossl_hsm] store_load: passing KeyHandle reference ({} bytes)",
        reference_size
    );

    let object_type: libc::c_int = OSSL_OBJECT_PKEY;
    // Use standard "EC" type so OpenSSL recognizes this as an EC key
    static DATA_TYPE: &[u8] = b"EC\0";

    let params: [OSSL_PARAM; 4] = [
        OSSL_PARAM {
            key: OSSL_OBJECT_PARAM_TYPE.as_ptr(),
            data_type: OSSL_PARAM_INTEGER,
            data: &object_type as *const _ as *mut _,
            data_size: std::mem::size_of::<libc::c_int>(),
            return_size: 0,
        },
        OSSL_PARAM {
            key: OSSL_OBJECT_PARAM_DATA_TYPE.as_ptr(),
            data_type: OSSL_PARAM_UTF8_STRING,
            data: DATA_TYPE.as_ptr() as *mut _,
            data_size: DATA_TYPE.len() - 1,
            return_size: 0,
        },
        OSSL_PARAM {
            key: OSSL_OBJECT_PARAM_REFERENCE.as_ptr(),
            data_type: OSSL_PARAM_OCTET_STRING,
            data: key_handle_ptr as *mut _,
            data_size: reference_size,
            return_size: 0,
        },
        OSSL_PARAM::END,
    ];

    ctx.loaded = true;

    // Call the callback with our parameters
    let ret = cb.call(&params);
    eprintln!("[ossl_hsm] store_load: callback returned {}", ret);

    1
}

/// Check if we've reached end of objects
unsafe extern "C" fn store_eof(loaderctx: *mut libc::c_void) -> libc::c_int {
    if loaderctx.is_null() {
        return 1;
    }

    let ctx = unsafe { &*(loaderctx as *const StoreCtx) };
    let eof = if ctx.loaded { 1 } else { 0 };
    eprintln!("[ossl_hsm] store_eof: {}", eof);
    eof
}

/// Close the store and free resources
unsafe extern "C" fn store_close(loaderctx: *mut libc::c_void) -> libc::c_int {
    if !loaderctx.is_null() {
        let ctx = unsafe { Box::from_raw(loaderctx as *mut StoreCtx) };
        eprintln!("[ossl_hsm] store_close: key_id='{}'", ctx.key_id);
    }
    1
}

// ============================================================================
// Dispatch table
// ============================================================================

const STORE_DISPATCH: &[OSSL_DISPATCH] = &[
    dispatch_table_entry!(OSSL_FUNC_STORE_OPEN, OSSL_FUNC_store_open_fn, store_open),
    dispatch_table_entry!(OSSL_FUNC_STORE_LOAD, OSSL_FUNC_store_load_fn, store_load),
    dispatch_table_entry!(OSSL_FUNC_STORE_EOF, OSSL_FUNC_store_eof_fn, store_eof),
    dispatch_table_entry!(OSSL_FUNC_STORE_CLOSE, OSSL_FUNC_store_close_fn, store_close),
    OSSL_DISPATCH::END,
];

// ============================================================================
// Algorithm registration
// ============================================================================

pub static STORE_ALGORITHMS: OnceLock<AlgPtr> = OnceLock::new();

pub fn init_algorithms() {
    STORE_ALGORITHMS.get_or_init(|| {
        let algs = Box::new([
            OSSL_ALGORITHM {
                algorithm_names: c"hsm".as_ptr(), // This is the URI scheme
                property_definition: c"provider=ossl_hsm".as_ptr(),
                implementation: STORE_DISPATCH.as_ptr(),
                algorithm_description: c"HSM key store loader".as_ptr(),
            },
            OSSL_ALGORITHM::END,
        ]);
        AlgPtr(Box::into_raw(algs) as *const _)
    });
}
