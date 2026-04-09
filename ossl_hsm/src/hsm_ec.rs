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

//! HSM-EC: Key management and signing for HSM-backed EC keys
//!
//! Stores only key IDs (not actual key material) in KeyHandle.
//! Signing and public key export are delegated to the HSM proxy gRPC server.

use std::ffi::CStr;
use std::sync::OnceLock;

use openssl_provider_forge::bindings::{
    CONST_OSSL_PARAM, OSSL_ALGORITHM, OSSL_CALLBACK, OSSL_DISPATCH, OSSL_FUNC_KEYMGMT_EXPORT,
    OSSL_FUNC_KEYMGMT_EXPORT_TYPES, OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_GET_PARAMS,
    OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_HAS, OSSL_FUNC_KEYMGMT_IMPORT,
    OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_KEYMGMT_LOAD, OSSL_FUNC_KEYMGMT_NEW,
    OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,
    OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, OSSL_FUNC_SIGNATURE_FREECTX,
    OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_NEWCTX, OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, OSSL_FUNC_keymgmt_export_fn,
    OSSL_FUNC_keymgmt_export_types_fn, OSSL_FUNC_keymgmt_free_fn, OSSL_FUNC_keymgmt_get_params_fn,
    OSSL_FUNC_keymgmt_gettable_params_fn, OSSL_FUNC_keymgmt_has_fn, OSSL_FUNC_keymgmt_import_fn,
    OSSL_FUNC_keymgmt_import_types_fn, OSSL_FUNC_keymgmt_load_fn, OSSL_FUNC_keymgmt_new_fn,
    OSSL_FUNC_keymgmt_query_operation_name_fn, OSSL_FUNC_signature_digest_sign_fn,
    OSSL_FUNC_signature_digest_sign_init_fn, OSSL_FUNC_signature_digest_verify_fn,
    OSSL_FUNC_signature_digest_verify_init_fn, OSSL_FUNC_signature_freectx_fn,
    OSSL_FUNC_signature_get_ctx_params_fn, OSSL_FUNC_signature_gettable_ctx_params_fn,
    OSSL_FUNC_signature_newctx_fn, OSSL_FUNC_signature_set_ctx_params_fn,
    OSSL_FUNC_signature_settable_ctx_params_fn, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_PARAM, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UNMODIFIED,
    OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_UTF8_STRING, dispatch_table_entry,
};
use openssl_provider_forge::ossl_callback::OSSLCallback;
use openssl_provider_forge::osslparams::OSSLParam;

use crate::grpc_client;

// ============================================================================
// Types
// ============================================================================

/// Opaque handle - stores only the key identifier, NOT the actual key
pub struct KeyHandle {
    pub key_id: String,
}

impl KeyHandle {
    pub fn new(key_id: String) -> Self {
        Self { key_id }
    }
}

/// Signature context - tracks state during signing operation
pub struct SignCtx {
    key_id: String,
}

// ============================================================================
// KEYMGMT: Key management operations
// ============================================================================

unsafe extern "C" fn keymgmt_new(_provctx: *mut libc::c_void) -> *mut libc::c_void {
    eprintln!("[ossl_hsm] keymgmt_new");
    Box::into_raw(Box::new(KeyHandle {
        key_id: String::new(),
    })) as *mut _
}

unsafe extern "C" fn keymgmt_free(keydata: *mut libc::c_void) {
    if !keydata.is_null() {
        let h = unsafe { Box::from_raw(keydata as *mut KeyHandle) };
        eprintln!("[ossl_hsm] keymgmt_free key='{}'", h.key_id);
    }
}

unsafe extern "C" fn keymgmt_has(
    keydata: *const libc::c_void,
    selection: libc::c_int,
) -> libc::c_int {
    if keydata.is_null() {
        return 0;
    }
    let h = unsafe { &*(keydata as *const KeyHandle) };
    let have = !h.key_id.is_empty();
    let want_priv = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY as i32) != 0;
    // We must claim to have the private key even though it's remote,
    // otherwise OSSL_STORE_load rejects the key entirely.
    // The actual private key operations go through the signature dispatch.
    eprintln!(
        "[ossl_hsm] keymgmt_has key='{}' want_priv={} have={}",
        h.key_id, want_priv, have
    );
    if have { 1 } else { 0 }
}

unsafe extern "C" fn keymgmt_import(
    keydata: *mut libc::c_void,
    selection: libc::c_int,
    params: *const OSSL_PARAM,
) -> libc::c_int {
    eprintln!("[ossl_hsm] keymgmt_import called! selection={}", selection);
    if keydata.is_null() {
        eprintln!("[ossl_hsm] keymgmt_import: null keydata");
        return 0;
    }
    let h = unsafe { &mut *(keydata as *mut KeyHandle) };

    // Look for "reference" parameter containing the key ID
    if let Ok(params) = OSSLParam::try_from(params) {
        for p in params {
            let Some(key) = p.get_key() else { continue };
            if key.to_bytes() == b"reference"
                && let Some(data) = p.get::<&[u8]>()
                && let Ok(id) = std::str::from_utf8(data)
            {
                h.key_id = id.trim_end_matches('\0').to_string();
                eprintln!("[ossl_hsm] I was asked for key '{}'", h.key_id);
                return 1;
            }
        }
    }

    0
}

unsafe extern "C" fn keymgmt_import_types(selection: libc::c_int) -> *const OSSL_PARAM {
    eprintln!(
        "[ossl_hsm] keymgmt_import_types called! selection={}",
        selection
    );
    static PARAMS: &[CONST_OSSL_PARAM] = &[
        CONST_OSSL_PARAM {
            key: c"reference".as_ptr(),
            data_type: OSSL_PARAM_OCTET_STRING,
            data: std::ptr::null(),
            data_size: 0,
            return_size: OSSL_PARAM_UNMODIFIED,
        },
        CONST_OSSL_PARAM::END,
    ];
    PARAMS.as_ptr() as *const _
}

unsafe extern "C" fn keymgmt_get_params(
    keydata: *mut libc::c_void,
    params: *mut OSSL_PARAM,
) -> libc::c_int {
    if keydata.is_null() {
        return 0;
    }

    let Ok(params) = OSSLParam::try_from(params) else {
        return 0;
    };

    for mut p in params {
        let Some(key) = p.get_key() else { continue };
        eprintln!(
            "[ossl_hsm] keymgmt_get_params: asked for '{}'",
            key.to_string_lossy()
        );

        match key.to_bytes() {
            b"bits" => {
                let _ = p.set(256u32);
            }
            b"security-bits" => {
                let _ = p.set(128u32);
            }
            b"max-size" => {
                let _ = p.set(72u32);
            }
            b"group" => {
                let _ = p.set(c"prime256v1");
            }
            _ => {}
        }
    }
    1
}

unsafe extern "C" fn keymgmt_gettable_params(_provctx: *mut libc::c_void) -> *const OSSL_PARAM {
    static PARAMS: &[CONST_OSSL_PARAM] = &[
        CONST_OSSL_PARAM {
            key: c"bits".as_ptr(),
            data_type: OSSL_PARAM_UNSIGNED_INTEGER,
            data: std::ptr::null(),
            data_size: 0,
            return_size: OSSL_PARAM_UNMODIFIED,
        },
        CONST_OSSL_PARAM {
            key: c"security-bits".as_ptr(),
            data_type: OSSL_PARAM_UNSIGNED_INTEGER,
            data: std::ptr::null(),
            data_size: 0,
            return_size: OSSL_PARAM_UNMODIFIED,
        },
        CONST_OSSL_PARAM {
            key: c"max-size".as_ptr(),
            data_type: OSSL_PARAM_UNSIGNED_INTEGER,
            data: std::ptr::null(),
            data_size: 0,
            return_size: OSSL_PARAM_UNMODIFIED,
        },
        CONST_OSSL_PARAM {
            key: c"group".as_ptr(),
            data_type: OSSL_PARAM_UTF8_STRING,
            data: std::ptr::null(),
            data_size: 0,
            return_size: OSSL_PARAM_UNMODIFIED,
        },
        CONST_OSSL_PARAM::END,
    ];
    PARAMS.as_ptr() as *const _
}

/// Export key data (needed for SSL to compare key against certificate)
unsafe extern "C" fn keymgmt_export(
    keydata: *mut libc::c_void,
    selection: libc::c_int,
    param_cb: OSSL_CALLBACK,
    cbarg: *mut libc::c_void,
) -> libc::c_int {
    if keydata.is_null() {
        return 0;
    }

    let cb = match OSSLCallback::try_new(param_cb, cbarg) {
        Ok(cb) => cb,
        Err(_) => return 0,
    };

    let h = unsafe { &*(keydata as *const KeyHandle) };
    eprintln!(
        "[ossl_hsm] keymgmt_export key='{}' selection={}",
        h.key_id, selection
    );

    // If private key is requested, refuse — we can't export HSM key material.
    // OpenSSL should fall back to using the signature dispatch instead.
    let want_priv = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY as i32) != 0;
    if want_priv {
        eprintln!("[ossl_hsm] keymgmt_export: private key requested, refusing (key is in HSM)");
        return 0;
    }

    // Only export if public key is requested
    let want_pub = (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY as i32) != 0;
    if !want_pub {
        eprintln!("[ossl_hsm] keymgmt_export: public key not requested, returning success");
        return 1;
    }

    // Get public key from gRPC server
    let pub_info = match grpc_client::get_public_key(&h.key_id) {
        Ok(info) => info,
        Err(e) => {
            eprintln!("[ossl_hsm] keymgmt_export: gRPC error: {}", e);
            return 0;
        }
    };

    // Parse the PEM to extract the EC public key point
    let pkey = match openssl::pkey::PKey::public_key_from_pem(pub_info.pem.as_bytes()) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[ossl_hsm] keymgmt_export: parse PEM: {}", e);
            return 0;
        }
    };

    let ec = match pkey.ec_key() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[ossl_hsm] keymgmt_export: ec_key: {}", e);
            return 0;
        }
    };

    // Get public key point in uncompressed form
    let mut bn_ctx = openssl::bn::BigNumContext::new().unwrap();
    let pub_key_bytes = match ec.public_key().to_bytes(
        ec.group(),
        openssl::ec::PointConversionForm::UNCOMPRESSED,
        &mut bn_ctx,
    ) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[ossl_hsm] keymgmt_export: to_bytes: {}", e);
            return 0;
        }
    };

    eprintln!(
        "[ossl_hsm] keymgmt_export: public key {} bytes",
        pub_key_bytes.len()
    );

    // Build params with group name and public key
    static GROUP_NAME: &[u8] = b"prime256v1\0";

    let params: [OSSL_PARAM; 3] = [
        OSSL_PARAM {
            key: c"group".as_ptr(),
            data_type: OSSL_PARAM_UTF8_STRING,
            data: GROUP_NAME.as_ptr() as *mut _,
            data_size: GROUP_NAME.len() - 1,
            return_size: 0,
        },
        OSSL_PARAM {
            key: c"pub".as_ptr(),
            data_type: OSSL_PARAM_OCTET_STRING,
            data: pub_key_bytes.as_ptr() as *mut _,
            data_size: pub_key_bytes.len(),
            return_size: 0,
        },
        OSSL_PARAM::END,
    ];

    let ret = cb.call(&params);
    eprintln!("[ossl_hsm] keymgmt_export: callback returned {}", ret);
    ret
}

/// Advertise what we can export
unsafe extern "C" fn keymgmt_export_types(selection: libc::c_int) -> *const OSSL_PARAM {
    eprintln!("[ossl_hsm] keymgmt_export_types selection={}", selection);
    static PARAMS: &[CONST_OSSL_PARAM] = &[
        CONST_OSSL_PARAM {
            key: c"group".as_ptr(),
            data_type: OSSL_PARAM_UTF8_STRING,
            data: std::ptr::null(),
            data_size: 0,
            return_size: OSSL_PARAM_UNMODIFIED,
        },
        CONST_OSSL_PARAM {
            key: c"pub".as_ptr(),
            data_type: OSSL_PARAM_OCTET_STRING,
            data: std::ptr::null(),
            data_size: 0,
            return_size: OSSL_PARAM_UNMODIFIED,
        },
        CONST_OSSL_PARAM::END,
    ];
    PARAMS.as_ptr() as *const _
}

/// Tell OpenSSL which signature algorithm name to use for our EC keys.
/// Without this, OpenSSL looks for a signature named "EC" (same as keymgmt)
/// instead of "ECDSA".
unsafe extern "C" fn keymgmt_query_operation_name(
    operation_id: libc::c_int,
) -> *const libc::c_char {
    eprintln!(
        "[ossl_hsm] keymgmt_query_operation_name operation_id={}",
        operation_id
    );
    // OSSL_OP_SIGNATURE = 12
    if operation_id == openssl_provider_forge::bindings::OSSL_OP_SIGNATURE as libc::c_int {
        return c"ECDSA".as_ptr();
    }
    std::ptr::null()
}

/// Load a key from a reference (passed by STORE or DECODER)
/// The reference is a pointer to a KeyHandle that was boxed by the store loader
unsafe extern "C" fn keymgmt_load(
    reference: *const libc::c_void,
    reference_sz: libc::size_t,
) -> *mut libc::c_void {
    eprintln!("[ossl_hsm] keymgmt_load: reference_sz={}", reference_sz);

    if reference.is_null() {
        eprintln!("[ossl_hsm] keymgmt_load: null reference");
        return std::ptr::null_mut();
    }

    // The reference is a pointer to a boxed KeyHandle
    // We just return it as-is (the store loader boxed it for us)
    let key_handle = reference as *mut KeyHandle;
    unsafe {
        eprintln!(
            "[ossl_hsm] keymgmt_load: returning KeyHandle for key '{}'",
            (*key_handle).key_id
        );
    }

    key_handle as *mut _
}

// ============================================================================
// SIGNATURE: Signing operations
// ============================================================================

unsafe extern "C" fn signature_newctx(
    _: *mut libc::c_void,
    _: *const libc::c_char,
) -> *mut libc::c_void {
    eprintln!("[ossl_hsm] signature_newctx");
    Box::into_raw(Box::new(SignCtx {
        key_id: String::new(),
    })) as *mut _
}

unsafe extern "C" fn signature_freectx(ctx: *mut libc::c_void) {
    if !ctx.is_null() {
        eprintln!("[ossl_hsm] signature_freectx");
        drop(unsafe { Box::from_raw(ctx as *mut SignCtx) });
    }
}

unsafe extern "C" fn signature_digest_sign_init(
    ctx: *mut libc::c_void,
    mdname: *const libc::c_char,
    provkey: *mut libc::c_void,
    _params: *const OSSL_PARAM,
) -> libc::c_int {
    if ctx.is_null() {
        return 0;
    }

    let sig_ctx = unsafe { &mut *(ctx as *mut SignCtx) };

    // Capture the key reference from the KeyHandle
    if !provkey.is_null() {
        let key_handle = unsafe { &*(provkey as *const KeyHandle) };
        sig_ctx.key_id = key_handle.key_id.clone();
        eprintln!(
            "[ossl_hsm] signature_digest_sign_init key_id='{}'",
            sig_ctx.key_id
        );
    }

    if !mdname.is_null() {
        let md = unsafe { CStr::from_ptr(mdname) };
        eprintln!("[ossl_hsm] signature_digest_sign_init digest={:?}", md);
    }
    1
}

unsafe extern "C" fn signature_digest_sign(
    ctx: *mut libc::c_void,
    sig: *mut libc::c_uchar,
    siglen: *mut libc::size_t,
    _sigsize: libc::size_t,
    tbs: *const libc::c_uchar,
    tbslen: libc::size_t,
) -> libc::c_int {
    if siglen.is_null() || ctx.is_null() {
        return 0;
    }

    // If sig is NULL, caller wants to know required buffer size
    if sig.is_null() {
        unsafe { *siglen = 72 }; // Max P-256 ECDSA DER signature
        return 1;
    }

    let sig_ctx = unsafe { &*(ctx as *const SignCtx) };
    eprintln!("[ossl_hsm] I'm signing with key '{}'", sig_ctx.key_id);

    // Hash the data locally, then send the digest to the gRPC server
    let data = unsafe { std::slice::from_raw_parts(tbs, tbslen) };
    let digest = match openssl::hash::hash(openssl::hash::MessageDigest::sha256(), data) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[ossl_hsm] hash: {}", e);
            return 0;
        }
    };

    // Call gRPC server to sign (with NONE = pre-hashed)
    let p1363 = match grpc_client::sign(&sig_ctx.key_id, &digest) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[ossl_hsm] gRPC sign: {}", e);
            return 0;
        }
    };

    // Convert IEEE P1363 (raw R|S) to ASN.1 DER for TLS
    let component_len = p1363.len() / 2;
    let r = openssl::bn::BigNum::from_slice(&p1363[..component_len]);
    let s = openssl::bn::BigNum::from_slice(&p1363[component_len..]);
    let (r, s) = match (r, s) {
        (Ok(r), Ok(s)) => (r, s),
        _ => {
            eprintln!("[ossl_hsm] P1363 parse error");
            return 0;
        }
    };

    let ecdsa_sig = match openssl::ecdsa::EcdsaSig::from_private_components(r, s) {
        Ok(sig) => sig,
        Err(e) => {
            eprintln!("[ossl_hsm] EcdsaSig: {}", e);
            return 0;
        }
    };

    let der = match ecdsa_sig.to_der() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[ossl_hsm] to_der: {}", e);
            return 0;
        }
    };

    eprintln!("[ossl_hsm] Signed via gRPC ({} bytes DER)", der.len());
    unsafe {
        std::ptr::copy_nonoverlapping(der.as_ptr(), sig, der.len());
        *siglen = der.len();
    };
    1
}

unsafe extern "C" fn signature_digest_verify_init(
    ctx: *mut libc::c_void,
    mdname: *const libc::c_char,
    provkey: *mut libc::c_void,
    _params: *const OSSL_PARAM,
) -> libc::c_int {
    if ctx.is_null() {
        return 0;
    }

    unsafe {
        let sig_ctx = &mut *(ctx as *mut SignCtx);

        if !provkey.is_null() {
            let key_handle = &*(provkey as *const KeyHandle);
            sig_ctx.key_id = key_handle.key_id.clone();
        }

        if !mdname.is_null() {
            let md = CStr::from_ptr(mdname);
            eprintln!("[ossl_hsm] signature_digest_verify_init digest={:?}", md);
        }
    }
    1
}

unsafe extern "C" fn signature_digest_verify(
    _ctx: *mut libc::c_void,
    _sig: *const libc::c_uchar,
    _siglen: libc::size_t,
    _tbs: *const libc::c_uchar,
    _tbslen: libc::size_t,
) -> libc::c_int {
    // Verification is not supported via HSM proxy (server-side TLS only needs signing).
    // The TLS peer verifies using the public key from the certificate directly.
    eprintln!("[ossl_hsm] signature_digest_verify: not implemented");
    0
}

/// Get signature context parameters
unsafe extern "C" fn signature_get_ctx_params(
    _ctx: *mut libc::c_void,
    params: *mut OSSL_PARAM,
) -> libc::c_int {
    let Ok(params) = OSSLParam::try_from(params) else {
        return 1;
    };

    for mut p in params {
        let Some(key) = p.get_key() else { continue };
        eprintln!(
            "[ossl_hsm] signature_get_ctx_params: asked for '{}'",
            key.to_string_lossy()
        );

        if key.to_bytes() == b"digest" {
            let _ = p.set(c"SHA256");
        }
    }
    1
}

/// Return what parameters can be retrieved from signature context
unsafe extern "C" fn signature_gettable_ctx_params(
    _ctx: *mut libc::c_void,
    _provctx: *mut libc::c_void,
) -> *const OSSL_PARAM {
    static PARAMS: &[CONST_OSSL_PARAM] = &[
        CONST_OSSL_PARAM {
            key: c"digest".as_ptr(),
            data_type: OSSL_PARAM_UTF8_STRING,
            data: std::ptr::null(),
            data_size: 0,
            return_size: OSSL_PARAM_UNMODIFIED,
        },
        CONST_OSSL_PARAM::END,
    ];
    PARAMS.as_ptr() as *const _
}

/// Set signature context parameters
unsafe extern "C" fn signature_set_ctx_params(
    _ctx: *mut libc::c_void,
    params: *const OSSL_PARAM,
) -> libc::c_int {
    // We accept digest parameter but always use SHA-256
    let Ok(params) = OSSLParam::try_from(params) else {
        return 1;
    };

    for p in params {
        if let Some(key) = p.get_key() {
            eprintln!(
                "[ossl_hsm] signature_set_ctx_params: '{}' set",
                key.to_string_lossy()
            );
        }
    }
    1
}

/// Return what parameters can be set on signature context
unsafe extern "C" fn signature_settable_ctx_params(
    _ctx: *mut libc::c_void,
    _provctx: *mut libc::c_void,
) -> *const OSSL_PARAM {
    static PARAMS: &[CONST_OSSL_PARAM] = &[
        CONST_OSSL_PARAM {
            key: c"digest".as_ptr(),
            data_type: OSSL_PARAM_UTF8_STRING,
            data: std::ptr::null(),
            data_size: 0,
            return_size: OSSL_PARAM_UNMODIFIED,
        },
        CONST_OSSL_PARAM::END,
    ];
    PARAMS.as_ptr() as *const _
}

// ============================================================================
// Dispatch tables (function pointer tables that OpenSSL calls into)
// ============================================================================

const KEYMGMT_DISPATCH: &[OSSL_DISPATCH] = &[
    dispatch_table_entry!(OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_keymgmt_new_fn, keymgmt_new),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_FREE,
        OSSL_FUNC_keymgmt_free_fn,
        keymgmt_free
    ),
    dispatch_table_entry!(OSSL_FUNC_KEYMGMT_HAS, OSSL_FUNC_keymgmt_has_fn, keymgmt_has),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_GET_PARAMS,
        OSSL_FUNC_keymgmt_get_params_fn,
        keymgmt_get_params
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        OSSL_FUNC_keymgmt_gettable_params_fn,
        keymgmt_gettable_params
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_IMPORT,
        OSSL_FUNC_keymgmt_import_fn,
        keymgmt_import
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
        OSSL_FUNC_keymgmt_import_types_fn,
        keymgmt_import_types
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_EXPORT,
        OSSL_FUNC_keymgmt_export_fn,
        keymgmt_export
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
        OSSL_FUNC_keymgmt_export_types_fn,
        keymgmt_export_types
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
        OSSL_FUNC_keymgmt_query_operation_name_fn,
        keymgmt_query_operation_name
    ),
    dispatch_table_entry!(
        OSSL_FUNC_KEYMGMT_LOAD,
        OSSL_FUNC_keymgmt_load_fn,
        keymgmt_load
    ),
    OSSL_DISPATCH::END,
];

const SIGNATURE_DISPATCH: &[OSSL_DISPATCH] = &[
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_NEWCTX,
        OSSL_FUNC_signature_newctx_fn,
        signature_newctx
    ),
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_FREECTX,
        OSSL_FUNC_signature_freectx_fn,
        signature_freectx
    ),
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        OSSL_FUNC_signature_digest_sign_init_fn,
        signature_digest_sign_init
    ),
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
        OSSL_FUNC_signature_digest_sign_fn,
        signature_digest_sign
    ),
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
        OSSL_FUNC_signature_digest_verify_init_fn,
        signature_digest_verify_init
    ),
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,
        OSSL_FUNC_signature_digest_verify_fn,
        signature_digest_verify
    ),
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
        OSSL_FUNC_signature_get_ctx_params_fn,
        signature_get_ctx_params
    ),
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
        OSSL_FUNC_signature_gettable_ctx_params_fn,
        signature_gettable_ctx_params
    ),
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        OSSL_FUNC_signature_set_ctx_params_fn,
        signature_set_ctx_params
    ),
    dispatch_table_entry!(
        OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        OSSL_FUNC_signature_settable_ctx_params_fn,
        signature_settable_ctx_params
    ),
    OSSL_DISPATCH::END,
];

// ============================================================================
// Algorithm registration (tells OpenSSL what we provide)
// ============================================================================

/// Wrapper to make raw pointer Sync+Send for static storage
#[derive(Clone, Copy)]
pub struct AlgPtr(pub *const OSSL_ALGORITHM);
unsafe impl Sync for AlgPtr {}
unsafe impl Send for AlgPtr {}

pub static KEYMGMT_ALGORITHMS: OnceLock<AlgPtr> = OnceLock::new();
pub static SIGNATURE_ALGORITHMS: OnceLock<AlgPtr> = OnceLock::new();

pub fn init_algorithms() {
    KEYMGMT_ALGORITHMS.get_or_init(|| {
        let algs = Box::new([
            OSSL_ALGORITHM {
                // Register as "EC" so SSL recognizes this as an EC key type
                algorithm_names: c"EC".as_ptr(),
                property_definition: c"provider=ossl_hsm".as_ptr(),
                implementation: KEYMGMT_DISPATCH.as_ptr(),
                algorithm_description: c"HSM-backed EC keys".as_ptr(),
            },
            OSSL_ALGORITHM::END,
        ]);
        AlgPtr(Box::into_raw(algs) as *const _)
    });

    SIGNATURE_ALGORITHMS.get_or_init(|| {
        let algs = Box::new([
            OSSL_ALGORITHM {
                // Register as "ECDSA" so SSL can find it for EC keys
                algorithm_names: c"ECDSA".as_ptr(),
                property_definition: c"provider=ossl_hsm".as_ptr(),
                implementation: SIGNATURE_DISPATCH.as_ptr(),
                algorithm_description: c"HSM-backed EC signatures".as_ptr(),
            },
            OSSL_ALGORITHM::END,
        ]);
        AlgPtr(Box::into_raw(algs) as *const _)
    });
}
