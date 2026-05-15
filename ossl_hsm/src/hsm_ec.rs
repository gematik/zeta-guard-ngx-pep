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

use openssl::hash::MessageDigest;
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

/// Public key material fetched from the HSM proxy on first use. We can't
/// retrieve the private key, but the public key tells us the curve (via the
/// EC group OID) and gives us the uncompressed point that OpenSSL needs for
/// cert/key matching in `keymgmt_export`.
pub struct KeyMaterial {
    pub curve: Curve,
    pub pub_uncompressed: Vec<u8>,
}

/// Opaque handle — stores only the key identifier, NOT the actual key.
/// `material` is populated lazily on first call to [`KeyHandle::material`].
pub struct KeyHandle {
    pub key_id: String,
    material: OnceLock<KeyMaterial>,
}

impl KeyHandle {
    pub fn new(key_id: String) -> Self {
        Self {
            key_id,
            material: OnceLock::new(),
        }
    }

    /// Fetch the public key from the HSM proxy (once) and cache the curve plus
    /// the uncompressed public key bytes. Subsequent calls hit the cache.
    pub fn material(&self) -> Result<&KeyMaterial, String> {
        if let Some(m) = self.material.get() {
            return Ok(m);
        }
        let info = grpc_client::get_public_key(&self.key_id)?;
        let pkey = openssl::pkey::PKey::public_key_from_pem(info.pem.as_bytes())
            .map_err(|e| format!("parse PEM: {e}"))?;
        let ec = pkey.ec_key().map_err(|e| format!("ec_key: {e}"))?;
        let group = ec.group();
        let curve = Curve::from_ec_group(group).ok_or_else(|| {
            format!(
                "unsupported EC curve for key '{}' (only P-256, P-384, brainpoolP{{256,384,512}}r1 supported)",
                self.key_id
            )
        })?;
        let mut bn_ctx =
            openssl::bn::BigNumContext::new().map_err(|e| format!("BigNumContext::new: {e}"))?;
        let pub_uncompressed = ec
            .public_key()
            .to_bytes(
                group,
                openssl::ec::PointConversionForm::UNCOMPRESSED,
                &mut bn_ctx,
            )
            .map_err(|e| format!("public_key.to_bytes: {e}"))?;
        // OnceLock::set: ignore the racy-loser case, the value is the same anyway.
        let _ = self.material.set(KeyMaterial {
            curve,
            pub_uncompressed,
        });
        Ok(self.material.get().unwrap())
    }
}

/// Signature context — tracks state during a signing operation. Both fields
/// are populated in `signature_digest_sign_init` from the bound key.
pub struct SignCtx {
    key_id: String,
    digest: Option<MessageDigest>,
    curve: Option<Curve>,
}

/// The curve is determined from the EC group OID in the returned public key.
///
/// Supported curves per gemSpec_Krypt A_28868: P-256 and P-384 (MUSS),
/// brainpoolP{256,384,512}r1 (KÖNNEN). P-521 is "andere" and SOLLEN NICHT,
/// so it is not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
    BrainpoolP256,
    BrainpoolP384,
    BrainpoolP512,
}

impl Curve {
    /// Identify the curve from an OpenSSL EC group (the group of the public
    /// key the HSM proxy returned). Returns None for unsupported curves.
    pub fn from_ec_group(group: &openssl::ec::EcGroupRef) -> Option<Self> {
        match group.curve_name()? {
            openssl::nid::Nid::X9_62_PRIME256V1 => Some(Self::P256),
            openssl::nid::Nid::SECP384R1 => Some(Self::P384),
            openssl::nid::Nid::BRAINPOOL_P256R1 => Some(Self::BrainpoolP256),
            openssl::nid::Nid::BRAINPOOL_P384R1 => Some(Self::BrainpoolP384),
            openssl::nid::Nid::BRAINPOOL_P512R1 => Some(Self::BrainpoolP512),
            _ => None,
        }
    }

    pub fn bits(self) -> u32 {
        match self {
            Self::P256 | Self::BrainpoolP256 => 256,
            Self::P384 | Self::BrainpoolP384 => 384,
            Self::BrainpoolP512 => 512,
        }
    }

    pub fn security_bits(self) -> u32 {
        match self {
            Self::P256 | Self::BrainpoolP256 => 128,
            Self::P384 | Self::BrainpoolP384 => 192,
            Self::BrainpoolP512 => 256,
        }
    }

    /// Max DER-encoded ECDSA signature length. ASN.1 SEQUENCE of two INTEGERs,
    /// each up to ceil(bits/8)+1 bytes (sign-bit padding) plus tag/length overhead.
    pub fn max_sig_der_len(self) -> usize {
        match self {
            Self::P256 | Self::BrainpoolP256 => 72,
            Self::P384 | Self::BrainpoolP384 => 104,
            Self::BrainpoolP512 => 137,
        }
    }

    pub fn group_cstr(self) -> &'static CStr {
        match self {
            Self::P256 => c"prime256v1",
            Self::P384 => c"secp384r1",
            Self::BrainpoolP256 => c"brainpoolP256r1",
            Self::BrainpoolP384 => c"brainpoolP384r1",
            Self::BrainpoolP512 => c"brainpoolP512r1",
        }
    }

    /// NUL-terminated bytes for OSSL_PARAM_UTF8_STRING exposure (OpenSSL expects
    /// the pointed-at memory to outlive the param, so this returns a `&'static`).
    pub fn group_name_bytes(self) -> &'static [u8] {
        match self {
            Self::P256 => b"prime256v1\0",
            Self::P384 => b"secp384r1\0",
            Self::BrainpoolP256 => b"brainpoolP256r1\0",
            Self::BrainpoolP384 => b"brainpoolP384r1\0",
            Self::BrainpoolP512 => b"brainpoolP512r1\0",
        }
    }

    /// TLS 1.2/1.3 default digest for ECDSA with this curve. Pairs each curve
    /// with the SHA-2 variant of matching strength (RFC 5639 §3 / TR-03111).
    pub fn default_digest(self) -> MessageDigest {
        match self {
            Self::P256 | Self::BrainpoolP256 => MessageDigest::sha256(),
            Self::P384 | Self::BrainpoolP384 => MessageDigest::sha384(),
            Self::BrainpoolP512 => MessageDigest::sha512(),
        }
    }
}

/// Map an OpenSSL digest name (`mdname`) to a `MessageDigest`. Accepts the
/// common spellings OpenSSL uses interchangeably ("SHA256", "SHA-256", "SHA2-256").
fn digest_from_mdname(mdname: &CStr) -> Option<MessageDigest> {
    match mdname.to_bytes() {
        b"SHA256" | b"SHA-256" | b"SHA2-256" => Some(MessageDigest::sha256()),
        b"SHA384" | b"SHA-384" | b"SHA2-384" => Some(MessageDigest::sha384()),
        b"SHA512" | b"SHA-512" | b"SHA2-512" => Some(MessageDigest::sha512()),
        _ => None,
    }
}

/// Reverse of `digest_from_mdname`: return the canonical OpenSSL name (NUL-
/// terminated for OSSL_PARAM_UTF8_STRING use) for a `MessageDigest`.
fn digest_name(d: &MessageDigest) -> &'static CStr {
    match d.type_() {
        openssl::nid::Nid::SHA256 => c"SHA256",
        openssl::nid::Nid::SHA384 => c"SHA384",
        openssl::nid::Nid::SHA512 => c"SHA512",
        _ => c"SHA256",
    }
}

// ============================================================================
// KEYMGMT: Key management operations
// ============================================================================

unsafe extern "C" fn keymgmt_new(_provctx: *mut libc::c_void) -> *mut libc::c_void {
    Box::into_raw(Box::new(KeyHandle::new(String::new()))) as *mut _
}

unsafe extern "C" fn keymgmt_free(keydata: *mut libc::c_void) {
    if !keydata.is_null() {
        let _ = unsafe { Box::from_raw(keydata as *mut KeyHandle) };
    }
}

unsafe extern "C" fn keymgmt_has(
    keydata: *const libc::c_void,
    _selection: libc::c_int,
) -> libc::c_int {
    if keydata.is_null() {
        return 0;
    }
    let h = unsafe { &*(keydata as *const KeyHandle) };
    // We must claim to have the private key even though it's remote,
    // otherwise OSSL_STORE_load rejects the key entirely.
    // The actual private key operations go through the signature dispatch.
    if !h.key_id.is_empty() { 1 } else { 0 }
}

unsafe extern "C" fn keymgmt_import(
    keydata: *mut libc::c_void,
    _selection: libc::c_int,
    params: *const OSSL_PARAM,
) -> libc::c_int {
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
                return 1;
            }
        }
    }

    0
}

unsafe extern "C" fn keymgmt_import_types(_selection: libc::c_int) -> *const OSSL_PARAM {
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

    let h = unsafe { &*(keydata as *const KeyHandle) };
    let curve = match h.material() {
        Ok(m) => m.curve,
        Err(e) => {
            eprintln!("[ossl_hsm] keymgmt_get_params: {}", e);
            return 0;
        }
    };

    for mut p in params {
        let Some(key) = p.get_key() else { continue };
        match key.to_bytes() {
            b"bits" => {
                let _ = p.set(curve.bits());
            }
            b"security-bits" => {
                let _ = p.set(curve.security_bits());
            }
            b"max-size" => {
                let _ = p.set(curve.max_sig_der_len() as u32);
            }
            b"group" => {
                let _ = p.set(curve.group_cstr());
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

    // If private key is requested, refuse — we can't export HSM key material.
    // OpenSSL should fall back to using the signature dispatch instead.
    let want_priv = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY as i32) != 0;
    if want_priv {
        return 0;
    }

    // Only export if public key is requested
    let want_pub = (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY as i32) != 0;
    if !want_pub {
        return 1;
    }

    let material = match h.material() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("[ossl_hsm] keymgmt_export: {}", e);
            return 0;
        }
    };

    eprintln!(
        "[ossl_hsm] keymgmt_export: returning public key, key_id={}, curve={:?}, {} bytes",
        &h.key_id,
        material.curve,
        material.pub_uncompressed.len()
    );

    let group_name = material.curve.group_name_bytes();
    let params: [OSSL_PARAM; 3] = [
        OSSL_PARAM {
            key: c"group".as_ptr(),
            data_type: OSSL_PARAM_UTF8_STRING,
            data: group_name.as_ptr() as *mut _,
            data_size: group_name.len() - 1,
            return_size: 0,
        },
        OSSL_PARAM {
            key: c"pub".as_ptr(),
            data_type: OSSL_PARAM_OCTET_STRING,
            data: material.pub_uncompressed.as_ptr() as *mut _,
            data_size: material.pub_uncompressed.len(),
            return_size: 0,
        },
        OSSL_PARAM::END,
    ];

    cb.call(&params)
}

/// Advertise what we can export
unsafe extern "C" fn keymgmt_export_types(_selection: libc::c_int) -> *const OSSL_PARAM {
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
    if operation_id == openssl_provider_forge::bindings::OSSL_OP_SIGNATURE as libc::c_int {
        return c"ECDSA".as_ptr();
    }
    std::ptr::null()
}

/// Load a key from a reference (passed by STORE or DECODER)
/// The reference is a pointer to a KeyHandle that was boxed by the store loader
unsafe extern "C" fn keymgmt_load(
    reference: *const libc::c_void,
    _reference_sz: libc::size_t,
) -> *mut libc::c_void {
    if reference.is_null() {
        eprintln!("[ossl_hsm] keymgmt_load: null reference");
        return std::ptr::null_mut();
    }

    // The reference is a pointer to a boxed KeyHandle
    // We just return it as-is (the store loader boxed it for us)
    let key_handle = reference as *mut KeyHandle;
    unsafe {
        eprintln!(
            "[ossl_hsm] keymgmt_load: returning KeyHandle for key_id={}",
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
    Box::into_raw(Box::new(SignCtx {
        key_id: String::new(),
        digest: None,
        curve: None,
    })) as *mut _
}

unsafe extern "C" fn signature_freectx(ctx: *mut libc::c_void) {
    if !ctx.is_null() {
        drop(unsafe { Box::from_raw(ctx as *mut SignCtx) });
    }
}

unsafe extern "C" fn signature_digest_sign_init(
    ctx: *mut libc::c_void,
    mdname: *const libc::c_char,
    provkey: *mut libc::c_void,
    _params: *const OSSL_PARAM,
) -> libc::c_int {
    if ctx.is_null() || provkey.is_null() {
        return 0;
    }

    let sig_ctx = unsafe { &mut *(ctx as *mut SignCtx) };
    let key_handle = unsafe { &*(provkey as *const KeyHandle) };

    let curve = match key_handle.material() {
        Ok(m) => m.curve,
        Err(e) => {
            eprintln!("[ossl_hsm] signature_digest_sign_init: {}", e);
            return 0;
        }
    };

    let digest = if mdname.is_null() {
        curve.default_digest()
    } else {
        let md = unsafe { CStr::from_ptr(mdname) };
        match digest_from_mdname(md) {
            Some(d) => d,
            None => {
                eprintln!(
                    "[ossl_hsm] signature_digest_sign_init: unknown digest {:?}",
                    md
                );
                return 0;
            }
        }
    };

    sig_ctx.key_id = key_handle.key_id.clone();
    sig_ctx.curve = Some(curve);
    sig_ctx.digest = Some(digest);

    eprintln!(
        "[ossl_hsm] signature_digest_sign_init key_id={}, curve={:?}, digest={}",
        &sig_ctx.key_id,
        curve,
        digest_name(&digest).to_str().unwrap(),
    );
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

    let sig_ctx = unsafe { &*(ctx as *const SignCtx) };
    let (Some(curve), Some(md)) = (sig_ctx.curve, sig_ctx.digest) else {
        eprintln!("[ossl_hsm] signature_digest_sign: not initialized");
        return 0;
    };

    // If sig is NULL, caller wants to know required buffer size
    if sig.is_null() {
        unsafe { *siglen = curve.max_sig_der_len() };
        return 1;
    }

    // Hash the data locally, then send the digest to the gRPC server
    let data = unsafe { std::slice::from_raw_parts(tbs, tbslen) };
    let digest = match openssl::hash::hash(md, data) {
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

    eprintln!(
        "[ossl_hsm] Signed via gRPC, key_id={}, curve={:?}, digest={}, {} bytes DER",
        &sig_ctx.key_id,
        curve,
        digest_name(&md).to_str().unwrap(),
        der.len()
    );
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
            eprintln!(
                "[ossl_hsm] signature_digest_verify_init key_id={}",
                &key_handle.key_id
            );
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
    ctx: *mut libc::c_void,
    params: *mut OSSL_PARAM,
) -> libc::c_int {
    let Ok(params) = OSSLParam::try_from(params) else {
        return 1;
    };

    let digest = if ctx.is_null() {
        None
    } else {
        unsafe { &*(ctx as *const SignCtx) }.digest
    };

    for mut p in params {
        let Some(key) = p.get_key() else { continue };
        if key.to_bytes() == b"digest"
            && let Some(d) = digest
        {
            let _ = p.set(digest_name(&d));
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
    let Ok(params) = OSSLParam::try_from(params) else {
        return 1;
    };

    for p in params {
        if let Some(key) = p.get_key() {
            eprintln!(
                "[ossl_hsm] signature_set_ctx_params: param={}",
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
