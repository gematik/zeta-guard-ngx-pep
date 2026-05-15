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

use anyhow::{Context, Result, ensure};
use foreign_types::ForeignType;

// OSSL_STORE API — not in openssl-sys, declare the subset we need.
#[allow(non_camel_case_types)]
mod ffi {
    use std::ffi::{c_char, c_int, c_void};

    pub const OSSL_STORE_INFO_PKEY: c_int = 4;

    pub enum OSSL_STORE_CTX {}
    pub enum OSSL_STORE_INFO {}

    unsafe extern "C" {
        pub fn OSSL_STORE_open(
            uri: *const c_char,
            ui_method: *const c_void,
            ui_data: *mut c_void,
            post_process: *const c_void,
            post_process_data: *mut c_void,
        ) -> *mut OSSL_STORE_CTX;

        pub fn OSSL_STORE_load(ctx: *mut OSSL_STORE_CTX) -> *mut OSSL_STORE_INFO;
        pub fn OSSL_STORE_close(ctx: *mut OSSL_STORE_CTX) -> c_int;

        pub fn OSSL_STORE_INFO_get_type(info: *const OSSL_STORE_INFO) -> c_int;
        pub fn OSSL_STORE_INFO_get1_PKEY(
            info: *const OSSL_STORE_INFO,
        ) -> *mut openssl_sys::EVP_PKEY;
        pub fn OSSL_STORE_INFO_free(info: *mut OSSL_STORE_INFO);
    }
}

/// Open an `hsm:` store URI via OpenSSL's OSSL_STORE API and return the EVP_PKEY.
pub fn load_pkey(uri: &str) -> Result<openssl::pkey::PKey<openssl::pkey::Private>> {
    use std::ffi::CString;

    let c_uri = CString::new(uri).context("CString")?;

    unsafe {
        let ctx = ffi::OSSL_STORE_open(
            c_uri.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
        );
        ensure!(!ctx.is_null(), "OSSL_STORE_open({uri}) returned NULL");

        let info = ffi::OSSL_STORE_load(ctx);
        if info.is_null() {
            ffi::OSSL_STORE_close(ctx);
            anyhow::bail!("OSSL_STORE_load returned NULL for {uri}");
        }

        let info_type = ffi::OSSL_STORE_INFO_get_type(info);
        ensure!(
            info_type == ffi::OSSL_STORE_INFO_PKEY,
            "expected PKEY (type {}), got type {info_type}",
            ffi::OSSL_STORE_INFO_PKEY
        );

        let evp_pkey = ffi::OSSL_STORE_INFO_get1_PKEY(info);
        ensure!(
            !evp_pkey.is_null(),
            "OSSL_STORE_INFO_get1_PKEY returned NULL"
        );

        ffi::OSSL_STORE_INFO_free(info);
        ffi::OSSL_STORE_close(ctx);

        // Wrap in openssl crate's PKey (get1_ incremented refcount, from_ptr takes ownership)
        Ok(openssl::pkey::PKey::from_ptr(evp_pkey))
    }
}
