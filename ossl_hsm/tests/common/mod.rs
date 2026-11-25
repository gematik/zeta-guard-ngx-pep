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

//! Shared helpers: OSSL_STORE access through the provider and an in-process hsm_sim.

#![allow(dead_code)]

use anyhow::{Context, Result, ensure};
use foreign_types_shared::ForeignType;
use tonic::transport::ServerTlsConfig;

// OSSL_STORE API — not in openssl-sys, declare the subset we need.
#[allow(non_camel_case_types)]
mod ossl_store {
    use std::ffi::{c_char, c_int, c_void};

    pub const OSSL_STORE_INFO_PKEY: c_int = 4;

    unsafe extern "C" {
        pub fn OSSL_PROVIDER_available(libctx: *mut c_void, name: *const c_char) -> c_int;
    }

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
        pub fn OSSL_STORE_eof(ctx: *mut OSSL_STORE_CTX) -> c_int;
        pub fn OSSL_STORE_close(ctx: *mut OSSL_STORE_CTX) -> c_int;

        pub fn OSSL_STORE_INFO_get_type(info: *const OSSL_STORE_INFO) -> c_int;
        pub fn OSSL_STORE_INFO_get1_PKEY(
            info: *const OSSL_STORE_INFO,
        ) -> *mut openssl_sys::EVP_PKEY;
        pub fn OSSL_STORE_INFO_free(info: *mut OSSL_STORE_INFO);
    }
}

/// Open an `hsm:` store URI via OpenSSL's OSSL_STORE API and return the EVP_PKEY.
///
/// This exercises the full provider call chain:
///   OSSL_STORE_open → store_open (parse URI)
///   OSSL_STORE_load → store_load → keymgmt_load (create KeyHandle)
///   OSSL_STORE_INFO_get1_PKEY → keymgmt_has, keymgmt_get_params
pub fn store_load_pkey(uri: &str) -> Result<openssl::pkey::PKey<openssl::pkey::Private>> {
    use std::ffi::CString;

    let c_uri = CString::new(uri).context("CString")?;

    unsafe {
        let ctx = ossl_store::OSSL_STORE_open(
            c_uri.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
        );
        ensure!(!ctx.is_null(), "OSSL_STORE_open({uri}) returned NULL");

        // Load the first (and only) object
        let info = ossl_store::OSSL_STORE_load(ctx);
        if info.is_null() {
            ossl_store::OSSL_STORE_close(ctx);
            anyhow::bail!("OSSL_STORE_load returned NULL for {uri}");
        }

        let info_type = ossl_store::OSSL_STORE_INFO_get_type(info);
        ensure!(
            info_type == ossl_store::OSSL_STORE_INFO_PKEY,
            "expected PKEY (type {}), got type {info_type}",
            ossl_store::OSSL_STORE_INFO_PKEY
        );

        let evp_pkey = ossl_store::OSSL_STORE_INFO_get1_PKEY(info);
        ensure!(
            !evp_pkey.is_null(),
            "OSSL_STORE_INFO_get1_PKEY returned NULL"
        );

        // Should be at EOF now (single object)
        ensure!(
            ossl_store::OSSL_STORE_eof(ctx) == 1,
            "expected EOF after loading single key"
        );

        ossl_store::OSSL_STORE_INFO_free(info);
        ossl_store::OSSL_STORE_close(ctx);

        // Wrap in openssl crate's PKey (get1_ incremented refcount, from_ptr takes ownership)
        Ok(openssl::pkey::PKey::from_ptr(evp_pkey))
    }
}

/// Whether OpenSSL has loaded the provider and its init succeeded. Without
/// that, key operations fail for reasons unrelated to what a test is about.
pub fn provider_loaded() -> bool {
    unsafe { ossl_store::OSSL_PROVIDER_available(std::ptr::null_mut(), c"ossl_hsm".as_ptr()) == 1 }
}

/// Serve hsm_sim on `listener`, with TLS if configured.
pub fn spawn_hsm_sim(listener: tokio::net::TcpListener, tls: Option<ServerTlsConfig>) {
    let keys_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../hsm_sim/keys");
    let ca = std::sync::Arc::new(hsm_sim::CertAuthority::load(&keys_dir).expect("load CA"));
    let cache_dir = tempfile::tempdir().unwrap().keep();

    let mut server = tonic::transport::Server::builder();
    if let Some(tls) = tls {
        server = server.tls_config(tls).expect("server tls config");
    }

    tokio::spawn(async move {
        let service = hsm_sim::HsmProxyServiceImpl {
            ca: Some(ca),
            cache: hsm_sim::CacheDir::new(cache_dir),
        };
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        server
            .add_service(
                hsm_sim::proto::hsm_proxy_service_server::HsmProxyServiceServer::new(service),
            )
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
}
