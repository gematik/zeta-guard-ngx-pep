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

//! Integration tests for the ossl_hsm OpenSSL provider.
//!
//! These tests exercise the provider through OpenSSL's C API (OSSL_STORE, etc.)
//! with a real hsm_sim instance. The provider .so is loaded by OpenSSL via
//! OPENSSL_CONF (set by .envrc locally, misc/cargo-build in CI).
//!
//! Prerequisites:
//! - OPENSSL_CONF pointing to an openssl.cnf that loads libossl_hsm.so
//! - libossl_hsm.so built (nextest setup script handles this)

use anyhow::{Context, Result, ensure};
use foreign_types_shared::ForeignType;

// OSSL_STORE API — not in openssl-sys, declare the subset we need.
#[allow(non_camel_case_types)]
mod ossl_store {
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
fn store_load_pkey(uri: &str) -> Result<openssl::pkey::PKey<openssl::pkey::Private>> {
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

/// Start hsm_sim, set HSM_PROXY_ADDR, return a gRPC client for verification.
async fn setup()
-> hsm_sim::proto::hsm_proxy_service_client::HsmProxyServiceClient<tonic::transport::Channel> {
    // Bind to random port, but capture the actual address
    let listener = tokio::net::TcpListener::bind("127.1.33.7:0").await.unwrap();
    let bound_addr = listener.local_addr().unwrap();
    let hsm_url = format!("http://{}:{}", bound_addr.ip(), bound_addr.port());

    // Set HSM_PROXY_ADDR before any OpenSSL call triggers provider init
    unsafe { std::env::set_var("HSM_PROXY_ADDR", &hsm_url) };

    // Start the server on the already-bound listener
    let keys_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../hsm_sim/keys");
    let ca = std::sync::Arc::new(hsm_sim::CertAuthority::load(&keys_dir).expect("load CA"));
    let cache_dir = tempfile::tempdir().unwrap().keep();

    tokio::spawn(async move {
        let service = hsm_sim::HsmProxyServiceImpl {
            ca: Some(ca),
            cache: hsm_sim::CacheDir::new(cache_dir),
        };
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        tonic::transport::Server::builder()
            .add_service(
                hsm_sim::proto::hsm_proxy_service_server::HsmProxyServiceServer::new(service),
            )
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    // Wait for hsm_sim to be ready
    let channel = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Ok(ch) = tonic::transport::Channel::from_shared(hsm_url.clone())
                .unwrap()
                .connect()
                .await
            {
                return ch;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("hsm_sim did not become");

    hsm_sim::proto::hsm_proxy_service_client::HsmProxyServiceClient::new(channel)
}

/// Verify OSSL_STORE_open("hsm:<key_id>") loads a key via the provider,
/// and that the loaded key's public component matches what hsm_sim derives.
#[tokio::test(flavor = "multi_thread")]
async fn store_open_loads_ec_key() -> Result<()> {
    let mut hsm_client = setup().await;
    let key_id = "provider-test.p256";

    // Load the key through OpenSSL's STORE API → exercises our provider
    let pkey = store_load_pkey(&format!("hsm:{key_id}"))?;

    // Verify it's an EC key (use id() instead of ec_key() which triggers a
    // full export including private key — our provider correctly refuses that)
    ensure!(
        pkey.id() == openssl::pkey::Id::EC,
        "expected EC key, got {:?}",
        pkey.id()
    );

    // keymgmt_export is called with selection=6 (public only) for this path,
    // which our provider handles. Fetch the same key from hsm_sim to compare.
    let pub_resp = hsm_client
        .get_public_key(hsm_sim::proto::GetPublicKeyRequest {
            key_id: key_id.to_string(),
        })
        .await?
        .into_inner();

    // Compare via keymgmt_export: public_key_to_der triggers export(selection=6)
    let provider_pubkey_der = pkey.public_key_to_der().context("public_key_to_der")?;
    ensure!(
        provider_pubkey_der == pub_resp.public_key_der,
        "provider key SPKI does not match hsm_sim key for {key_id}"
    );

    Ok(())
}
