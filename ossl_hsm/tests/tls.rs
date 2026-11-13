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

//! Transport security of the provider's connection to the HSM proxy.
//!
//! The provider reads its environment once per process, so each test needs a
//! process of its own (nextest's default).

mod common;

use anyhow::{Context, Result, ensure};
use common::store_load_pkey;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
};
use tonic::transport::{Certificate, Identity, ServerTlsConfig};

const KEY_ID: &str = "tls-test.p256";

// Certificates are generated without OpenSSL: the first OpenSSL call loads the
// provider, which reads its environment right then.
struct Ca {
    params: CertificateParams,
    key: KeyPair,
}

impl Ca {
    fn new() -> Result<Self> {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "test CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        Ok(Self {
            params,
            key: KeyPair::generate()?,
        })
    }

    fn server_tls(&self, dns_name: &str) -> Result<ServerTlsConfig> {
        let key = KeyPair::generate()?;
        let cert = CertificateParams::new(vec![dns_name.to_string()])?
            .signed_by(&key, &Issuer::from_params(&self.params, &self.key))?;
        let identity = Identity::from_pem(cert.pem(), key.serialize_pem());
        Ok(ServerTlsConfig::new().identity(identity))
    }

    fn pem(&self) -> Result<String> {
        Ok(self.params.self_signed(&self.key)?.pem())
    }

    /// Write the CA certificate to a file and return its path.
    fn pem_file(&self) -> Result<std::path::PathBuf> {
        let path = tempfile::tempdir()?.keep().join("ca.pem");
        std::fs::write(&path, self.pem()?)?;
        Ok(path)
    }

    /// Issue a client certificate, point the provider at it.
    fn set_client_identity(&self) -> Result<()> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec!["pep".to_string()])?;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = params.signed_by(&key, &Issuer::from_params(&self.params, &self.key))?;

        let dir = tempfile::tempdir()?.keep();
        std::fs::write(dir.join("client.pem"), cert.pem())?;
        std::fs::write(dir.join("client.key"), key.serialize_pem())?;
        unsafe {
            std::env::set_var("HSM_PROXY_CLIENT_CERT", dir.join("client.pem"));
            std::env::set_var("HSM_PROXY_CLIENT_KEY", dir.join("client.key"));
        }
        Ok(())
    }
}

/// Start a TLS-only hsm_sim on `localhost` and point the provider at it.
async fn tls_proxy(tls: ServerTlsConfig, trusted_ca: Option<&Ca>) -> Result<()> {
    let listener = tokio::net::TcpListener::bind("localhost:0").await?;
    let port = listener.local_addr()?.port();

    // Set before any OpenSSL call (hsm_sim included) triggers provider init
    unsafe {
        std::env::set_var("HSM_PROXY_ADDR", format!("https://localhost:{port}"));
        match trusted_ca {
            Some(ca) => std::env::set_var("HSM_PROXY_CA", ca.pem_file()?),
            None => std::env::remove_var("HSM_PROXY_CA"),
        }
    }

    common::spawn_hsm_sim(listener, Some(tls));
    ensure!(common::provider_loaded(), "provider not loaded");
    Ok(())
}

/// Load the key and fetch its public part, which takes a `GetPublicKey` RPC.
fn public_key_via_provider() -> Result<Vec<u8>> {
    let pkey = store_load_pkey(&format!("hsm:{KEY_ID}"))?;
    pkey.public_key_to_der().context("public_key_to_der")
}

#[tokio::test(flavor = "multi_thread")]
async fn https_with_pinned_ca_connects() -> Result<()> {
    let ca = Ca::new()?;
    tls_proxy(ca.server_tls("localhost")?, Some(&ca)).await?;

    let der = public_key_via_provider()?;
    ensure!(!der.is_empty(), "empty public key");
    Ok(())
}

/// The downgrade of the original finding: `https://` configured, proxy serving
/// plaintext. Were the provider to talk plaintext, the sim would answer.
#[tokio::test(flavor = "multi_thread")]
async fn https_to_plaintext_proxy_is_refused() -> Result<()> {
    let listener = tokio::net::TcpListener::bind("localhost:0").await?;
    let port = listener.local_addr()?.port();
    unsafe {
        std::env::set_var("HSM_PROXY_ADDR", format!("https://localhost:{port}"));
        std::env::remove_var("HSM_PROXY_CA");
    }
    common::spawn_hsm_sim(listener, None);
    ensure!(common::provider_loaded(), "provider not loaded");

    ensure!(
        public_key_via_provider().is_err(),
        "https:// was served in plaintext"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_certificate_from_other_ca_is_refused() -> Result<()> {
    let ca = Ca::new()?;
    let other_ca = Ca::new()?;
    tls_proxy(ca.server_tls("localhost")?, Some(&other_ca)).await?;

    ensure!(
        public_key_via_provider().is_err(),
        "untrusted proxy accepted"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_certificate_unknown_to_system_roots_is_refused() -> Result<()> {
    let ca = Ca::new()?;
    tls_proxy(ca.server_tls("localhost")?, None).await?;

    ensure!(
        public_key_via_provider().is_err(),
        "untrusted proxy accepted"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_certificate_for_other_host_is_refused() -> Result<()> {
    let ca = Ca::new()?;
    tls_proxy(ca.server_tls("hsm.example")?, Some(&ca)).await?;

    ensure!(public_key_via_provider().is_err(), "wrong host accepted");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn client_certificate_is_presented() -> Result<()> {
    let ca = Ca::new()?;
    let client_ca = Ca::new()?;
    client_ca.set_client_identity()?;
    let tls = ca
        .server_tls("localhost")?
        .client_ca_root(Certificate::from_pem(client_ca.pem()?));
    tls_proxy(tls, Some(&ca)).await?;

    let der = public_key_via_provider()?;
    ensure!(!der.is_empty(), "empty public key");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_requiring_client_certificate_refuses_anonymous() -> Result<()> {
    let ca = Ca::new()?;
    let client_ca = Ca::new()?;
    let tls = ca
        .server_tls("localhost")?
        .client_ca_root(Certificate::from_pem(client_ca.pem()?));
    tls_proxy(tls, Some(&ca)).await?;

    ensure!(
        public_key_via_provider().is_err(),
        "anonymous client accepted"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn client_certificate_from_other_ca_is_refused() -> Result<()> {
    let ca = Ca::new()?;
    let client_ca = Ca::new()?;
    Ca::new()?.set_client_identity()?;
    let tls = ca
        .server_tls("localhost")?
        .client_ca_root(Certificate::from_pem(client_ca.pem()?));
    tls_proxy(tls, Some(&ca)).await?;

    ensure!(
        public_key_via_provider().is_err(),
        "foreign client accepted"
    );
    Ok(())
}

#[test]
fn client_certificate_without_key_fails_provider_init() {
    let cert = tempfile::NamedTempFile::new().unwrap();
    unsafe { std::env::set_var("HSM_PROXY_CLIENT_CERT", cert.path()) };

    assert!(store_load_pkey(&format!("hsm:{KEY_ID}")).is_err());
}

#[test]
fn plaintext_to_remote_proxy_fails_provider_init() {
    unsafe { std::env::set_var("HSM_PROXY_ADDR", "http://192.0.2.1:50051") };

    assert!(store_load_pkey(&format!("hsm:{KEY_ID}")).is_err());
}
