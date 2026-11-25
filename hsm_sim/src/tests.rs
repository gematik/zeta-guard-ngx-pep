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

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, SubjectAlternativeName};
use openssl::x509::{X509, X509NameBuilder};
use tokio::net::TcpListener;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity, Server, ServerTlsConfig};

use super::proto::hsm_proxy_service_client::HsmProxyServiceClient;
use super::proto::hsm_proxy_service_server::HsmProxyServiceServer;
use super::{CacheDir, CertAuthority, HsmProxyServiceImpl};

/// Bind `addr` and serve the simulator on it in a background task.
async fn spawn_server(addr: &str, tls: Option<ServerTlsConfig>) -> SocketAddr {
    let cache_dir = tempfile::tempdir().unwrap();

    let keys_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("keys");
    let ca = Arc::new(CertAuthority::load(&keys_dir).expect("failed to load CA"));

    let listener = TcpListener::bind(addr).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let cache_path = cache_dir.keep();
    tokio::spawn(async move {
        let service = HsmProxyServiceImpl {
            ca: Some(ca),
            cache: CacheDir::new(cache_path),
        };

        let (health_reporter, health_service) = tonic_health::server::health_reporter();
        health_reporter
            .set_serving::<HsmProxyServiceServer<HsmProxyServiceImpl>>()
            .await;

        let mut builder = Server::builder();
        if let Some(tls) = tls {
            builder = builder.tls_config(tls).expect("tls config");
        }
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        builder
            .add_service(health_service)
            .add_service(HsmProxyServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    addr
}

/// Spin up the gRPC server with CA and standard health service, return a channel.
pub async fn start_server(addr: &str) -> Channel {
    let addr = spawn_server(addr, None).await;

    let url = format!("http://{}:{}", addr.ip(), addr.port());
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Ok(channel) = Channel::from_shared(url.clone()).unwrap().connect().await {
                return channel;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("server did not become ready")
}

/// Like [`start_server`], but TLS-only and demanding a client certificate
/// from `pki`. Returns the bound address once it accepts connections.
pub async fn start_mtls_server(addr: &str, pki: &TestPki) -> SocketAddr {
    let addr = spawn_server(addr, Some(pki.server_tls_config())).await;

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while tokio::net::TcpStream::connect(addr).await.is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("server did not become ready");
    addr
}

/// Throwaway CA with a server certificate for `localhost`/loopback and a
/// client certificate, all PEM.
pub struct TestPki {
    pub ca_cert: Vec<u8>,
    pub server_cert: Vec<u8>,
    pub server_key: Vec<u8>,
    pub client_cert: Vec<u8>,
    pub client_key: Vec<u8>,
}

enum CertKind<'a> {
    Ca,
    Server {
        ca: &'a X509,
        ca_key: &'a PKey<Private>,
    },
    Client {
        ca: &'a X509,
        ca_key: &'a PKey<Private>,
    },
}

fn new_key() -> Result<PKey<Private>> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    Ok(PKey::from_ec_key(EcKey::generate(&group)?)?)
}

fn new_cert(cn: &str, key: &PKey<Private>, kind: CertKind) -> Result<X509> {
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_nid(Nid::COMMONNAME, cn)?;
    let name = name.build();

    let mut serial = BigNum::new()?;
    serial.rand(127, MsbOption::MAYBE_ZERO, false)?;

    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_serial_number(serial.to_asn1_integer()?.as_ref())?;
    builder.set_subject_name(&name)?;
    builder.set_pubkey(key)?;
    builder.set_not_before(Asn1Time::from_unix(0)?.as_ref())?;
    builder.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;
    match kind {
        CertKind::Ca => {
            builder.set_issuer_name(&name)?;
            builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
            builder.sign(key, MessageDigest::sha256())?;
        }
        CertKind::Server { ca, ca_key } => {
            builder.set_issuer_name(ca.subject_name())?;
            let san = SubjectAlternativeName::new()
                .dns("localhost")
                .ip("127.0.0.1")
                .ip("::1")
                .build(&builder.x509v3_context(Some(ca), None))?;
            builder.append_extension(san)?;
            builder.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;
            builder.sign(ca_key, MessageDigest::sha256())?;
        }
        CertKind::Client { ca, ca_key } => {
            builder.set_issuer_name(ca.subject_name())?;
            builder.append_extension(ExtendedKeyUsage::new().client_auth().build()?)?;
            builder.sign(ca_key, MessageDigest::sha256())?;
        }
    }
    Ok(builder.build())
}

impl TestPki {
    pub fn generate() -> Result<Self> {
        let ca_key = new_key()?;
        let ca = new_cert("hsm_sim test CA", &ca_key, CertKind::Ca)?;
        let issuer = (&ca, &ca_key);

        let server_key = new_key()?;
        let server = new_cert(
            "localhost",
            &server_key,
            CertKind::Server {
                ca: issuer.0,
                ca_key: issuer.1,
            },
        )?;
        let client_key = new_key()?;
        let client = new_cert(
            "hsm_sim test client",
            &client_key,
            CertKind::Client {
                ca: issuer.0,
                ca_key: issuer.1,
            },
        )?;

        Ok(Self {
            ca_cert: ca.to_pem()?,
            server_cert: server.to_pem()?,
            server_key: server_key.private_key_to_pem_pkcs8()?,
            client_cert: client.to_pem()?,
            client_key: client_key.private_key_to_pem_pkcs8()?,
        })
    }

    /// Server side: TLS with this PKI's server certificate, client certificate required.
    pub fn server_tls_config(&self) -> ServerTlsConfig {
        ServerTlsConfig::new()
            .identity(Identity::from_pem(&self.server_cert, &self.server_key))
            .client_ca_root(Certificate::from_pem(&self.ca_cert))
    }

    /// Client side: trust this PKI's CA, optionally present its client certificate.
    pub fn client_tls_config(&self, with_client_cert: bool) -> ClientTlsConfig {
        let tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(&self.ca_cert));
        if with_client_cert {
            tls.identity(Identity::from_pem(&self.client_cert, &self.client_key))
        } else {
            tls
        }
    }

    /// Connect to a server started with [`start_mtls_server`].
    pub async fn connect(&self, addr: SocketAddr) -> Result<Channel> {
        Ok(Channel::from_shared(format!("https://{addr}"))?
            .tls_config(self.client_tls_config(true))?
            .connect()
            .await?)
    }
}

/// Convenience: start server on random port and return an HsmProxyService client.
pub async fn hsm_client() -> HsmProxyServiceClient<Channel> {
    HsmProxyServiceClient::new(start_server("127.0.0.1:0").await)
}
