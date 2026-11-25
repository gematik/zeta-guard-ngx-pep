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

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::signal::unix::SignalKind;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use hsm_sim::proto::hsm_proxy_service_server::HsmProxyServiceServer;
use hsm_sim::{CacheDir, CertAuthority, HsmProxyServiceImpl};

#[derive(Parser)]
#[command(name = "hsm_sim", about = "HSM Simulator")]
struct Cli {
    /// Directory containing ca.key + ca.crt, also used as cache for derived keys/certs.
    #[arg(long, env = "HSM_SIM_KEYS", default_value = "keys")]
    keys_dir: PathBuf,

    /// gRPC listen address; serves TLS if --tls-cert is given, plaintext otherwise
    #[arg(long, default_value = "[::1]:50051")]
    listen: String,

    /// PEM file with the server certificate (chain); enables TLS on --listen
    #[arg(long, env = "HSM_SIM_TLS_CERT", requires = "tls_key")]
    tls_cert: Option<PathBuf>,

    /// PEM file with the server certificate's private key
    #[arg(long, env = "HSM_SIM_TLS_KEY", requires = "tls_cert")]
    tls_key: Option<PathBuf>,

    /// PEM file with the CA(s) client certificates must chain to; makes a client
    /// certificate mandatory on --listen (mTLS)
    #[arg(long, env = "HSM_SIM_TLS_CLIENT_CA", requires = "tls_cert")]
    tls_client_ca: Option<PathBuf>,

    /// Additional plaintext gRPC listen address next to the TLS one, for clients
    /// without TLS support
    #[arg(long, env = "HSM_SIM_PLAINTEXT_LISTEN", requires = "tls_cert")]
    plaintext_listen: Option<String>,
}

impl Cli {
    fn tls_config(&self) -> Result<Option<ServerTlsConfig>, Box<dyn std::error::Error>> {
        let (Some(cert), Some(key)) = (&self.tls_cert, &self.tls_key) else {
            return Ok(None);
        };
        let read =
            |path: &PathBuf| std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()));
        let mut tls = ServerTlsConfig::new().identity(Identity::from_pem(read(cert)?, read(key)?));
        if let Some(client_ca) = &self.tls_client_ca {
            tls = tls.client_ca_root(Certificate::from_pem(read(client_ca)?));
        }
        Ok(Some(tls))
    }
}

async fn termination_signal() -> std::io::Result<()> {
    let mut term = tokio::signal::unix::signal(SignalKind::terminate())?;
    tokio::select! {
        r = tokio::signal::ctrl_c() => r,
        _ = term.recv() => Ok(()),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let keys_dir = if cli.keys_dir.is_absolute() {
        cli.keys_dir.clone()
    } else {
        std::env::current_dir()?.join(&cli.keys_dir)
    };

    let ca = match CertAuthority::load(&keys_dir) {
        Ok(ca) => {
            eprintln!("[hsm_sim] Loaded CA from {}", keys_dir.display());
            Some(Arc::new(ca))
        }
        Err(e) => {
            eprintln!(
                "[hsm_sim] Warning: no CA loaded from {}: {e} (GetCertificate will be unavailable)",
                keys_dir.display()
            );
            None
        }
    };

    let service = HsmProxyServiceImpl {
        ca,
        cache: CacheDir::new(keys_dir),
    };

    let addr = cli.listen.parse()?;
    let plaintext_addr = cli
        .plaintext_listen
        .as_deref()
        .map(str::parse)
        .transpose()?;
    let tls = cli.tls_config()?;
    eprintln!(
        "[hsm_sim] Listening on {addr} ({})",
        match (&tls, &cli.tls_client_ca) {
            (None, _) => "plaintext",
            (Some(_), None) => "TLS",
            (Some(_), Some(_)) => "TLS, client certificate required",
        }
    );
    if let Some(plaintext_addr) = plaintext_addr {
        eprintln!("[hsm_sim] Listening on {plaintext_addr} (plaintext)");
    }

    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(hsm_sim::proto::FILE_DESCRIPTOR_SET)
        .build_v1()?;

    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<HsmProxyServiceServer<HsmProxyServiceImpl>>()
        .await;

    let hsm_service = HsmProxyServiceServer::new(service);
    let serve = |mut builder: Server, addr| {
        builder
            .add_service(health_service.clone())
            .add_service(reflection.clone())
            .add_service(hsm_service.clone())
            .serve_with_shutdown(addr, async {
                termination_signal().await.ok();
                eprintln!("[hsm_sim] shutting down…");
            })
    };

    let builder = match tls {
        Some(tls) => Server::builder().tls_config(tls)?,
        None => Server::builder(),
    };
    let main_listener = serve(builder, addr);
    let plaintext_listener = async {
        match plaintext_addr {
            Some(addr) => serve(Server::builder(), addr).await,
            None => Ok(()),
        }
    };
    let server = async { tokio::try_join!(main_listener, plaintext_listener).map(|_| ()) };

    // serve_with_shutdown can hang due to ”half-dead” clients, e.g. when ossl_hsm connected
    // pre-fork, and didn't reconnect yet.
    tokio::select! {
        res = server => res?,
        _ = async {
            termination_signal().await.ok();
            // allow in-flight rpcs to finish. exits promptly when server future completes (select!)
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        } => {}
    }

    Ok(())
}
