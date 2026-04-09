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
use tonic::transport::Server;

use hsm_sim::proto::hsm_proxy_service_server::HsmProxyServiceServer;
use hsm_sim::{CacheDir, CertAuthority, HsmProxyServiceImpl};

#[derive(Parser)]
#[command(name = "hsm_sim", about = "HSM Simulator")]
struct Cli {
    /// Directory containing ca.key + ca.crt, also used as cache for derived keys/certs.
    #[arg(long, env = "HSM_SIM_KEYS", default_value = "keys")]
    keys_dir: PathBuf,

    /// gRPC listen address
    #[arg(long, default_value = "[::1]:50051")]
    listen: String,
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
    eprintln!("[hsm_sim] Listening on {}", addr);

    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(hsm_sim::proto::FILE_DESCRIPTOR_SET)
        .build_v1()?;

    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<HsmProxyServiceServer<HsmProxyServiceImpl>>()
        .await;

    Server::builder()
        .add_service(health_service)
        .add_service(reflection)
        .add_service(HsmProxyServiceServer::new(service))
        .serve_with_shutdown(addr, async {
            tokio::signal::ctrl_c().await.ok();
            eprintln!("[hsm_sim] Shutting down (2s grace period)");
            // Give in-flight RPCs time to finish, then exit even if clients
            // (e.g. k8s health probes) keep connections open.
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        })
        .await?;

    Ok(())
}
