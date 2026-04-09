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

use std::sync::Arc;

use tokio::net::TcpListener;
use tonic::transport::{Channel, Server};

use super::proto::hsm_proxy_service_client::HsmProxyServiceClient;
use super::proto::hsm_proxy_service_server::HsmProxyServiceServer;
use super::{CacheDir, CertAuthority, HsmProxyServiceImpl};

/// Spin up the gRPC server with CA and standard health service, return a channel.
pub async fn start_server(addr: &str) -> Channel {
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

        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(health_service)
            .add_service(HsmProxyServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

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

/// Convenience: start server on random port and return an HsmProxyService client.
pub async fn hsm_client() -> HsmProxyServiceClient<Channel> {
    HsmProxyServiceClient::new(start_server("127.1.33.7:0").await)
}
