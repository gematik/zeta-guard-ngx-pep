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

mod common;

use hsm_sim::proto::HealthCheckRequest;
use hsm_sim::proto::hsm_proxy_service_client::HsmProxyServiceClient;
use hsm_sim::tests::TestPki;
use tonic::transport::Channel;

async fn health_check(channel: Channel) -> Result<(), tonic::Status> {
    HsmProxyServiceClient::new(channel)
        .health_check(HealthCheckRequest {})
        .await
        .map(|_| ())
}

#[tokio::test]
async fn mtls_client_is_served() {
    let pki = TestPki::generate().unwrap();
    let addr = common::start_mtls_server("127.0.0.1:0", &pki).await;

    let channel = pki.connect(addr).await.expect("connect");
    health_check(channel).await.expect("health check");
}

#[tokio::test]
async fn client_without_certificate_is_refused() {
    let pki = TestPki::generate().unwrap();
    let addr = common::start_mtls_server("127.0.0.1:0", &pki).await;

    // TLS 1.3: the server's rejection may only surface on the first request
    let served = async {
        let channel = Channel::from_shared(format!("https://{addr}"))
            .unwrap()
            .tls_config(pki.client_tls_config(false))
            .unwrap()
            .connect()
            .await
            .ok()?;
        health_check(channel).await.ok()
    };
    assert!(served.await.is_none(), "anonymous client was served");
}

#[tokio::test]
async fn client_certificate_from_other_ca_is_refused() {
    let pki = TestPki::generate().unwrap();
    let mut foreign = TestPki::generate().unwrap();
    foreign.ca_cert = pki.ca_cert.clone();
    let addr = common::start_mtls_server("127.0.0.1:0", &pki).await;

    let served = async {
        let channel = foreign.connect(addr).await.ok()?;
        health_check(channel).await.ok()
    };
    assert!(served.await.is_none(), "foreign client was served");
}

#[tokio::test]
async fn plaintext_client_is_refused_by_tls_listener() {
    let pki = TestPki::generate().unwrap();
    let addr = common::start_mtls_server("127.0.0.1:0", &pki).await;

    let served = async {
        let channel = Channel::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .ok()?;
        health_check(channel).await.ok()
    };
    assert!(served.await.is_none(), "plaintext client was served");
}

fn free_addr() -> std::net::SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn wait_for(addr: std::net::SocketAddr) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while tokio::net::TcpStream::connect(addr).await.is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("hsm_sim did not start listening");
}

/// The binary with `--tls-*` and `--plaintext-listen`: mTLS on one port,
/// plaintext on the other.
#[tokio::test]
async fn binary_serves_mtls_and_plaintext_side_by_side() {
    let pki = TestPki::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let file = |name: &str, pem: &[u8]| {
        let path = dir.path().join(name);
        std::fs::write(&path, pem).unwrap();
        path
    };
    let tls_addr = free_addr();
    let plaintext_addr = free_addr();

    let mut hsm_sim = tokio::process::Command::new(env!("CARGO_BIN_EXE_hsm_sim"))
        .arg("--keys-dir")
        .arg(dir.path())
        .args(["--listen", &tls_addr.to_string()])
        .args(["--plaintext-listen", &plaintext_addr.to_string()])
        .arg("--tls-cert")
        .arg(file("server.pem", &pki.server_cert))
        .arg("--tls-key")
        .arg(file("server.key", &pki.server_key))
        .arg("--tls-client-ca")
        .arg(file("ca.pem", &pki.ca_cert))
        .kill_on_drop(true)
        .spawn()
        .expect("spawn hsm_sim");
    wait_for(tls_addr).await;
    wait_for(plaintext_addr).await;

    let mtls = async {
        let channel = pki.connect(tls_addr).await.ok()?;
        health_check(channel).await.ok()
    }
    .await;
    let anonymous = async {
        let channel = Channel::from_shared(format!("https://{tls_addr}"))
            .unwrap()
            .tls_config(pki.client_tls_config(false))
            .unwrap()
            .connect()
            .await
            .ok()?;
        health_check(channel).await.ok()
    }
    .await;
    let plaintext = async {
        let channel = Channel::from_shared(format!("http://{plaintext_addr}"))
            .unwrap()
            .connect()
            .await
            .ok()?;
        health_check(channel).await.ok()
    }
    .await;
    hsm_sim.kill().await.ok();

    assert!(mtls.is_some(), "mTLS client not served on the TLS listener");
    assert!(
        anonymous.is_none(),
        "anonymous client served on the TLS listener"
    );
    assert!(
        plaintext.is_some(),
        "plaintext client not served on the plaintext listener"
    );
}
