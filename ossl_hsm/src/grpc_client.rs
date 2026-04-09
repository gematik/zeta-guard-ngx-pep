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

//! gRPC client for the HSM Proxy Service.
//!
//! Provides a blocking interface around the async tonic client,
//! suitable for use from OpenSSL provider callbacks (which are synchronous C FFI).
//!
//! Uses a current-thread tokio runtime (no background threads) so it survives
//! nginx's fork(). Detects fork via PID check and reconnects automatically.

use std::net::ToSocketAddrs;
use std::sync::{Mutex, OnceLock};

use anyhow::Context;
use tonic::transport::{Channel, Uri};

pub mod proto {
    tonic::include_proto!("gematik.zetaguard.hsmproxy.v1");
}

use proto::hsm_proxy_service_client::HsmProxyServiceClient;
pub use proto::{DigestAlgorithm, GetPublicKeyRequest, SignRequest};

/// Default server address (can be overridden via HSM_PROXY_ADDR env var)
const DEFAULT_ADDR: &str = "http://[::1]:50051";

/// We need to resolve HSM_PROXY_ADDR eagerly because glibc's resolver is not fork-safe.
fn resolve_uri(uri: &str) -> anyhow::Result<Uri> {
    let parsed: Uri = uri.parse()?;
    let host = parsed.host().context("no host")?;
    let port = parsed.port_u16().unwrap_or(50051);

    let addr = format!("{host}:{port}")
        .to_socket_addrs()?
        .next()
        .context("DNS resolution failed")?;

    let ip = addr.ip();
    let authority = if ip.is_ipv6() {
        format!("[{ip}]:{}", addr.port())
    } else {
        format!("{ip}:{}", addr.port())
    };
    let resolved = format!("http://{authority}").parse()?;
    Ok(resolved)
}

struct RuntimeState {
    pid: u32,
    runtime: tokio::runtime::Runtime,
    client: HsmProxyServiceClient<Channel>,
}

impl RuntimeState {
    pub fn connect(uri: Uri) -> anyhow::Result<Self> {
        let pid = std::process::id();
        eprintln!(
            "[ossl_hsm] Connecting to gRPC server at {} (pid={})",
            uri, pid
        );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("runtime")?;

        let channel = runtime
            .block_on(
                Channel::builder(uri)
                    .connect_timeout(std::time::Duration::from_secs(5))
                    .connect(),
            )
            .context("connect")?;
        let client = HsmProxyServiceClient::new(channel);
        Ok(RuntimeState {
            pid,
            runtime,
            client,
        })
    }
}

struct ClientState {
    uri: Uri,
    rt: Option<RuntimeState>,
}

static STATE: OnceLock<Mutex<ClientState>> = OnceLock::new();

fn client_state() -> Result<&'static Mutex<ClientState>, &'static str> {
    STATE.get().ok_or("STATE uninit")
}

pub fn server_uri() -> Uri {
    let state = client_state().expect("client_state").lock().expect("lock");
    state.uri.clone()
}

/// Must be called during provider init, before nginx worker fork()
/// - Stores HSM_PROXY_ADDR in a static because the env gets lost fork
/// - Stores the main pid to detect if we have to reconnect after fork
pub fn init() {
    let _ = STATE.get_or_init(|| {
        let addr = std::env::var("HSM_PROXY_ADDR").unwrap_or_else(|_| DEFAULT_ADDR.to_string());
        let uri = resolve_uri(&addr)
            .map_err(|e| format!("Could not resolve HSM_PROXY_ADDR={addr}: {e}"))
            .unwrap();

        let state = ClientState { uri, rt: None };
        Mutex::new(state)
    });
}

/// Execute a gRPC call, reconnecting if needed (e.g. after nginx fork).
fn with_client<F, T>(f: F) -> Result<T, String>
where
    F: FnOnce(&mut RuntimeState) -> Result<T, String>,
{
    let mut state = client_state()?
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?;

    let current_pid = std::process::id();
    let need_reconnect = state.rt.as_ref().is_none_or(|rt| rt.pid != current_pid);

    if need_reconnect {
        let rt = RuntimeState::connect(state.uri.clone())
            .map_err(|e| format!("during reconnect: {e}"))?;
        state.rt.replace(rt);
    }

    let state = &mut *state;
    f(state.rt.as_mut().unwrap())
}

/// Sign data via the gRPC server. Returns IEEE P1363 signature bytes.
pub fn sign(key_id: &str, digest: &[u8]) -> Result<Vec<u8>, String> {
    let request = SignRequest {
        key_id: key_id.to_string(),
        data: digest.to_vec(),
        algorithm: DigestAlgorithm::None as i32, // provider already hashed
    };

    with_client(|rt| {
        let response = rt
            .runtime
            .block_on(rt.client.sign(request))
            .map_err(|e| format!("gRPC Sign error: {}", e))?;
        Ok(response.into_inner().signature)
    })
}

/// Get the public key PEM via the gRPC server.
pub fn get_public_key(key_id: &str) -> Result<PublicKeyInfo, String> {
    let request = GetPublicKeyRequest {
        key_id: key_id.to_string(),
    };

    with_client(|rt| {
        let response = rt
            .runtime
            .block_on(rt.client.get_public_key(request))
            .map_err(|e| format!("gRPC GetPublicKey error: {}", e))?;
        let resp = response.into_inner();
        Ok(PublicKeyInfo {
            pem: resp.public_key_pem,
            der: resp.public_key_der,
        })
    })
}

pub struct PublicKeyInfo {
    pub pem: String,
    pub der: Vec<u8>,
}
