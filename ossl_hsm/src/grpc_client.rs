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

use std::net::{IpAddr, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, bail};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity, Uri};

pub mod proto {
    tonic::include_proto!("gematik.zetaguard.hsmproxy.v1");
}

use proto::hsm_proxy_service_client::HsmProxyServiceClient;
pub use proto::{DigestAlgorithm, GetPublicKeyRequest, SignRequest};

/// Default server address (can be overridden via HSM_PROXY_ADDR env var)
const DEFAULT_ADDR: &str = "http://[::1]:50051";

/// Where and how to reach the HSM proxy.
#[derive(Clone)]
struct Target {
    /// `<scheme>://<ip>:<port>`, see [`resolve`]
    uri: Uri,
    /// Carries the TLS configuration, trust anchors included, so that workers
    /// connect with exactly what was loaded before fork.
    endpoint: Endpoint,
    tls: bool,
}

/// Transport security for an endpoint: `Ok(true)` for TLS, `Ok(false)` for
/// plaintext. Plaintext is only accepted towards a loopback address, unless
/// explicitly allowed.
fn wants_tls(scheme: Option<&str>, ip: IpAddr, allow_plaintext: bool) -> anyhow::Result<bool> {
    match scheme {
        Some("https") => Ok(true),
        Some("http") | None if ip.is_loopback() || allow_plaintext => Ok(false),
        Some("http") | None => bail!(
            "plaintext connection to non-loopback address {ip} refused, use https:// \
             (or set HSM_PROXY_ALLOW_PLAINTEXT=1)"
        ),
        Some(other) => bail!("unsupported scheme {other:?}"),
    }
}

/// We need to resolve HSM_PROXY_ADDR eagerly because glibc's resolver is not fork-safe.
/// The configured host name is kept for certificate validation.
fn resolve(
    addr: &str,
    allow_plaintext: bool,
    ca: Option<Certificate>,
    identity: Option<Identity>,
) -> anyhow::Result<Target> {
    let parsed: Uri = addr.parse()?;
    let host = parsed.host().context("no host")?;
    let port = parsed.port_u16().unwrap_or(50051);

    let resolved = format!("{host}:{port}")
        .to_socket_addrs()?
        .next()
        .context("DNS resolution failed")?;

    let ip = resolved.ip();
    let authority = if ip.is_ipv6() {
        format!("[{ip}]:{}", resolved.port())
    } else {
        format!("{ip}:{}", resolved.port())
    };

    if wants_tls(parsed.scheme_str(), ip, allow_plaintext)? {
        let domain = host.trim_start_matches('[').trim_end_matches(']');
        let tls = ClientTlsConfig::new().domain_name(domain);
        let tls = match ca {
            Some(ca) => tls.ca_certificate(ca),
            None => tls.with_native_roots(),
        };
        let tls = match identity {
            Some(identity) => tls.identity(identity),
            None => tls,
        };
        let uri: Uri = format!("https://{authority}").parse()?;
        // requests keep naming the configured host, not the address it resolved to
        let origin: Uri = format!("https://{host}:{port}").parse()?;
        let endpoint = Channel::builder(uri.clone())
            .origin(origin)
            .tls_config(tls)
            .context("tls config")?;
        Ok(Target {
            uri,
            endpoint,
            tls: true,
        })
    } else {
        if ca.is_some() || identity.is_some() {
            bail!("HSM_PROXY_CA and a client certificate need https://");
        }
        let uri: Uri = format!("http://{authority}").parse()?;
        Ok(Target {
            endpoint: Channel::builder(uri.clone()),
            uri,
            tls: false,
        })
    }
}

struct RuntimeState {
    pid: u32,
    runtime: tokio::runtime::Runtime,
    client: HsmProxyServiceClient<Channel>,
}

impl RuntimeState {
    pub fn connect(target: Target) -> anyhow::Result<Self> {
        let pid = std::process::id();
        eprintln!(
            "[ossl_hsm] Connecting to gRPC server at {} (pid={})",
            target.uri, pid
        );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("runtime")?;

        let channel = runtime
            .block_on(
                target
                    .endpoint
                    .connect_timeout(std::time::Duration::from_secs(5))
                    // HTTP/2 keepalive: prevent idle connections from being silently
                    // dropped by iptables/load-balancers/conntrack/middleboxes …
                    .http2_keep_alive_interval(std::time::Duration::from_secs(30))
                    .keep_alive_timeout(std::time::Duration::from_secs(10))
                    .keep_alive_while_idle(true)
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
    target: Target,
    rt: Option<RuntimeState>,
}

static STATE: OnceLock<Mutex<ClientState>> = OnceLock::new();

fn client_state() -> Result<&'static Mutex<ClientState>, &'static str> {
    STATE.get().ok_or("STATE uninit")
}

/// Value of the environment variable `var`, if set.
fn env_var(var: &str) -> Result<Option<String>, String> {
    match std::env::var(var) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{var}: not valid UTF-8")),
    }
}

/// Contents of the file named by the environment variable `var`, if set.
fn read_env_file(var: &str) -> Result<Option<Vec<u8>>, String> {
    match std::env::var_os(var) {
        Some(path) => std::fs::read(&path)
            .map(Some)
            .map_err(|e| format!("{var}={}: {e}", path.to_string_lossy())),
        None => Ok(None),
    }
}

/// Must be called during provider init, before nginx worker fork()
/// - Stores HSM_PROXY_ADDR in a static because the env gets lost fork
/// - Stores the main pid to detect if we have to reconnect after fork
///
/// Environment:
/// - `HSM_PROXY_ADDR`: `https://host[:port]`; `http://` only for loopback
/// - `HSM_PROXY_CA`: PEM file with the CA(s) to trust for the proxy's
///   certificate instead of the system trust store
/// - `HSM_PROXY_CLIENT_CERT`, `HSM_PROXY_CLIENT_KEY`: PEM files with the
///   certificate (chain) and private key to authenticate with (mTLS)
/// - `HSM_PROXY_ALLOW_PLAINTEXT=1`: accept `http://` to a non-loopback address
pub fn init() -> Result<(), String> {
    if STATE.get().is_some() {
        return Ok(());
    }

    let addr = env_var("HSM_PROXY_ADDR")?.unwrap_or_else(|| DEFAULT_ADDR.to_string());
    let allow_plaintext = env_var("HSM_PROXY_ALLOW_PLAINTEXT")?.is_some_and(|v| v == "1");
    let ca = read_env_file("HSM_PROXY_CA")?.map(Certificate::from_pem);
    let identity = match (
        read_env_file("HSM_PROXY_CLIENT_CERT")?,
        read_env_file("HSM_PROXY_CLIENT_KEY")?,
    ) {
        (Some(cert), Some(key)) => Some(Identity::from_pem(cert, key)),
        (None, None) => None,
        _ => {
            return Err(
                "HSM_PROXY_CLIENT_CERT and HSM_PROXY_CLIENT_KEY must be set together".to_string(),
            );
        }
    };

    let target = resolve(&addr, allow_plaintext, ca, identity)
        .map_err(|e| format!("HSM_PROXY_ADDR={addr}: {e:#}"))?;
    if !target.tls && allow_plaintext {
        eprintln!(
            "[ossl_hsm] WARNING: HSM_PROXY_ALLOW_PLAINTEXT=1, signing requests to {} are \
             neither encrypted nor authenticated",
            target.uri
        );
    }

    let _ = STATE.set(Mutex::new(ClientState { target, rt: None }));
    Ok(())
}

/// Execute a gRPC call, reconnecting if needed.
///
/// Reconnects happen on:
/// - first call (cold cache),
/// - PID mismatch (post-fork in nginx workers),
/// - any error from `f` (transport break, server restart, idle conn reaped).
///
/// On `f` error, drops the cached runtime and retries once; if that fails too,
/// the error is returned and the next call will reconnect again. So a worker
/// recovers as soon as the server is reachable, driven by sign traffic.
fn with_client<F, T>(mut f: F) -> Result<T, String>
where
    F: FnMut(&mut RuntimeState) -> Result<T, String>,
{
    const MAX_ATTEMPTS: usize = 2;
    let mut last_err = String::from("with_client: no attempts made");
    for attempt in 1..=MAX_ATTEMPTS {
        let mut state = client_state()?
            .lock()
            .map_err(|e| format!("Lock error: {e}"))?;

        let current_pid = std::process::id();
        let need_reconnect = state.rt.as_ref().is_none_or(|rt| rt.pid != current_pid);
        if need_reconnect {
            // After fork(), kqueue/epoll fds inherited from the parent are invalid in the
            // child. Dropping the old tokio Runtime would panic trying to wake the I/O
            // driver (EBADF). Leaking it is safe: the worker eventually exits and the fd
            // is reclaimed by the OS.
            if state.rt.as_ref().is_some_and(|rt| rt.pid != current_pid) {
                std::mem::forget(state.rt.take());
            }
            match RuntimeState::connect(state.target.clone()) {
                Ok(rt) => {
                    state.rt = Some(rt);
                }
                Err(e) => {
                    last_err = format!("reconnect (attempt {attempt}/{MAX_ATTEMPTS}): {e:#}");
                    eprintln!("[ossl_hsm] {last_err}");
                    continue;
                }
            }
        }

        let state = &mut *state;
        match f(state.rt.as_mut().unwrap()) {
            Ok(v) => return Ok(v),
            Err(e) => {
                last_err = e;
                eprintln!(
                    "[ossl_hsm] gRPC call failed (attempt {attempt}/{MAX_ATTEMPTS}): {last_err}; \
                     dropping cached connection"
                );
                state.rt = None;
            }
        }
    }
    Err(last_err)
}

/// A signature for another key than the requested one must not be used.
fn check_key_id(requested: &str, answered: &str) -> Result<(), String> {
    if requested != answered {
        return Err(format!(
            "gRPC Sign error: response is for key {answered:?}, requested {requested:?}"
        ));
    }
    Ok(())
}

/// Sign data via the gRPC server. Returns IEEE P1363 signature bytes.
pub fn sign(key_id: &str, digest: &[u8]) -> Result<Vec<u8>, String> {
    with_client(|rt| {
        let request = SignRequest {
            key_id: key_id.to_string(),
            data: digest.to_vec(),
            algorithm: DigestAlgorithm::None as i32, // provider already hashed
        };
        let response = rt
            .runtime
            .block_on(rt.client.sign(request))
            .map_err(|e| format!("gRPC Sign error: {e}"))?;
        let response = response.into_inner();
        check_key_id(key_id, &response.key_id)?;
        Ok(response.signature)
    })
}

/// Get the public key PEM via the gRPC server.
pub fn get_public_key(key_id: &str) -> Result<PublicKeyInfo, String> {
    with_client(|rt| {
        let request = GetPublicKeyRequest {
            key_id: key_id.to_string(),
        };
        let response = rt
            .runtime
            .block_on(rt.client.get_public_key(request))
            .map_err(|e| format!("gRPC GetPublicKey error: {e}"))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    const REMOTE: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
    const LOOPBACK: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    #[test]
    fn https_is_tls_everywhere() {
        assert!(wants_tls(Some("https"), REMOTE, false).unwrap());
        assert!(wants_tls(Some("https"), LOOPBACK, false).unwrap());
        assert!(wants_tls(Some("https"), REMOTE, true).unwrap());
    }

    #[test]
    fn plaintext_only_to_loopback() {
        assert!(!wants_tls(Some("http"), LOOPBACK, false).unwrap());
        assert!(!wants_tls(None, LOOPBACK, false).unwrap());
        assert!(
            !wants_tls(
                Some("http"),
                IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                false
            )
            .unwrap()
        );
        assert!(wants_tls(Some("http"), REMOTE, false).is_err());
        assert!(wants_tls(None, REMOTE, false).is_err());
    }

    #[test]
    fn remote_plaintext_needs_opt_in() {
        assert!(!wants_tls(Some("http"), REMOTE, true).unwrap());
        assert!(!wants_tls(None, REMOTE, true).unwrap());
    }

    #[test]
    fn unknown_scheme_is_refused() {
        assert!(wants_tls(Some("grpc"), LOOPBACK, true).is_err());
    }

    #[test]
    fn resolve_keeps_https() {
        let target = resolve("https://127.0.0.1:1234", false, None, None).unwrap();
        assert_eq!(target.uri.to_string(), "https://127.0.0.1:1234/");
        assert!(target.tls);
    }

    #[test]
    fn resolve_keeps_https_for_ipv6_literal() {
        let target = resolve("https://[::1]:1234", false, None, None).unwrap();
        assert_eq!(target.uri.to_string(), "https://[::1]:1234/");
        assert!(target.tls);
    }

    #[test]
    fn resolve_plaintext_loopback() {
        let target = resolve(DEFAULT_ADDR, false, None, None).unwrap();
        assert_eq!(target.uri.to_string(), "http://[::1]:50051/");
        assert!(!target.tls);
    }

    #[test]
    fn resolve_refuses_remote_plaintext() {
        assert!(resolve("http://192.0.2.1:50051", false, None, None).is_err());
        assert!(resolve("192.0.2.1:50051", false, None, None).is_err());
        assert!(resolve("http://192.0.2.1:50051", true, None, None).is_ok());
    }

    #[test]
    fn sign_response_for_other_key_is_refused() {
        assert!(check_key_id("tls.p256", "tls.p256").is_ok());
        assert!(check_key_id("tls.p256", "asl.p256").is_err());
        assert!(check_key_id("tls.p256", "").is_err());
    }

    #[test]
    fn resolve_refuses_tls_material_over_plaintext() {
        let identity = Some(Identity::from_pem("", ""));
        assert!(resolve(DEFAULT_ADDR, false, None, identity).is_err());
        let ca = Some(Certificate::from_pem(""));
        assert!(resolve(DEFAULT_ADDR, false, ca, None).is_err());
    }

    #[test]
    fn resolve_refuses_unusable_client_certificate() {
        let identity = Some(Identity::from_pem("", ""));
        assert!(resolve("https://127.0.0.1:1234", false, None, identity).is_err());
    }
}
