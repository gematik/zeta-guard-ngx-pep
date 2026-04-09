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

use std::fs::{File, OpenOptions};
use std::net::TcpListener;
use std::ops::RangeInclusive;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use std::{env, fs};

use anyhow::{Context, Result, bail};
use http::StatusCode;
use ngx_pep::its::TestControlClient;
use reqwest::{Client, ClientBuilder, Url};
use rstest::fixture;
use tokio::process::Command;
use tokio::runtime::Handle;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_serde::formats::Json;

use ngx_pep::client::{
    ClientRegistration, create_smcb_token, exchange_access_token, get_nonce, register_client,
};

use crate::common::echo::echo_server;
use crate::common::ocsp::ocsp_responder;

pub mod echo;
pub mod ocsp;

#[allow(dead_code, clippy::all)]
pub mod typify {
    include!(concat!(env!("OUT_DIR"), "/typify.rs"));
}

pub struct PortLock {
    pub port: u16,
    _file: File, // for flock
}

impl PortLock {
    pub fn try_acquire(dir: &Path, port: u16) -> Result<Option<Self>> {
        std::fs::create_dir_all(dir).context("create lock dir")?;

        let path = dir.join(format!("port-{port}.lock"));
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("open lock file {path:?}"))?;

        // exlusive, non-blocking
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            // Someone else holds it.
            return Ok(None);
        }

        Ok(Some(Self { port, _file: file }))
    }
}

pub fn reserve_port(prefix: &Path, range: RangeInclusive<u16>) -> Result<PortLock> {
    let lock_dir = prefix.join("locks");

    for port in range.clone() {
        let test_prefix = prefix.join(format!("test-{port}"));
        if !test_prefix.exists() {
            bail!("test prefix missing: {}", test_prefix.to_str().unwrap());
        }
        let Some(lock) = PortLock::try_acquire(&lock_dir, port)? else {
            continue;
        };

        // try to bind chosen ports
        match (
            TcpListener::bind(("127.0.0.1", port)),
            // embedded echo server to test upstream
            TcpListener::bind(("127.1.33.7", port + 100)),
            // hsm_sim for this nginx
            TcpListener::bind(("127.1.33.7", port + 200)),
            // ocsp responder
            TcpListener::bind(("127.1.33.7", port + 300)),
        ) {
            (Ok(listener_nginx), Ok(listener_echo), Ok(listener_hsm_sim), Ok(listener_ocsp)) => {
                // ports are bindable, drop sockets so nginx and echo server can bind on it
                drop(listener_nginx);
                drop(listener_echo);
                drop(listener_hsm_sim);
                drop(listener_ocsp);
                return Ok(lock);
            }
            _ => {
                // either or both ports blocked by some other process, drop flock and try next
                drop(lock);
                continue;
            }
        }
    }

    bail!("no free port in range {range:?}");
}

struct State {
    prefix: PathBuf,
    control_path: PathBuf,
    started: bool,
    port_lock: PortLock,
    hsm_sim: Option<JoinHandle<()>>,
    ocsp_responder: Option<JoinHandle<()>>,
}

struct NginxManager {
    state: Mutex<State>,
    leases: AtomicUsize,
    pid: AtomicI32, // master PID (child of the test binary)
}

static MANAGER: OnceLock<Manager> = OnceLock::new();

fn manager() -> Manager {
    let prefix = Path::new("./prefix").to_path_buf();

    // see build.rs for range
    let port_lock = reserve_port(&prefix, 8003..=8006).expect("port");

    MANAGER
        .get_or_init(|| {
            let prefix = Path::new("./prefix").to_path_buf();
            let control_path = prefix.join(format!("test-{}/control", port_lock.port));
            if control_path.exists() {
                fs::remove_dir_all(&control_path)
                    .unwrap_or_else(|_| panic!("remove {}", control_path.display()));
            }
            fs::create_dir_all(&control_path)
                .unwrap_or_else(|_| panic!("create {}", control_path.display()));
            Manager(Arc::new(NginxManager {
                state: Mutex::new(State {
                    prefix,
                    control_path,
                    started: false,
                    port_lock,
                    hsm_sim: None,
                    ocsp_responder: None,
                }),
                leases: AtomicUsize::new(0),
                pid: AtomicI32::new(0),
            }))
        })
        .clone()
}

#[derive(Clone)]
struct Manager(Arc<NginxManager>);

impl Manager {
    async fn ensure_started(&self) -> Result<()> {
        let mut state = self.0.state.lock().await;
        if state.started {
            return Ok(());
        }

        let port = state.port_lock.port;
        let hsm_sim_addr = format!("127.1.33.7:{}", port + 200);
        let hsm_sim_url = format!("http://{hsm_sim_addr}");

        let hsm_sim_addr_clone = hsm_sim_addr.clone();
        let hsm_sim_task = tokio::spawn(async move {
            let _ = hsm_sim::tests::start_server(&hsm_sim_addr_clone).await;
        });

        let old_handle = state.hsm_sim.replace(hsm_sim_task);
        if let Some(handle) = old_handle {
            handle.abort();
        }

        // Wait for hsm-sim to be connectable before spawning nginx
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if tokio::net::TcpStream::connect(&hsm_sim_addr).await.is_ok() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .context("hsm_sim did not become ready")?;

        // Start OCSP responder
        let ocsp_port = port + 300;
        let conf_dir = state.prefix.join("conf");
        let ocsp_responder_task = tokio::spawn(async move {
            ocsp_responder(ocsp_port, &conf_dir)
                .await
                .expect("ocsp_responder")
        });

        let old_ocsp = state.ocsp_responder.replace(ocsp_responder_task);
        if let Some(handle) = old_ocsp {
            handle.abort();
        }

        let ocsp_addr = format!("127.1.33.7:{ocsp_port}");
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if tokio::net::TcpStream::connect(&ocsp_addr).await.is_ok() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .context("ocsp responder did not become ready")?;

        let mut cmd = Command::new(state.prefix.join("sbin/nginx"));
        cmd.args(["-c", &format!("conf/test-{port}.conf")]);
        cmd.env("HSM_PROXY_ADDR", &hsm_sim_url);

        // Redirect stdout/stderr to the shared test log file.
        // All nginx instances + their ossl_hsm provider output go to one file for easier debugging.
        let log_file = || {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(state.prefix.join("test.log"))
        };
        let stdout = log_file().context("test.log (stdout)")?;
        let stderr = log_file().context("test.log (stderr)")?;

        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(stdout);
        cmd.stderr(stderr);

        let child = cmd.spawn().context("spawn")?;
        let pid = child.id().context("pid")? as i32;

        self.0.pid.store(pid, Ordering::SeqCst);
        state.started = true;

        Ok(())
    }

    fn stop_blocking(&self) {
        let pid = self.0.pid.swap(0, Ordering::SeqCst);
        if pid == 0 {
            return;
        }

        let mut state = tokio::task::block_in_place(move || {
            Handle::current().block_on(async move { self.0.state.lock().await })
        });

        if let Some(handle) = state.hsm_sim.take() {
            handle.abort();
        }
        if let Some(handle) = state.ocsp_responder.take() {
            handle.abort();
        }

        unsafe {
            libc::kill(pid, libc::SIGQUIT);

            // reap with timeout
            let mut status: libc::c_int = 0;
            let mut waited_ms = 0;

            while waited_ms < 10_000 {
                let rc = libc::waitpid(pid, &mut status, libc::WNOHANG);
                if rc == pid {
                    break;
                }
                if rc == -1 {
                    // ECHILD (already reaped) or other: give up
                    break;
                }

                // sleep 10ms
                let ts = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 10_000_000,
                };
                libc::nanosleep(&ts, std::ptr::null_mut());
                waited_ms += 10;
            }
        }

        let _ = self.0.leases.swap(0, Ordering::SeqCst);
        state.started = false;
    }
}

#[derive(Clone)]
pub struct NginxLease {
    mgr: Manager,
}

impl NginxLease {
    pub async fn acquire() -> Result<Self> {
        let mgr = manager();
        mgr.ensure_started().await?;

        mgr.0.leases.fetch_add(1, Ordering::SeqCst);

        Ok(Self { mgr })
    }

    pub async fn url(&self) -> Result<Url> {
        let port = self.mgr.0.state.lock().await.port_lock.port;
        // use IP instead of `localhost`, because that might resolve to [::1] and lead to problems
        // in CI
        Url::parse(&format!("http://127.0.0.1:{port}")).context("url parse")
    }

    pub async fn tls_url(&self) -> Result<Url> {
        let port = self.mgr.0.state.lock().await.port_lock.port;
        // prepend 2 for ssl listener
        Url::parse(&format!("https://127.0.0.1:2{port}")).context("url parse")
    }

    pub async fn hsm_sim_url(&self) -> Result<String> {
        let port = self.mgr.0.state.lock().await.port_lock.port;
        Ok(format!("http://127.1.33.7:{}", port + 200))
    }

    pub async fn wait_ready(&self) -> Result<()> {
        // not to be confused with echo-server /ready; this is tested on-demand, in start_echo_server
        let nginx_ready = async move {
            let url = self.url().await?.join("ready/")?;
            loop {
                if let Ok(resp) = reqwest::get(url.clone()).await
                    && resp.status() == StatusCode::OK
                {
                    return anyhow::Ok(());
                }
                sleep(Duration::from_millis(10)).await;
            }
        };
        let control_ready = async move {
            loop {
                if self.control_client().await.is_ok() {
                    return anyhow::Ok(());
                }
                sleep(Duration::from_millis(10)).await;
            }
        };

        let _ = timeout(Duration::from_secs(5), async move {
            futures::try_join!(nginx_ready, control_ready)
        })
        .await?;
        Ok(())
    }

    pub async fn control_sockets(&self) -> Result<Vec<PathBuf>> {
        let mut sockets: Vec<PathBuf> = Vec::new();
        let mut read_dir =
            tokio::fs::read_dir(self.mgr.0.state.lock().await.control_path.as_path()).await?;
        while let Some(socket) = read_dir.next_entry().await? {
            let file_type = socket.file_type().await?;
            if file_type.is_socket() {
                sockets.push(socket.path());
            }
        }
        Ok(sockets)
    }

    async fn make_control_client(&self, socket: PathBuf) -> Result<TestControlClient> {
        let transport = tarpc::serde_transport::unix::connect(&socket, Json::default).await?;
        Ok(TestControlClient::new(tarpc::client::Config::default(), transport).spawn())
    }

    /// Picks the first available socket and constructs a client to it.
    /// NOTE: Every worker process has its own control socket, but as the JWK cache is distributed
    /// we only need to control one to manipulate it.
    pub async fn control_client(&self) -> Result<TestControlClient> {
        let sockets = self.control_sockets().await?;
        if sockets.is_empty() {
            bail!(
                "0 sockets found at {}",
                self.mgr.0.state.lock().await.control_path.display()
            )
        }

        let socket = sockets.first().unwrap().clone();
        self.make_control_client(socket).await
    }

    pub async fn start_echo_server(&self) -> JoinHandle<()> {
        let port = self.mgr.0.state.lock().await.port_lock.port + 100; // eg 8003 + 100 → 8103
        let task = tokio::spawn(async move { echo_server(port).await.expect("echo_server") });
        let echo_ready =
            Url::parse(&format!("http://127.1.33.7:{port}/ready/")).expect("ready url");

        timeout(Duration::from_secs(5), async move {
            loop {
                if let Ok(resp) = reqwest::get(echo_ready.clone()).await
                    && resp.status() == StatusCode::OK
                {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("to become ready");

        task
    }
}

impl Drop for NginxLease {
    fn drop(&mut self) {
        let remaining = self.mgr.0.leases.fetch_sub(1, Ordering::SeqCst) - 1;
        if remaining != 0 {
            return;
        }

        self.mgr.stop_blocking();
    }
}

#[fixture]
pub async fn nginx() -> NginxLease {
    NginxLease::acquire().await.expect("acquire nginx")
}

pub struct TestContext {
    pub client: Client,
    pub auth_url: Url,
    pub token_url: Url,
    pub nonce_url: Url,
    pub registration: ClientRegistration,
}

impl TestContext {
    async fn get() -> Result<Self> {
        let client = ClientBuilder::new()
            .use_rustls_tls()
            .danger_accept_invalid_certs(true)
            .build()?;

        let auth_url = env::var("IT_AUTH")?;
        let auth_url: Url = if auth_url.ends_with("/") {
            auth_url
        } else {
            format!("{}/", auth_url)
        }
        .parse()?;

        let registration_url =
            auth_url.join("realms/zeta-guard/clients-registrations/openid-connect/")?;
        let token_url = auth_url.join("realms/zeta-guard/protocol/openid-connect/token/")?;
        let nonce_url = auth_url.join("realms/zeta-guard/zeta-guard-nonce")?;
        let registration = register_client(registration_url.clone(), &client).await?;
        Ok(TestContext {
            client,
            auth_url,
            token_url,
            nonce_url,
            registration,
        })
    }

    pub fn it_p12(&self) -> PathBuf {
        env::var("IT_P12").expect("IT_P12").into()
    }

    pub fn it_p12_pass(&self) -> String {
        env::var("IT_P12_PASS").expect("IT_P12_PASS")
    }

    pub async fn access_token(&self) -> Result<String> {
        let nonce = get_nonce(self.nonce_url.clone(), &self.client).await?;

        let smcb = create_smcb_token(
            &self.it_p12(),
            &self.it_p12_pass(),
            self.auth_url.clone(),
            nonce.clone(),
            &self.registration,
        )
        .await?;

        exchange_access_token(
            self.token_url.clone(),
            nonce,
            &self.registration,
            &smcb,
            &self.client,
        )
        .await
    }

    pub fn popp_p12(&self) -> Result<PathBuf> {
        Ok(PathBuf::from(env::var("IT_POPP_P12").expect("IT_POPP_P12")))
    }

    pub fn popp_p12_pass(&self) -> Result<String> {
        Ok(env::var("IT_POPP_P12_PASS").expect("IT_POPP_P12_PASS"))
    }

    pub fn popp_p12_alias(&self) -> Result<String> {
        Ok(env::var("IT_POPP_P12_ALIAS").expect("IT_POPP_P12_ALIAS"))
    }
}

static CONTEXT: OnceLock<TestContext> = OnceLock::new();

#[fixture]
pub async fn context() -> &'static TestContext {
    CONTEXT.get_or_init(|| {
        tokio::task::block_in_place(|| {
            let rt = Handle::current();
            rt.block_on(async { TestContext::get().await.expect("TestContext") })
        })
    })
}
