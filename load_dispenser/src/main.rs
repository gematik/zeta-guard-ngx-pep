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

use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use async_walkdir::{Filtering, WalkDir};
use base64ct::{Base64, Encoding};
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use http::Uri;
use indicatif::{ProgressBar, ProgressStyle};
use ngx_pep::client::asl::AslResponse;
use ngx_pep::client::asl::{encode_valid_http_request, valid_asl_request};
use ngx_pep::client::register_client;
use ngx_pep::client::token_dispenser::{Lost, PoPPKey, SessionDispenser, SmcBKey, TokenDispenser};
use rand::prelude::*;
use reqwest::cookie::Jar;
use reqwest::{Method, Url};
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::{Mutex, RwLock, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response};

use pb::StatusReply;
use pb::load_dispenser_server::{LoadDispenser, LoadDispenserServer};

mod pb {
    include!(concat!(env!("OUT_DIR"), "/load_dispenser.rs"));
    pub const FILE_DESCRIPTOR_SET: &[u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/load_dispenser_descriptor.bin"));
}

mod stats;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LdConfig {
    host: String,
    /// worker tasks (multiplexed to `nproc` threads)
    threads: usize,
    /// number of identities to use
    instances: usize,
    /// fraction of instances that had tokens previously (all database entries exist, etc.)
    registered_full: f64,
    /// limit concurrent requests during the setup phase
    setup_semaphore: u64,
    /// wait time after setup (to better separate graphs)
    wait_after_setup_s: u64,
    /// NOTE: enforced for the whole turn; .tokens() might lead to 0 or multiple
    /// requests, depending on the state of the instance
    target_rps: u32,
    /// ramp-up time to target_rps
    ramp_s: u64,
    /// load runtime, measured from RUNNING (i.e. excluding setup); 0 for unlimited
    runtime_s: u64,
    /// access token loss rate [0.0,1.0]
    loss_rate_access: f64,
    /// refresh token loss rate [0.0,1.0] (rt loss implies at loss)
    loss_rate_refresh: f64,
    /// must be "hellozeta" or "tokens".
    /// "tokens" will only keep the identity logged in to pdp, and skip the "hellozeta" request.
    /// NOTE: "tokens" should probably be combined with a token losing option, otherwise the worker
    /// loop will run dry when all identities are logged in already.
    test: String,
}

fn effective(slot: &serde_json::Value) -> Result<LdConfig, config::ConfigError> {
    let config: LdConfig = config::Config::builder()
        .set_default("threads", 250)?
        .set_default("instances", 70_000)?
        .set_default("registered_full", 1.0)?
        .set_default("setup_semaphore", 512)?
        .set_default("wait_after_setup_s", 15)?
        .set_default("target_rps", 350)?
        .set_default("ramp_s", 5)?
        .set_default("loss_rate_access", 0.0)?
        .set_default("loss_rate_refresh", 0.0)?
        .set_default("runtime_s", 1800)?
        .set_default("test", "hellozeta")?
        .add_source(config::Environment::with_prefix("LOAD_DISPENSER").try_parsing(true))
        .add_source(config::Config::try_from(slot)?)
        .build()?
        .try_deserialize()?;

    match config.test.as_str() {
        "hellozeta" | "tokens" => {}
        _ => {
            return Err(config::ConfigError::Message(format!(
                "Invalid test value: {}",
                config.test
            )));
        }
    };

    Ok(config)
}

fn json_from_proto(v: prost_types::Value) -> serde_json::Value {
    use prost_types::value::Kind;
    use serde_json::Value as J;
    match v.kind {
        None | Some(Kind::NullValue(_)) => J::Null,
        Some(Kind::NumberValue(n)) => {
            // Struct numbers are always f64; keep integers integral so serde
            // can deserialize them into usize/u32/u64 fields
            if n.fract() == 0.0 && (i64::MIN as f64..=i64::MAX as f64).contains(&n) {
                J::from(n as i64)
            } else {
                serde_json::Number::from_f64(n)
                    .map(J::Number)
                    .unwrap_or(J::Null)
            }
        }
        Some(Kind::StringValue(s)) => J::String(s),
        Some(Kind::BoolValue(b)) => J::Bool(b),
        Some(Kind::StructValue(s)) => json_from_proto_struct(s),
        Some(Kind::ListValue(l)) => J::Array(l.values.into_iter().map(json_from_proto).collect()),
    }
}

fn json_from_proto_struct(s: prost_types::Struct) -> serde_json::Value {
    serde_json::Value::Object(
        s.fields
            .into_iter()
            .map(|(k, v)| (k, json_from_proto(v)))
            .collect(),
    )
}

fn proto_from_json(v: serde_json::Value) -> prost_types::Value {
    use prost_types::value::Kind;
    use serde_json::Value as J;
    let kind = match v {
        J::Null => Kind::NullValue(0),
        J::Bool(b) => Kind::BoolValue(b),
        J::Number(n) => Kind::NumberValue(n.as_f64().unwrap_or(f64::NAN)),
        J::String(s) => Kind::StringValue(s),
        J::Array(a) => Kind::ListValue(prost_types::ListValue {
            values: a.into_iter().map(proto_from_json).collect(),
        }),
        obj @ J::Object(_) => Kind::StructValue(proto_struct_from_json(obj)),
    };
    prost_types::Value { kind: Some(kind) }
}

fn proto_struct_from_json(v: serde_json::Value) -> prost_types::Struct {
    let serde_json::Value::Object(map) = v else {
        return prost_types::Struct::default();
    };
    prost_types::Struct {
        fields: map
            .into_iter()
            .map(|(k, v)| (k, proto_from_json(v)))
            .collect(),
    }
}

fn progress_bar(msg: &str, n: u64) -> ProgressBar {
    let progress = indicatif::ProgressBar::new(n);
    progress.set_message(msg.to_string());
    progress.set_style(
        ProgressStyle::with_template(
            "{bar:40.cyan/blue} {pos:>7}/{len:7} [{elapsed_precise}/{duration_precise}] {msg}",
        )
        .expect("ProgressStyle"),
    );

    // non-tty (kubectl logs): indicatif draws nothing at all — emit one plain
    // line every 10s instead. Weak handle so the ticker dies with the bar.
    if progress.is_hidden() {
        let weak = progress.downgrade();
        tokio::spawn(async move {
            loop {
                let Some(pb) = weak.upgrade() else { break };
                if pb.is_finished() {
                    break;
                }
                println!(
                    "{} {}/{} [{}s/{}s])",
                    pb.message(),
                    pb.position(),
                    pb.length().unwrap_or(0),
                    pb.elapsed().as_secs(),
                    pb.duration().as_secs(),
                );
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });
    }
    progress
}

/// Retry a fallible async op. Used only in the SETUP phase, which is
/// preparation (not measured), so we retry hard on ANY error — transient
/// connection resets ("connection closed before message completed") are common
/// when hammering register+exchange under load. Exponential backoff
/// (100ms doubling, capped 5s): outages during setup are pool-starvation or
/// reload blips lasting seconds. 8 attempts cover ~11s.
async fn with_retry<F, Fut, T>(attempts: usize, mut f: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut last: Option<anyhow::Error> = None;
    for i in 0..attempts.max(1) {
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                last = Some(e);
                if i + 1 < attempts {
                    let ms = (100u64 << i.min(6)).min(5_000);
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                }
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("with_retry: no attempts")))
}

#[allow(unused)]
struct Dispensed {
    token_dispenser: TokenDispenser,
    session_dispenser: SessionDispenser,
    idx: usize,
}

/// Push button, receive TokenDispenser
struct DispenserDispenser {
    keys: Vec<SmcBKey>,
    dispensers: Vec<OnceLock<Mutex<Dispensed>>>,
    idx: AtomicUsize,
    host: String,
    client_registration_url: Url,
    nonce_url: Url,
    token_url: Url,
    popp_key: PoPPKey,
    limiter: Arc<DefaultDirectRateLimiter>,
}

impl DispenserDispenser {
    #[allow(clippy::too_many_arguments)]
    async fn new(
        keys: Vec<SmcBKey>,
        host: String,
        client_registration_url: Url,
        nonce_url: Url,
        token_url: Url,
        popp_key: PoPPKey,
        registered: usize,
        limiter: Arc<DefaultDirectRateLimiter>,
        setup_sem: usize,
    ) -> Result<Self> {
        let dispensers = keys.iter().map(|_| OnceLock::new()).collect();

        let n_keys = keys.len();
        let idx = AtomicUsize::new(0);
        let mut dd = DispenserDispenser {
            keys,
            dispensers,
            idx,
            host,
            client_registration_url,
            nonce_url,
            token_url,
            popp_key,
            limiter: limiter.clone(),
        };

        if registered > 0 {
            println!("Fully registering {registered} clients");
            let progress = progress_bar(
                "Initial token exchange to fully register users…",
                registered as u64,
            );
            // Cap concurrent in-flight setup work.
            let setup_sem = Semaphore::new(setup_sem);
            let tasks = FuturesUnordered::new();
            for _ in 0..registered {
                tasks.push(async {
                    let _permit = setup_sem.acquire().await.expect("setup semaphore");
                    let dispensed = dd.dispense().await?.lock().await;

                    let _ = with_retry(8, || dispensed.token_dispenser.tokens()).await?;

                    // forget the just acquired tokens again, we only want to init KeyCloak state
                    dispensed
                        .token_dispenser
                        .lose_tokens(Lost::RefreshToken)
                        .await;

                    progress.inc(1);
                    anyhow::Ok(())
                });
            }

            let _ = tasks
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .map(|v| anyhow::Ok(v?))
                .collect::<anyhow::Result<Vec<_>>>()?;

            progress.finish();

            if registered < n_keys {
                println!("Shuffling identities.");
                dd.shuffle();
            }
        }

        Ok(dd)
    }

    fn shuffle(&mut self) {
        self.dispensers.shuffle(&mut ThreadRng::default());
    }

    async fn dispense(&self) -> Result<&Mutex<Dispensed>> {
        let idx = self.idx.fetch_add(1, Ordering::Relaxed) % self.keys.len();
        let dispensers = &self.dispensers[idx];
        let dispensers = match dispensers.get() {
            Some(t) => Ok(t),
            None => {
                let jar = Arc::new(Jar::default());

                // idx was already claimed above, so retrying only re-attempts
                // the network call for THIS slot (no round-robin advance).
                let registration = with_retry(8, || {
                    register_client(self.client_registration_url.clone(), &jar)
                })
                .await?;
                let smcb_key = self.keys[idx].clone();
                let token_dispenser = TokenDispenser::new(
                    jar,
                    registration,
                    smcb_key,
                    self.host.clone(),
                    self.nonce_url.clone(),
                    self.token_url.clone(),
                    self.popp_key.clone(),
                );
                let session_dispenser = token_dispenser.new_session_dispenser();
                let _ = dispensers.set(Mutex::new(Dispensed {
                    token_dispenser,
                    session_dispenser,
                    idx,
                }));
                dispensers.get().ok_or(anyhow!("absurd"))
            }
        }?;

        Ok(dispensers)
    }
}

async fn prepare_identity(path: &Path) -> Result<SmcBKey> {
    let mut file = File::open(path).await.unwrap();
    let mut b64 = String::new();
    file.read_to_string(&mut b64).await.unwrap();
    let p12 = Base64::decode_vec(&b64).unwrap();

    let smcb_key = SmcBKey::from_bytes(&p12, "00")?;

    Ok(smcb_key)
}

async fn prepare_identities(base: &Path, count: usize) -> Result<Vec<SmcBKey>> {
    let progress = progress_bar("Reading SMC-B keystores…", count as u64);

    let mut entries = WalkDir::new(base).filter(|entry| async move {
        if let Some(true) = entry
            .path()
            .file_name()
            .map(|f| f.to_string_lossy().ends_with(".b64"))
        {
            return Filtering::Continue;
        }
        Filtering::Ignore
    });

    let tasks = FuturesUnordered::new();
    while tasks.len() < count {
        match entries.next().await {
            Some(Ok(entry)) => {
                let path = entry.path();
                let progress = progress.clone();
                tasks.push(tokio::spawn(async move {
                    let res = prepare_identity(&path).await;
                    progress.inc(1);
                    res
                }));
            }
            Some(Err(e)) => {
                bail!("error: {}", e)
            }
            None => break,
        }
    }

    let keys = tasks
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .map(|v| anyhow::Ok(v??))
        .collect::<anyhow::Result<Vec<_>>>()?;
    assert!(keys.len() == count);

    progress.finish();
    Ok(keys)
}

async fn hellozeta(
    base: &str,
    dd: Arc<DispenserDispenser>,
    loss_rate_access: f64,
    loss_rate_refresh: f64,
) -> Result<()> {
    let mut dispensed = dd.dispense().await?.lock().await;

    if loss_rate_refresh > 0.0 && fastrand::f32() <= loss_rate_refresh as f32 {
        dispensed
            .token_dispenser
            .lose_tokens(Lost::RefreshToken)
            .await;
    } else if loss_rate_access > 0.0 && fastrand::f32() <= loss_rate_access as f32 {
        dispensed
            .token_dispenser
            .lose_tokens(Lost::AccessToken)
            .await;
    }
    let tokens = dispensed.token_dispenser.tokens().await?.clone();
    let session = dispensed
        .session_dispenser
        .asl_session(format!("{base}ASL").parse()?)
        .await?;

    let mut extra_headers = HashMap::new();
    extra_headers.insert("PoPP", tokens.popp.clone());

    let target: Uri = format!("{base}pep/achelos_testfachdienst/hellozeta").parse()?;
    let inner =
        encode_valid_http_request(&tokens, Method::GET, target.clone(), Some(extra_headers))?;

    match valid_asl_request(&tokens, session, target.to_string().parse()?, &inner, None).await? {
        AslResponse::Body(_) => Ok(()),
        AslResponse::Error(e) => Err(anyhow!("ASL error {e:?}")),
        AslResponse::HttpError(e) => Err(anyhow!("HTTP error {e:?}")),
        AslResponse::Unexpected((status, body)) => bail!("unexpected error {status:?} {body}"),
    }
}

async fn tokens(
    dd: Arc<DispenserDispenser>,
    loss_rate_access: f64,
    loss_rate_refresh: f64,
) -> Result<()> {
    let dispensed = dd.dispense().await?.lock().await;

    if loss_rate_access > 0.0 && fastrand::f32() <= loss_rate_access as f32 {
        // println!("Losing access token {}", dispensed.idx);
        dispensed
            .token_dispenser
            .lose_tokens(Lost::AccessToken)
            .await;
    } else if loss_rate_refresh > 0.0 && fastrand::f32() <= loss_rate_refresh as f32 {
        // println!("Losing refresh token {}", dispensed.idx);
        dispensed
            .token_dispenser
            .lose_tokens(Lost::RefreshToken)
            .await;
    }
    let _ = dispensed.token_dispenser.tokens().await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn worker(
    test: String,
    dd: Arc<DispenserDispenser>,
    base: Arc<str>,
    cancel: CancellationToken,
    idx: usize,
    ramp: Duration,
    loss_rate_access: f64,
    loss_rate_refresh: f64,
    rec: stats::Recorder,
) {
    tokio::select! {
        _ = cancel.cancelled() => return,
        _ = tokio::time::sleep(ramp) => {}
    }
    let label: &'static str = match test.as_str() {
        "hellozeta" => "hellozeta",
        "tokens" => "tokens",
        _ => panic!("invalid value for test: {test}"),
    };
    loop {
        let iteration = async {
            // Gate is driver pacing, not request latency — kept outside the timed region;
            // record_correct handles coordinated omission.
            dd.limiter.until_ready().await;
            rec.time(label, async {
                match test.as_str() {
                    "hellozeta" => {
                        hellozeta(&base, dd.clone(), loss_rate_access, loss_rate_refresh).await
                    }
                    "tokens" => tokens(dd.clone(), loss_rate_access, loss_rate_refresh).await,
                    _ => unreachable!("test value checked above"),
                }
            })
            .await
        };
        let res = tokio::select! {
            _ = cancel.cancelled() => return,
            res = iteration => res,
        };
        if let Err(e) = res {
            eprintln!("{idx} {e:?}");
            rec.error(format!("{e:?}"));
        }
    }
}

async fn setup(cfg: &LdConfig) -> Result<DispenserDispenser> {
    let registered = (cfg.instances as f64 * cfg.registered_full).ceil() as usize;

    let popp_key = PoPPKey::from_path(
        Path::new("popp-token-Server-Sim-nist-komp61.p12"),
        "00",
        "alias",
    )
    .await?;
    let keys = prepare_identities(Path::new("keystores"), cfg.instances).await?;
    let auth_url: Url = format!("https://{}/auth/", cfg.host).parse()?;
    let client_registration_url =
        auth_url.join("realms/zeta-guard/clients-registrations/openid-connect/")?;
    let nonce_url = auth_url.join("realms/zeta-guard/zeta-guard-nonce/")?;
    let token_url = auth_url.join("realms/zeta-guard/protocol/openid-connect/token")?;

    let limiter = Arc::new(RateLimiter::direct(Quota::per_second(
        NonZeroU32::new(cfg.target_rps).ok_or(anyhow!("target_rps must be > 0"))?,
    )));
    DispenserDispenser::new(
        keys,
        cfg.host.clone(),
        client_registration_url,
        nonce_url,
        token_url,
        popp_key,
        registered,
        limiter,
        cfg.setup_semaphore as usize,
    )
    .await
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Phase {
    Stopped,
    Setup,
    Running,
    Aborted,
    Failed,
}

impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Phase::Stopped => "STOPPED",
            Phase::Setup => "SETUP",
            Phase::Running => "RUNNING",
            Phase::Aborted => "ABORTED",
            Phase::Failed => "FAILED",
        }
    }
}

struct Control {
    phase: Phase,
    cancel: Option<CancellationToken>,
    aborted: bool,
}

async fn run_test(
    control: Arc<StdMutex<Control>>,
    cfg: LdConfig,
    cancel: CancellationToken,
) -> Result<()> {
    let dd = tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        res = setup(&cfg) => res?,
    };
    let dd = Arc::new(dd);

    control.lock().unwrap().phase = Phase::Running;
    if cfg.wait_after_setup_s > 0 {
        println!("wait_after_setup_s = {}…", cfg.wait_after_setup_s);
        tokio::time::sleep(Duration::from_secs(cfg.wait_after_setup_s)).await;
    }
    println!("Running load: {cfg:?}");

    // wrk2-style client-side latency + rps to stdout. expected_interval enables
    // coordinated-omission correction
    let rec = stats::spawn(Some(
        1_000_000u64 * cfg.threads as u64 / cfg.target_rps.max(1) as u64,
    ));

    let base: Arc<str> = Arc::from(format!("https://{}/", cfg.host));
    let mut workers = JoinSet::new();
    for idx in 0..cfg.threads {
        let ramp = Duration::from_secs(cfg.ramp_s).mul_f64(idx as f64 / cfg.threads as f64);
        workers.spawn(worker(
            cfg.test.clone(),
            dd.clone(),
            base.clone(),
            cancel.clone(),
            idx,
            ramp,
            cfg.loss_rate_access,
            cfg.loss_rate_refresh,
            rec.clone(),
        ));
    }
    // Ramp samples would be CO-corrected against the full target rate the
    // governor wasn't yet demanding — discard them instead, so the reported
    // histograms cover pure steady state.
    if cfg.ramp_s > 0 {
        let rec = rec.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = cancel.cancelled() => {}
                _ = tokio::time::sleep(Duration::from_secs(cfg.ramp_s)) => rec.reset(),
            }
        });
    }
    if cfg.runtime_s > 0 {
        let timer_expired = tokio::select! {
            _ = cancel.cancelled() => false,
            _ = tokio::time::sleep(Duration::from_secs(cfg.runtime_s)) => true,
        };
        if timer_expired {
            println!("Runtime limit ({}s) reached.", cfg.runtime_s);
            cancel.cancel();
        }
    }
    while workers.join_next().await.is_some() {}
    drop(rec); // last Recorder gone -> aggregator flushes the cumulative summary
    println!("Load stopped.");
    Ok(())
}

#[derive(Clone)]
struct Dispatcher {
    control: Arc<StdMutex<Control>>,
    slot: Arc<RwLock<serde_json::Value>>,
}

#[tonic::async_trait]
impl LoadDispenser for Dispatcher {
    async fn start(&self, _: Request<()>) -> Result<Response<()>, tonic::Status> {
        let cfg = effective(&*self.slot.read().await)
            .map_err(|e| tonic::Status::failed_precondition(e.to_string()))?;

        let cancel = CancellationToken::new();
        {
            let mut control = self.control.lock().unwrap();
            if !matches!(control.phase, Phase::Stopped | Phase::Aborted) {
                return Err(tonic::Status::failed_precondition(format!(
                    "test already active ({})",
                    control.phase.as_str()
                )));
            }
            control.phase = Phase::Setup;
            control.cancel = Some(cancel.clone());
            control.aborted = false;
        }

        let control = self.control.clone();
        tokio::spawn(async move {
            let outcome = run_test(control.clone(), cfg, cancel).await;

            let mut control = control.lock().unwrap();
            control.phase = match outcome {
                Ok(_) => {
                    if control.aborted {
                        Phase::Aborted
                    } else {
                        Phase::Stopped
                    }
                }
                Err(e) => {
                    eprintln!("Test error: {e:?}");
                    Phase::Failed
                }
            };
            control.cancel = None;
            println!("Now in {:?}", control.phase);
        });

        Ok(Response::new(()))
    }

    async fn abort(&self, _: Request<()>) -> Result<Response<()>, tonic::Status> {
        let mut control = self.control.lock().unwrap();
        if let Some(cancel) = control.cancel.take() {
            control.aborted = true;
            cancel.cancel();
        }
        Ok(Response::new(()))
    }

    async fn status(&self, _: Request<()>) -> Result<Response<StatusReply>, tonic::Status> {
        let status = self.control.lock().unwrap().phase.as_str().to_string();
        Ok(Response::new(StatusReply { status }))
    }

    async fn get_config(
        &self,
        _: Request<()>,
    ) -> Result<Response<prost_types::Struct>, tonic::Status> {
        let cfg = effective(&*self.slot.read().await)
            .map_err(|e| tonic::Status::failed_precondition(e.to_string()))?;
        config_reply(cfg)
    }

    async fn set_config(
        &self,
        req: Request<prost_types::Struct>,
    ) -> Result<Response<prost_types::Struct>, tonic::Status> {
        let candidate = json_from_proto_struct(req.into_inner());
        let cfg =
            effective(&candidate).map_err(|e| tonic::Status::invalid_argument(e.to_string()))?;
        // unknown-key check against the struct's own field names, via serialization
        let known =
            serde_json::to_value(&cfg).map_err(|e| tonic::Status::internal(e.to_string()))?;
        if let (Some(candidate), Some(known)) = (candidate.as_object(), known.as_object())
            && let Some(k) = candidate.keys().find(|k| !known.contains_key(*k))
        {
            return Err(tonic::Status::invalid_argument(format!(
                "unknown config field `{k}`, expected one of {}",
                known
                    .keys()
                    .map(|k| format!("`{k}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }

        *self.slot.write().await = candidate;
        Ok(Response::new(proto_struct_from_json(known)))
    }
}

fn config_reply(cfg: LdConfig) -> Result<Response<prost_types::Struct>, tonic::Status> {
    let value = serde_json::to_value(cfg).map_err(|e| tonic::Status::internal(e.to_string()))?;
    Ok(Response::new(proto_struct_from_json(value)))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let addr: SocketAddr = env::var("LOAD_DISPENSER_GRPC_ADDR")
        .unwrap_or("0.0.0.0:50051".to_string())
        .parse()?;

    let dispatcher = Dispatcher {
        control: Arc::new(StdMutex::new(Control {
            phase: Phase::Stopped,
            cancel: None,
            aborted: false,
        })),
        slot: Arc::new(RwLock::new(serde_json::Value::Object(Default::default()))),
    };

    let reflection_v1 = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(pb::FILE_DESCRIPTOR_SET)
        .build_v1()?;
    let reflection_v1alpha = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(pb::FILE_DESCRIPTOR_SET)
        .build_v1alpha()?;

    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<LoadDispenserServer<Dispatcher>>()
        .await;

    println!("load_dispenser listening on {addr}");
    tonic::transport::Server::builder()
        .add_service(reflection_v1)
        .add_service(reflection_v1alpha)
        .add_service(health_service)
        .add_service(LoadDispenserServer::new(dispatcher))
        .serve_with_shutdown(addr, async {
            use tokio::signal::unix::{SignalKind, signal};
            let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
            tokio::select! {
                _ = term.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        })
        .await?;

    Ok(())
}
