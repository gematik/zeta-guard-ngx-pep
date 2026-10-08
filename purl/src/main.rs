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
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use argp::{FromArgs, parse_args_or_exit};
use http::Method;
use ngx_pep::client::asl::{encode_valid_http_request, valid_asl_request};
use ngx_pep::client::register_client;
use ngx_pep::client::token_dispenser::{PoPPKey, SmcBKey, TokenDispenser};
use reqwest::Url;
use reqwest::cookie::Jar;
use tokio::sync::mpsc::{Sender, channel};
use tokio::time::Instant;

#[allow(dead_code, clippy::all)]
mod typify {
    include!(concat!(env!("OUT_DIR"), "/typify.rs"));
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
enum Subcommand {
    Curl(Curl),
    Asl(Asl),
    Bench(Bench),
}

/// cli args
#[derive(Debug, FromArgs)]
struct Args {
    /// path to pkcs12 keystore to sign smcb token with (uses the first private key chain) — env: PURL_P12
    #[argp(option, short = 'p')]
    p12: Option<String>,

    /// password for pkcs12 keystore — env: PURL_P12_PASS
    #[argp(option, short = 'w')]
    p12_pass: Option<String>,

    /// path to pkcs12 keystore to sign popp token with — env: PURL_POPP_P12
    #[argp(option, short = 'P')]
    popp_p12: Option<String>,

    /// password for popp pkcs12 keystore — env: PURL_POPP_P12_PASS
    #[argp(option, short = 'W')]
    popp_p12_pass: Option<String>,

    /// alias in popp pkcs12 keystore — env: PURL_POPP_P12_ALIAS
    #[argp(option, short = 'A', default = "\"alias\".to_string()")]
    popp_p12_alias: String,

    /// authserver host, e.g. zeta-cd.westeurope.cloudapp.azure.com — env: PURL_HOST
    #[argp(option, short = 'h')]
    host: Option<String>,

    /// authserver base url, e.g. https://zeta-dev…/auth/ — env: PURL_AUTH
    #[argp(option, short = 'a')]
    auth: Option<String>,

    /// realm — env: PURL_REALM
    #[argp(option, short = 'r', default = "\"zeta-guard\".to_string()")]
    realm: String,

    /// accept invalid certs
    #[argp(switch, short = 'k')]
    insecure: bool,

    #[argp(subcommand)]
    command: Subcommand,
}

impl Args {
    fn p12(&self) -> PathBuf {
        Path::new(
            &std::env::var("PURL_P12")
                .unwrap_or_else(|_| self.p12.clone().expect("require -p or PURL_P12")),
        )
        .to_path_buf()
    }

    fn p12_pass(&self) -> String {
        std::env::var("PURL_P12_PASS")
            .unwrap_or_else(|_| self.p12_pass.clone().expect("require -w or PURL_P12_PASS"))
    }

    pub fn popp_p12(&self) -> PathBuf {
        Path::new(
            &std::env::var("PURL_POPP_P12")
                .unwrap_or_else(|_| self.popp_p12.clone().expect("require -P or PURL_POPP_P12")),
        )
        .to_path_buf()
    }

    pub fn popp_p12_pass(&self) -> String {
        std::env::var("PURL_POPP_P12_PASS").unwrap_or_else(|_| {
            self.popp_p12_pass
                .clone()
                .expect("require -W or PURL_POPP_P12_PASS")
        })
    }

    pub fn popp_p12_alias(&self) -> String {
        std::env::var("PURL_POPP_P12_ALIAS").unwrap_or(self.popp_p12_alias.clone())
    }

    fn host(&self) -> String {
        std::env::var("PURL_HOST")
            .unwrap_or_else(|_| self.host.clone().expect("require -h or PURL_HOST"))
    }

    fn auth(&self) -> String {
        std::env::var("PURL_AUTH")
            .unwrap_or_else(|_| self.auth.clone().expect("require -a or PURL_AUTH"))
    }

    fn realm(&self) -> String {
        std::env::var("PURL_REALM").unwrap_or_else(|_| self.realm.clone())
    }

    fn auth_url(&self) -> Result<Url> {
        let auth = self.auth();
        let url = if auth.ends_with("/") {
            auth
        } else {
            format!("{}/", auth)
        };
        Ok(Url::parse(&url)?)
    }

    fn client_registration_url(&self) -> Result<Url> {
        Ok(self.auth_url()?.join(&format!(
            "realms/{}/clients-registrations/openid-connect/",
            self.realm()
        ))?)
    }

    fn token_url(&self) -> Result<Url> {
        Ok(self.auth_url()?.join(&format!(
            "realms/{}/protocol/openid-connect/token",
            self.realm()
        ))?)
    }

    fn nonce_url(&self) -> Result<Url> {
        Ok(self
            .auth_url()?
            .join(&format!("realms/{}/zeta-guard-nonce/", self.realm()))?)
    }
}

/// wrap curl
#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand, name = "curl")]
struct Curl {
    /// request method, needed for DPoP proof, passed to curl as --request also
    #[argp(option, short = 'X', default = "\"GET\".to_string()")]
    request: String,

    /// target, e.g. https://zeta-dev…/proxy/hellozeta
    #[argp(positional)]
    target: String,

    /// set PoPP header
    #[argp(switch, short = 'p')]
    popp: bool,

    /// …passed on to curl
    #[argp(positional, greedy)]
    rest: Vec<String>,
}

/// asl
#[derive(FromArgs, PartialEq, Debug, Clone)]
#[argp(subcommand, name = "asl")]
struct Asl {
    /// asl target *without* /ASL, e.g.  https://zeta-dev…
    #[argp(positional)]
    target: String,

    /// number of concurrent tasks for the benchmark
    #[argp(option, short = 'T', default = "16")]
    n_tasks: u16,

    /// number of repetitions, 0 = infinite
    #[argp(option, short = 'n', default = "0")]
    n_repeats: usize,

    /// set PoPP header
    #[argp(switch, short = 'p')]
    popp: bool,
}

impl Asl {
    pub fn target_url(&self) -> Result<Url> {
        let target = &self.target;
        let url = if target.ends_with("/") {
            target
        } else {
            &format!("{}/", target)
        };
        Ok(Url::parse(url)?)
    }
}

async fn benchmark<F, Fut>(f: F, n_tasks: usize, n_repeats: usize)
where
    F: Fn(Sender<Option<f32>>) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let progress = indicatif::ProgressBar::new_spinner();
    let (tx, mut rx) = channel::<Option<f32>>(n_tasks);

    let tasks: Vec<_> = (0..n_tasks).map(|_| tokio::spawn(f(tx.clone()))).collect();
    drop(tx); // rx.recv() returns None once all workers hang up

    let start = Instant::now();
    let mut times = vec![];
    let mut e = 0;
    let mut t = 0;

    while let Some(ms) = rx.recv().await {
        t += 1;
        if n_repeats > 0 && t > n_repeats {
            break;
        }
        match ms {
            Some(ms) => {
                times.push(ms);
            }
            None => {
                e += 1;
            }
        };
        let sum: f32 = times.iter().sum();
        let mean_ms = sum * 1000f32 / times.len() as f32;
        let elapsed = Instant::now().duration_since(start).as_secs_f32();
        let rps = times.len() as f32 / elapsed;

        let times_recent: Vec<_> = times
            .iter()
            .skip(times.len().saturating_sub(1000))
            .copied()
            .collect();
        let sum_recent: f32 = times_recent.iter().sum();
        let mean_ms_recent = sum_recent * 1000f32 / times_recent.len() as f32;
        let min_ms_recent = times.iter().fold(f32::INFINITY, |a, &b| a.min(b)) * 1000f32;
        let max_ms_recent = times.iter().fold(f32::NEG_INFINITY, |a, &b| a.max(b)) * 1000f32;
        progress.set_message(format!(
            "{mean_ms:.4}ms (last 1k: {mean_ms_recent:.4}ms [{min_ms_recent:.4}ms, {max_ms_recent:.4}ms] ) {rps:.2} {e:6}/{t:6}"
        ));
    }
    progress.finish();
    for t in &tasks {
        t.abort();
    }
}

async fn asl(cmd: &Asl, token_dispenser: TokenDispenser) -> Result<()> {
    benchmark(
        move |tx| {
            let token_dispenser = token_dispenser.clone();
            let cmd = cmd.clone();
            let mut session_dispenser = token_dispenser.new_session_dispenser();
            async move {
                loop {
                    let res: Result<()> = async {
                        let tokens = token_dispenser.tokens().await?;
                        let session = session_dispenser.asl_session(cmd.target_url()?).await?;

                        let mut extra_headers = HashMap::new();
                        extra_headers.insert("PoPP", tokens.popp.clone());

                        let inner = encode_valid_http_request(
                            &tokens,
                            Method::GET,
                            cmd.target_url()?
                                .join("/pep/achelos_testfachdienst/hellozeta")?
                                .as_str()
                                .parse()?,
                            Some(extra_headers),
                        )?;

                        let start = Instant::now();

                        valid_asl_request(&tokens, session, cmd.target_url()?, &inner, None)
                            .await?;
                        let _ = tx
                            .send(Some(Instant::now().duration_since(start).as_secs_f32()))
                            .await;
                        Ok(())
                    }
                    .await;
                    if res.is_err() {
                        println!("{res:?}");
                        let _ = tx.send(None).await;
                    }
                }
            }
        },
        cmd.n_tasks.into(),
        cmd.n_repeats,
    )
    .await;

    Ok(())
}

async fn curl(args: &Args, cmd: &Curl, token_dispenser: TokenDispenser) -> Result<()> {
    let tokens = token_dispenser.tokens().await?;
    let mut curl_args = vec![
        "--header".to_string(),
        format!("authorization: DPoP {}", &tokens.access_token),
        "--header".to_string(),
        format!(
            "dpop: {}",
            &tokens.valid_dpop_proof(&cmd.request, &cmd.target)?
        ),
        "--request".to_string(),
        cmd.request.clone(),
    ];
    if args.insecure {
        curl_args.push("--insecure".to_string());
    }
    if cmd.popp {
        curl_args.push("--header".to_string());
        curl_args.push(format!("PoPP: {}", tokens.popp));
    }
    curl_args.append(&mut cmd.rest.clone());
    curl_args.push(cmd.target.clone());
    // exec does not return on success
    Err(Command::new("curl").args(&curl_args).exec())?
}

/// Benchmark GET via reqwest with optional PoPP
#[derive(FromArgs, PartialEq, Debug, Clone)]
#[argp(subcommand, name = "bench")]
struct Bench {
    /// request method
    #[argp(option, short = 'X', default = "\"GET\".to_string()")]
    request: String,

    /// pass PoPP
    #[argp(switch, short = 'p')]
    popp: bool,

    /// PoPP: override actorId claim
    #[argp(option)]
    popp_actor_id_override: Option<String>,

    /// expect response status, 0: any
    #[argp(option, default = "0")]
    expect_status: u16,

    /// number of concurrent tasks for the benchmark
    #[argp(option, short = 'T', default = "16")]
    n_tasks: u16,

    /// number of repetitions, 0 = infinite
    #[argp(option, short = 'n', default = "0")]
    n_repeats: usize,

    /// target, e.g. https://zeta-dev…/proxy/hellozeta
    #[argp(positional)]
    target: String,
}

impl Bench {
    pub fn target_url(&self) -> Result<Url> {
        self.target.parse().context("unable to parse target URL")
    }
}

async fn bench(cmd: &Bench, token_dispenser: TokenDispenser) -> Result<()> {
    let expect_status = cmd.expect_status;
    let do_popp = cmd.popp;
    let target = cmd.target_url()?.clone();

    benchmark(
        move |tx| {
            let token_dispenser = token_dispenser.clone();

            let target = target.clone();
            async move {
                loop {
                    let res: Result<()> = async {
                        let tokens = token_dispenser.tokens().await?;
                        let mut request = tokens.valid_get(&token_dispenser.jar, target.clone())?;
                        if do_popp {
                            request = request.header("popp", &tokens.popp);
                        };
                        // set forward headers to enable testing without ingress
                        request =
                            request.header("x-forwarded-host", target.host().unwrap().to_string());
                        request = request.header(
                            "x-forwarded-port",
                            target.port_or_known_default().unwrap().to_string(),
                        );
                        request = request.header("x-forwarded-proto", target.scheme());

                        let start = Instant::now();

                        match request.send().await {
                            Ok(response) => {
                                if expect_status != 0 && response.status() != expect_status {
                                    bail!(
                                        "unespected status; want={expect_status}, got={}",
                                        response.status()
                                    );
                                }
                            }
                            Err(e) => {
                                if expect_status != 0
                                    && let Some(status) = e.status()
                                    && status != expect_status
                                {
                                    bail!("{e:?}");
                                }
                            }
                        }

                        let _ = tx
                            .send(Some(Instant::now().duration_since(start).as_secs_f32()))
                            .await;
                        Ok(())
                    }
                    .await;
                    if res.is_err() {
                        println!("{res:?}");
                        let _ = tx.send(None).await;
                    }
                }
            }
        },
        cmd.n_tasks.into(),
        cmd.n_repeats,
    )
    .await;

    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args: Args = parse_args_or_exit(argp::DEFAULT);

    let jar = Jar::default();
    let registration = register_client(args.client_registration_url()?, &jar).await?;
    let smcb_key = SmcBKey::from_path(&args.p12(), &args.p12_pass()).await?;
    let popp_key = PoPPKey::from_path(
        &args.popp_p12(),
        &args.popp_p12_pass(),
        &args.popp_p12_alias(),
    )
    .await?;

    let jar = Arc::new(Jar::default());

    let token_dispenser = TokenDispenser::new(
        jar,
        registration,
        smcb_key,
        args.host(),
        args.nonce_url()?,
        args.token_url()?,
        popp_key,
    );

    match &args.command {
        Subcommand::Curl(cmd) => curl(&args, cmd, token_dispenser).await,
        Subcommand::Asl(cmd) => asl(cmd, token_dispenser).await,
        Subcommand::Bench(cmd) => bench(cmd, token_dispenser).await,
    }
}
