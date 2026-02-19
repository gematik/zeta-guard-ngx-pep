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

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;
use argp::{FromArgs, parse_args_or_exit};
use base64ct::{Base64UrlUnpadded, Encoding};
use futures::channel::mpsc::channel;
use futures::{SinkExt, StreamExt};
use http::Method;
use ngx_pep::client::asl::{asl_handshake, asl_request, encode_http_request};
use ngx_pep::client::{
    ClientRegistration, create_dpop_proof, create_smcb_token, exchange_access_token, get_nonce,
    register_client,
};
use reqwest::{Client, ClientBuilder, Url};
use sha2::{Digest, Sha256};
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
    fn p12_path(&self) -> PathBuf {
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
            "realms/{}/protocol/openid-connect/token/",
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
    /// request method, needed for DPoP proof, pass to curl as --request also
    #[argp(option, short = 'X', default = "\"GET\".to_string()")]
    request: String,

    /// target, e.g. https://zeta-dev…/proxy/hellozeta
    #[argp(positional)]
    target: String,

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

async fn benchmark<F, Fut>(f: F, n_tasks: usize)
where
    F: FnOnce() -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<Vec<f32>>> + Send + 'static,
{
    let progress = indicatif::ProgressBar::new_spinner();
    let (tx, mut rx) = channel(n_tasks);

    let mut tasks = vec![];

    for _ in 0..n_tasks {
        let f = f.clone();
        let mut tx = tx.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                let f = f.clone();
                match f().await {
                    Ok(times) => tx.send(Some(times)).await.expect("send"),
                    Err(_e) => {
                        // println!("{e}");
                        tx.send(None).await.expect("send")
                    }
                };
            }
        }));
    }

    let start = Instant::now();
    let mut times = vec![];
    let mut e = 0;
    let mut t = 0;

    while let Some(ms) = rx.next().await {
        t += 1;
        match ms {
            Some(ms) => {
                times.extend_from_slice(&ms);
            }
            None => {
                e += 1;
            }
        };
        let sum: f32 = times.iter().sum();
        let mean_ms = sum * 100f32 / times.len() as f32;
        let elapsed = Instant::now().duration_since(start).as_secs_f32();
        let rps = times.len() as f32 / elapsed;

        let l = if times.len() < 1_001 {
            times.len()
        } else {
            times.len() - 1000
        };

        let times_l: Vec<_> = times.iter().skip(l).copied().collect();
        let sum_l: f32 = times_l.iter().sum();
        let mean_ms_l = sum_l * 100f32 / times_l.len() as f32;
        progress.set_message(format!(
            "{mean_ms:.4}ms {mean_ms_l:.4}ms {rps:.2} {e:6}/{t:6}"
        ));
    }
}

async fn asl(
    cmd: &Asl,
    registration: &ClientRegistration,
    client: Client,
    access_token: &str,
) -> Result<()> {
    const N_TASKS: usize = 10;
    const N_MESSAGES: usize = 10;

    let access_token = access_token.to_string();
    let cmd = cmd.clone();
    let registration = registration.clone();
    benchmark(
        move || async move {
            let mut times = vec![];
            let mut start = Instant::now();
            let (cid, mut state) = asl_handshake(
                client.clone(),
                &registration,
                cmd.target_url()?,
                &access_token,
            )
            .await?;
            times.push(Instant::now().duration_since(start).as_secs_f32());

            let inner = encode_http_request(
                &registration,
                Method::GET,
                cmd.target_url()?
                    .join("/.well-known/oauth-protected-resource")?
                    .as_str()
                    .parse()?,
                &access_token,
            )?;

            for req_ctr in 0..N_MESSAGES {
                start = Instant::now();
                let _ = asl_request(
                    &registration,
                    client.clone(),
                    &access_token,
                    cmd.target_url()?,
                    &cid,
                    &mut state,
                    req_ctr as u64,
                    &inner,
                )
                .await?;
                times.push(Instant::now().duration_since(start).as_secs_f32());
            }

            Ok(times)
        },
        N_TASKS,
    )
    .await;
    Ok(())
}

async fn curl(
    args: &Args,
    cmd: &Curl,
    registration: &ClientRegistration,
    access_token: &str,
) -> Result<()> {
    let dpop = create_dpop_proof(
        registration,
        &cmd.request,
        &cmd.target,
        Some(Base64UrlUnpadded::encode_string(&Sha256::digest(
            access_token,
        ))),
        None,
    )?;
    let mut curl_args = vec![
        "--header".to_string(),
        format!("authorization: Bearer {access_token}"),
        "--header".to_string(),
        format!("dpop: {dpop}"),
        "--request".to_string(),
        cmd.request.clone(),
    ];
    if args.insecure {
        curl_args.push("--insecure".to_string());
    }
    curl_args.append(&mut cmd.rest.clone());
    curl_args.push(cmd.target.clone());
    // exec does not return on success
    Err(Command::new("curl").args(&curl_args).exec())?
}

#[tokio::main(worker_threads = 8)]
async fn main() -> Result<()> {
    let args: Args = parse_args_or_exit(argp::DEFAULT);
    let client: Client = ClientBuilder::new()
        .use_rustls_tls()
        .danger_accept_invalid_certs(args.insecure)
        .build()?;
    let registration = register_client(args.client_registration_url()?, &client).await?;

    let nonce = get_nonce(args.nonce_url()?, &client).await?;
    let smcb = create_smcb_token(
        &args.p12_path(),
        &args.p12_pass(),
        args.auth_url()?,
        nonce.clone(),
        &registration,
    )
    .await?;

    let access_token = exchange_access_token(
        args.token_url()?,
        nonce.clone(),
        &registration,
        &smcb,
        &client,
    )
    .await?;
    match &args.command {
        Subcommand::Curl(cmd) => curl(&args, cmd, &registration, &access_token).await,
        Subcommand::Asl(cmd) => asl(cmd, &registration, client, &access_token).await,
    }
}
