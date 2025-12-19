/*-
 * #%L
 * ngx_pep
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH
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
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

use anyhow::{Context, Result, anyhow, bail};
use argp::{FromArgs, parse_args_or_exit};
use asl::client::{self, HandshakeKeys};
use asl::{Environment, raw_keys_from_bytes};
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use futures::channel::mpsc::channel;
use futures::{SinkExt, StreamExt};
use http::{Method, Request};
use jsonwebtoken::dangerous::insecure_decode;
use jsonwebtoken::jwk::{Jwk, PublicKeyUse};
use jsonwebtoken::{Algorithm, EncodingKey, Header, TokenData, get_current_timestamp};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use p12_keystore::KeyStore;
use reqwest::{Client, ClientBuilder, RequestBuilder, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::time::Instant;
use uuid::Uuid;

#[allow(dead_code, clippy::all)]
mod typify {
    include!(concat!(env!("OUT_DIR"), "/typify.rs"));
}
use typify::ClientAssertionJwtPayload;

use crate::typify::DPoPProofJwtPayload;

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

#[derive(Deserialize, Debug)]
struct ClientRegistrationAccessToken {
    aud: String,
}

#[derive(Deserialize, Debug, Clone)]
struct ClientRegistrationJwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize, Debug, Clone)]
struct ClientRegistration {
    client_id: String,
    jwks: ClientRegistrationJwks,
    registration_access_token: String,
}

impl ClientRegistration {
    pub fn sign_jwt<T: Serialize>(
        &self,
        typ: Option<String>,
        payload: T,
        key: &EncodingKey,
    ) -> Result<String> {
        let mut header = Header::new(Algorithm::ES256);
        header.typ = typ.or(Some("JWT".to_string()));
        let n_keys = self.jwks.keys.len();
        if n_keys != 1 {
            bail!(
                "n_keys invalid; want 1, got {n_keys} — {:?}",
                self.jwks.keys
            );
        }
        let jwk = &self.jwks.keys[0];
        header.jwk = Some(jwk.clone());

        Ok(jsonwebtoken::encode(&header, &payload, key)?)
    }

    pub fn registration_access_token(&self) -> Result<TokenData<ClientRegistrationAccessToken>> {
        insecure_decode(&self.registration_access_token).context("registration_access_token")
    }
}

#[derive(Deserialize, Debug)]
struct TokenExchangeResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

impl TokenExchangeResponse {
    fn access_token(&self) -> Result<String> {
        self.access_token
            .as_ref()
            .ok_or_else(|| {
                anyhow!(
                    "error={}, error_description={}",
                    self.error.as_ref().unwrap_or(&"None".to_string()),
                    self.error_description
                        .as_ref()
                        .unwrap_or(&"None".to_string())
                )
            })
            .cloned()
    }
}

static PEM: LazyLock<Vec<u8>> =
    LazyLock::new(|| include_bytes!("../tests/ec-private.pem").to_vec());

static KEY: LazyLock<EncodingKey> = LazyLock::new(|| EncodingKey::from_ec_pem(&PEM).expect("ec"));

fn client_registration_request(jwk: Jwk) -> Value {
    json!({
     "token_endpoint_auth_method": "private_key_jwt",
     "token_endpoint_auth_signing_alg": "ES256",
     "dpop_bound_access_tokens": true,
     "grant_types": [
       "refresh_token",
       "urn:ietf:params:oauth:grant-type:token-exchange",
     ],
     "response_types": [
       "token"
     ],
     "client_name": "𝛇-Guard client",
     "jwks": {
       "keys": [
         jwk
       ]
     }
    })
}

async fn register_client(args: &Args, client: &Client) -> Result<ClientRegistration> {
    let mut jwk = Jwk::from_encoding_key(&KEY, Algorithm::ES256)?;
    jwk.common.public_key_use = Some(PublicKeyUse::Signature);
    jwk.common.key_id = Some(jwk.thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256));

    let request = client_registration_request(jwk);

    let registration: ClientRegistration = client
        .post(args.client_registration_url()?)
        .json(&request)
        .header("accept", "application/json")
        .send()
        .await?
        .json()
        .await?;

    Ok(registration)
}

async fn get_nonce(args: &Args, client: &Client) -> Result<String> {
    client
        .get(args.nonce_url()?)
        .send()
        .await?
        .text()
        .await
        .context("getting nonce")
}

// Can't use jsonwebtoken or bp256 (missing ecdsa impl.), so we use openssl here…
fn sign_jwt_brainpool<T: Serialize>(header: &Header, claims: &T, key: &[u8]) -> Result<String> {
    // assume ES256, even though this is not true (ES256 implies p256 normally)
    if header.alg != Algorithm::ES256 {
        bail!("alg invalid; want ES256, got {:?}", header.alg);
    }

    let header = serde_json::to_vec(header)?;
    let claims = serde_json::to_vec(claims)?;

    let enc_header = Base64UrlUnpadded::encode_string(&header);
    let enc_claims = Base64UrlUnpadded::encode_string(&claims);
    let message = format!("{enc_header}.{enc_claims}");

    let key = PKey::private_key_from_der(key)?;

    let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
    signer.update(message.as_bytes())?;
    let der_sig = signer.sign_to_vec()?;

    // DER → (r || s)
    let sig = EcdsaSig::from_der(&der_sig)?;
    let r = sig.r();
    let s = sig.s();

    // 256b cipher
    const NBYTES: usize = 32;
    let pad: i32 = NBYTES.try_into()?;
    let mut r = r.to_vec_padded(pad)?;
    let mut s = s.to_vec_padded(pad)?;

    let mut raw = Vec::with_capacity(2 * NBYTES);
    raw.append(&mut r);
    raw.append(&mut s);

    let enc_sig = Base64UrlUnpadded::encode_string(&raw);

    Ok(format!("{message}.{enc_sig}"))
}

async fn create_smcb_token(
    args: &Args,
    registration: &ClientRegistration,
    client: &Client,
) -> Result<String> {
    let mut buf = vec![];

    File::open(args.p12_path())
        .await?
        .read_to_end(&mut buf)
        .await?;
    let keystore = KeyStore::from_pkcs12(&buf, &args.p12_pass())?;
    let (_alias, chain) = keystore.private_key_chain().context("private_key_chain")?;
    // n.b. *not* base64-url, and Keycloak seems to require padding as well. See also:
    // https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6
    let ee = Base64::encode_string(chain.chain()[0].as_der());

    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("JWT".to_string());
    header.x5c = Some(vec![ee]);

    let now = get_current_timestamp();
    let id = json!({
        "jti": Uuid::new_v4().to_string(),
        "typ": "Bearer",
        "iss": registration.client_id,
        "azp": "target-client",
        "sub": "1-10.3.9876540000.10.246",
        "aud": [
            args.auth_url()?
        ],
        "exp": now + 60,
        "iat": now,
        "nonce": get_nonce(args, client).await?,
    });
    sign_jwt_brainpool(&header, &id, chain.key())
}

fn create_dpop_proof(
    registration: &ClientRegistration,
    htm: &str,
    htu: &str,
    ath: Option<String>,
    nonce: Option<String>,
) -> Result<String> {
    registration.sign_jwt(
        Some("dpop+jwt".to_string()),
        DPoPProofJwtPayload {
            htm: htm.to_string(),
            htu: htu.to_string(),
            ath,
            nonce,
            iat: get_current_timestamp().try_into()?,
            jti: Uuid::new_v4().to_string(),
        },
        &KEY,
    )
}

fn create_client_assertion(registration: &ClientRegistration) -> Result<String> {
    registration.sign_jwt(
        None,
        ClientAssertionJwtPayload {
            aud: vec![registration.registration_access_token()?.claims.aud],
            client_statement: None,
            exp: (get_current_timestamp() + 60).try_into().unwrap(),
            iss: registration.client_id.clone(),
            jti: Uuid::new_v4().to_string(),
            sub: registration.client_id.clone(),
        },
        &KEY,
    )
}

async fn exchange_access_token(
    args: &Args,
    registration: &ClientRegistration,
    smcb: &str,
    client: &Client,
) -> Result<String> {
    let client_assertion = create_client_assertion(registration)?;
    let mut fields = HashMap::new();
    fields.insert(
        "grant_type",
        "urn:ietf:params:oauth:grant-type:token-exchange",
    );
    fields.insert("client_id", &registration.client_id);
    fields.insert("scope", "zero:audience");
    fields.insert("subject_token_type", "urn:ietf:params:oauth:token-type:jwt");
    fields.insert("subject_token", smcb);
    fields.insert(
        "requested_token_type",
        "urn:ietf:params:oauth:token-type:access_token",
    );
    fields.insert(
        "client_assertion_type",
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    );
    fields.insert("client_assertion", &client_assertion);

    let dpop = create_dpop_proof(
        registration,
        "POST",
        args.token_url()?.as_str(),
        None,
        Some(get_nonce(args, client).await?),
    )?;

    let token: TokenExchangeResponse = client
        .post(args.token_url()?)
        .form(&fields)
        .header("accept", "application/json")
        .header("DPoP", dpop)
        .send()
        .await?
        .json()
        .await?;
    let access_token = token.access_token()?;
    Ok(access_token)
}

fn new_post_request(
    registration: &ClientRegistration,
    client: &Client,
    access_token: &str,
    url: Url,
) -> Result<RequestBuilder> {
    let dpop = create_dpop_proof(
        registration,
        "POST",
        url.as_str(),
        Some(Base64UrlUnpadded::encode_string(&Sha256::digest(
            access_token,
        ))),
        None,
    )?;
    Ok(client
        .post(url)
        .bearer_auth(access_token)
        .header("dpop", &dpop))
}

fn encode_http_request(req: Request<&[u8]>) -> Vec<u8> {
    let (parts, body) = req.into_parts();
    let mut buf = Vec::new();

    write!(
        &mut buf,
        "{} {} HTTP/1.1\r\n",
        parts.method,
        parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
    )
    .unwrap();

    for (name, value) in &parts.headers {
        write!(&mut buf, "{}: {}\r\n", name, value.to_str().unwrap()).unwrap();
    }

    buf.extend_from_slice(b"\r\n");
    buf.extend_from_slice(body);
    buf
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
                    // Err(e) => println!("{e}"),
                    Err(_e) => tx.send(None).await.expect("send"),
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
    let access_token = access_token.to_string();
    let cmd = cmd.clone();
    let registration = registration.clone();
    let client = client.clone();

    const CLIENT_ECDH_SK_HEX: &str =
        "3bdbaa604b9f5be68d938b543464f1515d24535974e0cbeb2c7779b35e9a6a93";
    const CLIENT_ECDH_PK_HEX: &str = "be58f717ff585fd57a21ceaa17f9153180e379048947ad22820e1f359b52019fb9a8dfce2b054f426db806387f3e918a8daa9d286caf54e8ff37e1165ead5cd8";
    const CLIENT_PQC_SK_HEX: &str = "fba750a955261d6b62972c4dcbd06182c7a355b946bfc0b44988337a15bcbd800b8a6a908b71437b5a8ca1e95b81288c8e2922078021d48a17e31247386352b5c99eed537b9560504a450dc2c6613b21a9567c3a8c9430099bcdbc9721ae8c82529ba05b6c349218bc96a9100ec59bd8e939b6116065a28ac3781db28ab366a47eb133c1b559310ec542ed6498eea99d28489090da001979c126439689f82da13ca711a5a9d1e36d77521b7bcb89e630035b7817d650c2d7f9a0d218bd2b570934f0618ae0ccc6c4cddd49cb15e214bb48483ee23d2089b81a377f24e21b63615825dc2789284149736c95e6b2c7c189c2733bf751c2abfa87d142b680091d0bc577161843a1573f47d70909f84ce0db3b0c670a55886b40955bb9fa408a433871432210666ffba6a0594937725626077222555681075c7c877251664a6ab2050a4417aa81d41edbc4585a8700501468f9c1adad39a0ca3b072a7b050048cc858385014ab4d5029bebc629a5a06092f2019920b1f019cddae12f49b796bab9b4d28bac89161b3180567efcca575a397775b76a591596446719a4384fa510cea861524b938d02b532d29cf803995db21847655cf03a3465a956d3d709f746c78ce91a2e628d4938abb9c332d1e49e132a93f9362b8b734e386ab5db3a7e2109c5ada23354317852aa7f03b13b6cb2b00480b1ad589e2f007292f9054af86ba13a9d627497930210bdf5479ce339f6008def86637893581a1abd31f01b9dc630f905caae7113421816a547c97a42632ba67581685ff6777c993ac781d151555b6806d1b2b47ccd4c971e4c75a4e1b9112c9163ccb4a9a5d6734c113ea4e8ba73384c7572cb9d3b1c97a0be3f4b037fc28b248cce5ae2017c57c2b9d61dce206c939204adec1555a186194067bde76248eb1f57855a070c1118a327a850bbf201648eac02ee8b7367355b48964168f81150ca64fc709033a8ae93d111930927f54bb75764c5e353cd7114b14a42cbda6c42daa0471b975618ac9e0e07b794d01a28301037b90553ba045c264cd5f2a264e98cf6ea34ed55498bd26b57a88b2ba7629751aa34f8c6d7e6c04c583bdfa41d2eab0636f7bd67e709268821110a2633470d4abcad59c1693873b8442301d9a09ea3870bcfb68bbbb44bb1dc66ff26c392495f475010759c3940a71af401c731f6a5d85cabb0597c9cf6b265e28a20c81d6ac83cb0babbcab4779f267cd53928d7faa7f3736ce96958bbc75d4215b2691370ffc35565135726202a7859485af1ce08bcc8aef0729cbb3de590ccaf3622a5e333f8b06e551b26980a9e26b5ae4de65f2fe14456603236c5585d7ccb0696936ab9c09cf73465b0b7ddf05df170421e5828f48aa993734363cb8d03b13ef173659d2767bdf5a1dbc87101117c4a04159cec3cbb64c9866c4b54431658d00a182c355616c6980511574c959815657099b5c1bb7222680aa610bdd5e5241df32ce03406df20588c582da9452c43a97a76d51bc25185773c327e327f64db9e7d640bfab7c6de17660744727da764e2a02d710190f827a6fdd950ad0674af5723eee50b7343653138aa858a69643a5975b314cce6826ba03ca21a8ca3356f6f5b12d9e5be87854b4b4b41efa89a84698f9d968dd9ac40d818c7853aaa19a7c29a30667f5a6a158b69293bad8fe388825b829348ce171a8a2768a37fac97f36b7320493a74b9cf032abd3460bc00a4cac0715f1813878328123ae537ebfb1ce278b9bd5a09c36a90ada07b40c818be86c039fc7dcdfaa5d2373726a153cc901a8d8b3906988370d731c83c923d094028329617a103b28122d0962b5847a5d4ebb12e5951f5891d31696d5ff2a2bd5a1ff6c101c55971f7b31b0ef7c0f71814289b97c6670a3d173dd61cb399a61fc94142340421274cb40f450f5881096979826be463aca1a5e8eca073b1cc44bacea6ec9b6896cf7f8b50c86647e6f2b2f43a83d316b079237901424db9441e7ee6cb0e5a29c0595d63602e3e5b062ad35ff936b071d00b93733c51d0a966cc141d715f21d8b61209adee3362cb08ca570361ae138ba3291d5bc22030e369dd47c4309c39e8e64111f446bfb585e82b6ea2627c00fd4e8625a19c82af60bb945cd11530149eb2f44075f98ddd893b0a81686f8847d95749a8daa2e2ccb6909b99e73001f1115c65491c66865cb47ab53c9435655780caa8026040452c52595a72794b426422cc3798358dd2470e91f69a7bc601d3956c437b4c32f602b6437adc229583554c69644d359a461a2b60b22734544963c927705bd1900ad30f4b749e8d0322e9708069e550700587565837d1c15adaa1ca2df43c580cb12bcb531137065a509a5901c606a6734af8cf5b5aa7b6a66332b4172efccd7a062cfe1ca68ed3138a6c1beb9a2e391accdc041fe3a4a3a5eccd069a3b84528338e5c4ca8b2d01e3b8c562a848a70f096b18931355a941ccf6576af5246cbb17359cc245c7db708f5a65a3331237746a23bc5662e15339630decba951270568b8083a0387a99448be199af14712dbd27a1ed08a66ab08edbe2c4e772cabed6b9f2589f74d44a8ac594886418a6675371c4a96e10a2cd36916594b5fa71478073827571999c8859c1a449ea4aab6bf2a759500d3d725a81868bad4c5cbb64b5b676c951614b55e694ac011275eab761f6c74feb780c1cc6db32505665115c2119cb2b44d4a9cf756c3905336136b9898723b82876b0ce49c98bb082e8fbc3fb1a71b8b02bee8475e4cb6b67700ade0315580c4922ca61d251a6123a8e921384e463af99fa4792fb3591a694f5bb0df4624de8b61fcb403022a12af5f88ba4a900b79cc9b1bb21d7034ed03b675920141744c9b55c08f5c76af5056d2a09a1e85962cf03483b863aeda91f7018b135b70de9765184719daa2136b28c1b1be7c4c510aeb0882f3e3aba33f12c25c334d36961769b3c8c62b75bf33d30246e532134ac332d1483b1ababbd7a03797c054635c76bd0bbc4bf287523e23958a0bb3ec652ce961f60143167462a8bdb02960b5d3e8a80bfb74320411a06e204e81907b701a1cdf88fc84784fc45313ca27a31226662cc424450361191b32ee24aafe69cae4602f4ca15fc3bcd80295268a72d6bbb0bf04c785fb3492da6c8e51ca283ac6b627b28c50c0c0b88ada9679750cb158bb9275999823b3c512573b825b1214ea4cdbeb3a66014857ec3b5716688b5629c8d05844775cd302c846e5a64322d4a1aaca3040604ad548a1b9e30d0c9b677b3fb04980d7c42ab141c672e2d7207254813dd0d0b85ec7ac50eb4fba09e2b40c11ee17d940f293857a840b3976bf27e452f59695578cd52c99edc4e7e867ff0ee15f658fa26399b028d";
    const CLIENT_PQC_PK_HEX: &str = "d9e5be87854b4b4b41efa89a84698f9d968dd9ac40d818c7853aaa19a7c29a30667f5a6a158b69293bad8fe388825b829348ce171a8a2768a37fac97f36b7320493a74b9cf032abd3460bc00a4cac0715f1813878328123ae537ebfb1ce278b9bd5a09c36a90ada07b40c818be86c039fc7dcdfaa5d2373726a153cc901a8d8b3906988370d731c83c923d094028329617a103b28122d0962b5847a5d4ebb12e5951f5891d31696d5ff2a2bd5a1ff6c101c55971f7b31b0ef7c0f71814289b97c6670a3d173dd61cb399a61fc94142340421274cb40f450f5881096979826be463aca1a5e8eca073b1cc44bacea6ec9b6896cf7f8b50c86647e6f2b2f43a83d316b079237901424db9441e7ee6cb0e5a29c0595d63602e3e5b062ad35ff936b071d00b93733c51d0a966cc141d715f21d8b61209adee3362cb08ca570361ae138ba3291d5bc22030e369dd47c4309c39e8e64111f446bfb585e82b6ea2627c00fd4e8625a19c82af60bb945cd11530149eb2f44075f98ddd893b0a81686f8847d95749a8daa2e2ccb6909b99e73001f1115c65491c66865cb47ab53c9435655780caa8026040452c52595a72794b426422cc3798358dd2470e91f69a7bc601d3956c437b4c32f602b6437adc229583554c69644d359a461a2b60b22734544963c927705bd1900ad30f4b749e8d0322e9708069e550700587565837d1c15adaa1ca2df43c580cb12bcb531137065a509a5901c606a6734af8cf5b5aa7b6a66332b4172efccd7a062cfe1ca68ed3138a6c1beb9a2e391accdc041fe3a4a3a5eccd069a3b84528338e5c4ca8b2d01e3b8c562a848a70f096b18931355a941ccf6576af5246cbb17359cc245c7db708f5a65a3331237746a23bc5662e15339630decba951270568b8083a0387a99448be199af14712dbd27a1ed08a66ab08edbe2c4e772cabed6b9f2589f74d44a8ac594886418a6675371c4a96e10a2cd36916594b5fa71478073827571999c8859c1a449ea4aab6bf2a759500d3d725a81868bad4c5cbb64b5b676c951614b55e694ac011275eab761f6c74feb780c1cc6db32505665115c2119cb2b44d4a9cf756c3905336136b9898723b82876b0ce49c98bb082e8fbc3fb1a71b8b02bee8475e4cb6b67700ade0315580c4922ca61d251a6123a8e921384e463af99fa4792fb3591a694f5bb0df4624de8b61fcb403022a12af5f88ba4a900b79cc9b1bb21d7034ed03b675920141744c9b55c08f5c76af5056d2a09a1e85962cf03483b863aeda91f7018b135b70de9765184719daa2136b28c1b1be7c4c510aeb0882f3e3aba33f12c25c334d36961769b3c8c62b75bf33d30246e532134ac332d1483b1ababbd7a03797c054635c76bd0bbc4bf287523e23958a0bb3ec652ce961f60143167462a8bdb02960b5d3e8a80bfb74320411a06e204e81907b701a1cdf88fc84784fc45313ca27a31226662cc424450361191b32ee24aafe69cae4602f4ca15fc3bcd80295268a72d6bbb0bf04c785fb3492da6c8e51ca283ac6b627b28c50c0c0b88ada9679750cb158bb9275999823b3c512573b825b1214ea4cdbeb3a66014857ec3b5716688b5629c8d05844775cd302c846e5a64322d4a1aaca3040604ad548a1b9e30d0c9b677b3fb04980d7c42ab141c";

    let (client_raw_pk, client_raw_sk) = raw_keys_from_bytes(
        &hex::decode(CLIENT_ECDH_SK_HEX).unwrap(),
        &hex::decode(CLIENT_ECDH_PK_HEX).unwrap(),
        &hex::decode(CLIENT_PQC_SK_HEX).unwrap(),
        &hex::decode(CLIENT_PQC_PK_HEX).unwrap(),
    )
    .unwrap();
    let client_keys = HandshakeKeys {
        pk: client_raw_pk,
        sk: client_raw_sk,
    };
    benchmark(
        move || async move {
            let mut times = vec![];

            let (state, m1) =
                client::initiate_handshake_with_keys(Environment::Testing, client_keys.clone())?;

            let mut start = Instant::now();
            let response = new_post_request(
                &registration,
                &client.clone(),
                &access_token,
                cmd.target_url()?.join("ASL/")?,
            )?
            .header("content-type", "application/cbor")
            .body(m1)
            .send()
            .await?;

            let cid: Vec<_> = response.headers().get_all("ZETA-ASL-CID").iter().collect();
            if cid.len() != 1 {
                bail!("cid.len() {} != 1", cid.len());
            }
            let cid = cid[0].to_str()?.to_string();
            let m2 = response.bytes().await?.to_vec().clone();
            times.push(Instant::now().duration_since(start).as_secs_f32());

            let (state, m3) = client::continue_handshake(state, &m2)?;

            start = Instant::now();
            let m4 = new_post_request(
                &registration,
                &client,
                &access_token,
                cmd.target_url()?.join(&cid)?,
            )?
            .header("content-type", "application/cbor")
            .body(m3)
            .send()
            .await?
            .bytes()
            .await?
            .to_vec();
            times.push(Instant::now().duration_since(start).as_secs_f32());

            let mut state = client::finish_handshake(state, &m4)
                .context(format!("finish_handshake, m4={}b", m4.len()))?;

            let inner = encode_http_request(
                http::Request::builder()
                    .method(Method::GET)
                    .uri("/.well-known/oauth-protected-resource")
                    .header("authorization", format!("Bearer {access_token}"))
                    .header(
                        "dpop",
                        create_dpop_proof(
                            &registration,
                            "GET",
                            "http://localhost/.well-known/oauth-protected-resource",
                            Some(Base64UrlUnpadded::encode_string(&Sha256::digest(
                                &access_token,
                            ))),
                            None,
                        )?,
                    )
                    .body(&[] as &[u8])
                    .context("request builder")?,
            );

            for req_ctr in 0..10 {
                let request = client::encrypt_request(&mut state, req_ctr, &inner)?;

                start = Instant::now();
                let response = new_post_request(
                    &registration,
                    &client,
                    &access_token,
                    cmd.target_url()?.join(&cid)?,
                )?
                .header("content-type", "application/octet-stream")
                .body(request)
                .send()
                .await?
                .bytes()
                .await?;
                times.push(Instant::now().duration_since(start).as_secs_f32());
                let response_bytes = client::decrypt_response(&state, req_ctr, &response)?;

                let mut headers = [httparse::EMPTY_HEADER; 128];
                let mut response = httparse::Response::new(&mut headers);
                let parse_status = response.parse(&response_bytes)?;

                if parse_status.is_partial() {
                    anyhow::bail!("partial response");
                }
                let header_len = parse_status.unwrap();
                let _body: Vec<u8> = response_bytes[header_len..].into();

                let status = response.code.expect("code");
                let reason = response.reason.expect("reason");
                if status != 200 {
                    bail!("{} {}", status, reason);
                }
            }

            Ok(times)
        },
        1,
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
    let registration = register_client(&args, &client).await?;
    let smcb = create_smcb_token(&args, &registration, &client).await?;
    let access_token = exchange_access_token(&args, &registration, &smcb, &client).await?;
    match &args.command {
        Subcommand::Curl(cmd) => curl(&args, cmd, &registration, &access_token).await,
        Subcommand::Asl(cmd) => asl(cmd, &registration, client, &access_token).await,
    }
}
