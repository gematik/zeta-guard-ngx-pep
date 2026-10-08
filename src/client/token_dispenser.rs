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

use std::fmt::Debug;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use asl::client::SessionState;
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use bytes::Bytes;
use http::Method;
use http::header::{COOKIE, SET_COOKIE};
use jsonwebtoken::dangerous::insecure_decode;
use jsonwebtoken::{Algorithm, EncodingKey, Header, TokenData, get_current_timestamp};
use p12_keystore::{KeyStore, KeyStoreEntry};
use reqwest::cookie::{CookieStore, Jar};
use reqwest::{RequestBuilder, Url};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::client::asl::asl_handshake;
use crate::client::{
    ClientRegistration, KEY, SHARED_CLIENT, TokenExchangeResponse, create_client_assertion,
    create_client_assertion_with_attestation, create_smcb_token, get_nonce, send_retry_stale,
};
use crate::conf::end_of_quarter_utc;
use crate::typify::{AccessTokenPayload, DPoPProofJwtPayload};

pub fn popp_token_payload(actor_id: &str, iat: u64, patient_proof_time: u64) -> Value {
    json!({
      "actorId": actor_id,
      "actorProfessionOid": "1.2.276.0.76.4.32",
      "iat": iat,
      "insurerId": "109500969",
      "iss": "https://popp.example.com",
      "patientId": "X110639491",
      "patientProofTime": patient_proof_time,
      "proofMethod": "ehc-practitioner-user-x509",
      "version": "1.0.0"
    })
}

pub fn create_dpop_proof(
    registration: &ClientRegistration,
    htm: &str,
    htu: &str,
    ath: Option<&str>,
    nonce: Option<&str>,
) -> Result<String> {
    registration.sign_jwt(
        Some("dpop+jwt".to_string()),
        DPoPProofJwtPayload {
            htm: htm.to_string(),
            htu: htu.to_string(),
            ath: ath.map(|x| x.to_string()),
            nonce: nonce.map(|x| x.to_string()),
            iat: get_current_timestamp().try_into()?,
            jti: Uuid::new_v4().to_string(),
        },
        &KEY,
    )
}

pub async fn create_popp_token(
    popp_key: &PoPPKey,
    actor_id: &str,
    iat: u64,
    patient_proof_time: u64,
) -> Result<String> {
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("vnd.telematik.popp+jwt".to_string());
    header.kid = Some(popp_key.kid.clone());
    let ee = Base64::encode_string(&popp_key.cert);
    header.x5c = Some(vec![ee]);
    let payload = popp_token_payload(actor_id, iat, patient_proof_time);
    let key = EncodingKey::from_ec_der(&popp_key.key);
    Ok(jsonwebtoken::encode(&header, &payload, &key)?)
}

#[derive(Debug, Clone)]
pub enum Lost {
    /// user lost both access and refresh tokens, and should do a full token exchange on .tokens()
    RefreshToken,
    /// user lost only access tokens, and should do a refresh on .tokens()
    AccessToken,
    Not,
}

#[derive(Debug, Clone)]
pub struct Tokens {
    pub registration: ClientRegistration,
    pub access_token: String,
    pub access_token_data: TokenData<AccessTokenPayload>,
    pub refresh_token: String,
    pub popp: String,
    pub popp_exp: u64,
    pub lost: Lost,
}

impl Tokens {
    pub fn valid_dpop_proof(&self, htm: &str, htu: &str) -> Result<String> {
        create_dpop_proof(
            &self.registration,
            htm,
            htu,
            Some(&Base64UrlUnpadded::encode_string(&Sha256::digest(
                &self.access_token,
            ))),
            None,
        )
    }

    pub fn request_builder(
        &self,
        method: Method,
        jar: &Jar,
        url: Url,
        dpop: &str,
        forwarded_for: Option<&str>,
    ) -> Result<RequestBuilder> {
        let host = url.host().context("url needs a host")?;
        let hostport = match url.port() {
            Some(port) => format!("{}:{}", host, port),
            None => host.to_string(),
        };

        let mut request = SHARED_CLIENT
            .request(method, url.clone())
            .header("host", hostport)
            .bearer_auth(&self.access_token)
            .header("dpop", dpop);
        if let Some(forwarded_for) = forwarded_for {
            request = request.header("forwarded", format!("for=\"{}\"", forwarded_for))
        }
        if let Some(c) = jar.cookies(&url) {
            request = request.header(COOKIE, c);
        }
        Ok(request)
    }

    /// returns a RequestBuilder with valid dpop header and a forwarded value derived from the
    /// token's ip_address claim, to not trigger no-travel enforcement in integration tests
    pub fn valid_get(&self, jar: &Jar, url: Url) -> Result<RequestBuilder> {
        self.request_builder(
            Method::GET,
            jar,
            url.clone(),
            &self.valid_dpop_proof("GET", url.as_str())?,
            Some(&self.access_token_data.claims.ip_address),
        )
    }

    /// see [`Self::get_with_dpop`]
    pub fn valid_post(&self, jar: &Jar, url: Url) -> Result<RequestBuilder> {
        self.request_builder(
            Method::POST,
            jar,
            url.clone(),
            &self.valid_dpop_proof("POST", url.as_str())?,
            Some(&self.access_token_data.claims.ip_address),
        )
    }
}

pub struct AslSession {
    pub jar: Jar,
    pub cid: String,
    pub state: SessionState,
    pub reg_ctr: u64,
    pub exp: u64,
}

pub struct SessionDispenser {
    pub jar: Jar,
    pub token_dispenser: TokenDispenser,
    pub session: Option<AslSession>,
}

impl SessionDispenser {
    pub fn new(token_dispenser: &TokenDispenser) -> Self {
        let jar = Jar::default();
        SessionDispenser {
            jar,
            token_dispenser: token_dispenser.clone(),
            session: Default::default(),
        }
    }

    pub async fn asl_session(&mut self, target: Url) -> Result<&mut AslSession> {
        let now = get_current_timestamp();
        if self
            .session
            .as_mut()
            .is_none_or(|session| session.exp.saturating_sub(now) < MIN_VALIDITY)
        {
            let tokens = self.token_dispenser.tokens().await?;
            let asl_session = asl_handshake(&tokens, target).await?;
            self.session.replace(asl_session);
        }
        Ok(self.session.as_mut().unwrap())
    }
}

#[derive(Clone)]
pub struct SmcBKey {
    pub cert: Bytes,
    pub key: Bytes,
}

impl Debug for SmcBKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmcBIdentity")
            .field("cert", &format!("({}b)", self.cert.len()))
            .field("key", &format!("({}b)", self.key.len()))
            .finish()
    }
}

impl SmcBKey {
    pub fn from_bytes(bytes: &[u8], pass: &str) -> Result<Self> {
        let keystore = KeyStore::from_pkcs12(bytes, pass)?;
        let (_alias, chain) = keystore.private_key_chain().context("private_key_chain")?;
        let cert = Bytes::copy_from_slice(chain.chain()[0].as_der());
        let key = Bytes::copy_from_slice(chain.key());
        Ok(SmcBKey { cert, key })
    }
    pub async fn from_path(path: &Path, pass: &str) -> Result<Self> {
        let mut buf = Vec::new();
        File::open(path).await?.read_to_end(buf.as_mut()).await?;
        SmcBKey::from_bytes(&buf, pass)
    }
}

#[derive(Clone)]
pub struct PoPPKey {
    pub cert: Bytes,
    pub kid: String,
    pub key: Bytes,
}

impl Debug for PoPPKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoPPIdentity")
            .field("kid", &self.kid)
            .field("key", &format!("({}b)", self.key.len()))
            .finish()
    }
}

impl PoPPKey {
    pub async fn from_path(path: &Path, pass: &str, alias: &str) -> Result<Self> {
        let mut buf = Vec::new();
        File::open(path).await?.read_to_end(buf.as_mut()).await?;

        let keystore = KeyStore::from_pkcs12(&buf, pass)?;
        if let Some(KeyStoreEntry::PrivateKeyChain(chain)) = keystore.entry(alias) {
            let kid = alias.to_string();
            let cert = Bytes::copy_from_slice(chain.chain()[0].as_der());
            let key = Bytes::copy_from_slice(chain.key());

            Ok(PoPPKey { cert, kid, key })
        } else {
            bail!(
                "no PrivateKeyChain found at {} (alias={})",
                path.display(),
                alias,
            )
        }
    }
}

/// Push button, receive tokens
#[derive(Debug, Clone)]
pub struct TokenDispenser {
    pub jar: Arc<Jar>,
    pub registration: ClientRegistration,
    pub smcb_key: SmcBKey,
    pub host: String,
    pub nonce_url: Url,
    pub token_url: Url,
    pub popp_key: PoPPKey,
    pub tokens: Arc<RwLock<Option<Tokens>>>,
}

/// Result of a single token-exchange attempt: either the tokens, or a
/// retryable in-flight-expiry rejection of the client assertion.
enum ExchangeOutcome {
    Ok((String, String)),
    RetryableClientAuth(String),
}

const MIN_VALIDITY: u64 = 10; // seconds, for AT,RT,PoPP, and ASL sessions

impl TokenDispenser {
    pub fn new(
        jar: Arc<Jar>,
        registration: ClientRegistration,
        smcb_key: SmcBKey,
        host: String,
        nonce_url: Url,
        token_url: Url,
        popp_key: PoPPKey,
    ) -> Self {
        let tokens = Arc::new(RwLock::new(None));
        TokenDispenser {
            jar,
            registration,
            smcb_key,
            host,
            nonce_url,
            token_url,
            popp_key,
            tokens,
        }
    }

    async fn exchange_access_token(
        &self,
        refresh_token: Option<String>,
    ) -> Result<(String, String)> {
        // The client assertion is short-lived, so a request that stalls in
        // flight (tail latency, GC, checkpoint) can arrive after its `exp` and
        // be rejected with `invalid_client / Token is not active`. Retry that
        // one case once with a freshly-minted assertion. Kept narrow so genuine
        // auth failures still surface immediately.
        const MAX_ATTEMPTS: usize = 2;
        for attempt in 1..=MAX_ATTEMPTS {
            match self
                .try_exchange_access_token(refresh_token.as_deref())
                .await?
            {
                ExchangeOutcome::Ok(tokens) => return Ok(tokens),
                ExchangeOutcome::RetryableClientAuth(_) if attempt < MAX_ATTEMPTS => continue,
                ExchangeOutcome::RetryableClientAuth(err) => {
                    bail!("{err}")
                }
            }
        }
        unreachable!("retry loop returns on the final attempt")
    }

    /// One attempt of the token exchange / refresh. Mints a fresh assertion
    /// (fresh `now`) each call, so retries get a new validity window.
    async fn try_exchange_access_token(
        &self,
        refresh_token: Option<&str>,
    ) -> Result<ExchangeOutcome> {
        // form-urlencoded (RFC 6749 token endpoint encoding); also keeps the
        // body replayable so send_retry_stale can actually retry this request
        let mut form: Vec<(&str, String)> = vec![
            ("client_id", self.registration.client_id.clone()),
            (
                "requested_token_type",
                "urn:ietf:params:oauth:token-type:refresh_token".into(),
            ),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
            ),
        ];

        let now = get_current_timestamp();
        match refresh_token {
            Some(refresh_token) => {
                let client_assertion = create_client_assertion(&self.registration, now)?;
                form.push(("grant_type", "refresh_token".into()));
                form.push(("refresh_token", refresh_token.to_string()));
                form.push(("client_assertion", client_assertion.clone()));
            }
            None => {
                let nonce = get_nonce(self.nonce_url.clone(), &self.jar).await?;

                let smcb = create_smcb_token(
                    &self.smcb_key,
                    self.token_url.clone(),
                    nonce.clone(),
                    &self.registration,
                    now,
                )
                .await?;
                // oauth protected resource / resource -> wird von OPA geprüft
                let opr: Url = format!("https://{}", self.host).parse()?;
                let opr = opr.join("/.well-known/oauth-protected-resource")?;
                let mut request = SHARED_CLIENT.get(opr.clone());

                if let Some(c) = self.jar.cookies(&opr) {
                    request = request.header(COOKIE, c);
                }
                let response = send_retry_stale(request).await?;

                self.jar.set_cookies(
                    &mut response.headers().get_all(SET_COOKIE).iter(),
                    &self.token_url,
                );

                let opr: Value = response.json().await?;
                let resource = opr.get("resource").expect("resource");

                let client_assertion = create_client_assertion_with_attestation(
                    nonce.clone(),
                    &self.registration,
                    now,
                )?;

                form.push((
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange".into(),
                ));
                form.push(("scope", "zero:audience".into()));
                form.push(("audience", resource.as_str().unwrap().to_string()));
                form.push((
                    "subject_token_type",
                    "urn:ietf:params:oauth:token-type:jwt".into(),
                ));
                form.push(("subject_token", smcb.to_string()));
                form.push(("client_assertion", client_assertion.clone()));
            }
        }

        let dpop = create_dpop_proof(
            &self.registration,
            "POST",
            self.token_url.as_str(),
            None,
            None,
        )?;

        let mut request = SHARED_CLIENT.post(self.token_url.clone());
        if let Some(c) = self.jar.cookies(&self.token_url) {
            request = request.header(COOKIE, c);
        }

        let response = send_retry_stale(
            request
                .form(&form)
                .header("accept", "application/json")
                .header("DPoP", dpop),
        )
        .await?;

        self.jar.set_cookies(
            &mut response.headers().get_all(SET_COOKIE).iter(),
            &self.token_url,
        );

        let token: TokenExchangeResponse = response.json().await?;

        // Retry only the in-flight-expiry case; everything else surfaces.
        if token.access_token.is_none()
            && token.error.as_deref() == Some("invalid_client")
            && token
                .error_description
                .as_deref()
                .is_some_and(|d| d.contains("Token is not active"))
        {
            return Ok(ExchangeOutcome::RetryableClientAuth(serde_json::to_string(
                &token,
            )?));
        }

        let access_token = token.access_token()?;
        let refresh_token = token
            .refresh_token
            .ok_or(anyhow!("No refresh_token received"))?;

        Ok(ExchangeOutcome::Ok((access_token, refresh_token)))
    }

    pub async fn tokens(&self) -> Result<Tokens> {
        let now = get_current_timestamp();

        if let Some(s) = self.tokens.read().await.clone()
            && let remain_at = s.access_token_data.claims.exp.saturating_sub(now as i64)
            && let remain_popp = s.popp_exp.saturating_sub(now)
            && remain_at >= MIN_VALIDITY as i64
            && remain_popp >= MIN_VALIDITY
            && matches!(s.lost, Lost::Not)
        {
            return Ok(s);
        }

        let mut state = self.tokens.write().await;

        let refresh_token = match state.as_ref() {
            Some(s) => {
                let token_data: TokenData<Value> = insecure_decode(&s.refresh_token)?;
                token_data
                    .claims
                    .get("exp")
                    .and_then(Value::as_i64)
                    .is_some_and(|exp| {
                        exp.saturating_sub(now as i64) >= MIN_VALIDITY as i64
                            && !matches!(s.lost, Lost::RefreshToken)
                    })
                    .then(|| s.refresh_token.clone())
            }
            None => None,
        };

        let (access_token, refresh_token) = self.exchange_access_token(refresh_token).await?;

        let registration = self.registration.clone();
        let access_token_data: TokenData<AccessTokenPayload> =
            insecure_decode(access_token.clone())?;

        let (popp, popp_exp) = if let Some(state) = state.as_ref()
            && state.popp_exp.saturating_sub(now) >= MIN_VALIDITY
        {
            (state.popp.clone(), state.popp_exp)
        } else {
            let popp =
                create_popp_token(&self.popp_key, &access_token_data.claims.sub, now, now).await?;
            // assuming PoppValidity::Quarter
            let popp_exp = end_of_quarter_utc(now as i64) as u64;
            (popp, popp_exp)
        };

        let new_tokens = Tokens {
            registration,
            access_token,
            access_token_data,
            refresh_token,
            popp,
            popp_exp,
            lost: Lost::Not,
        };

        state.replace(new_tokens.clone());
        Ok(new_tokens)
    }

    /// simulate lost tokens, effective on next call to .tokens()
    pub async fn lose_tokens(&self, lost: Lost) {
        let mut guard = self.tokens.write().await;
        *guard = guard.clone().map(|mut tokens| {
            tokens.lost = lost;
            tokens
        });
    }

    pub fn new_session_dispenser(&self) -> SessionDispenser {
        SessionDispenser::new(self)
    }
}
