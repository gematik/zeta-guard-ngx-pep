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

use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{Context, bail};
use anyhow::{Result, anyhow};
use asn1_rs::FromDer;
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use http::header::{COOKIE, SET_COOKIE};
use jsonwebtoken::Algorithm;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::Header;
use jsonwebtoken::TokenData;
use jsonwebtoken::dangerous::insecure_decode;
use jsonwebtoken::jwk::{Jwk, PublicKeyUse, ThumbprintHash};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use p256::ecdsa::SigningKey;
use p256::pkcs8::der::EncodePem;
use p256::pkcs8::{DecodePrivateKey, EncodePublicKey, SubjectPublicKeyInfoRef};
use reqwest::cookie::{CookieStore, Jar};
use reqwest::{Client, ClientBuilder, RequestBuilder, Url};
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_json::json;
use sha2::Digest;
use sha2::Sha256;
use uuid::Uuid;
use x509_parser::der_parser::{Oid, oid};
use x509_parser::parse_x509_certificate;

use crate::client::asn1::AdmissionSyntax;
use crate::client::token_dispenser::SmcBKey;

pub mod asl;
mod asn1;
pub mod token_dispenser;

#[derive(Deserialize, Debug)]
pub struct ClientRegistrationAccessToken {
    iat: u64,
    aud: String,
}

#[derive(Deserialize, Debug, Clone)]
struct ClientRegistrationJwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ClientRegistration {
    pub client_id: String,
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
        // client-assertion-jwt.yaml / dpop-token.yaml allow only the mandatory public-key members
        // (kty/crv/x/y) in the embedded jwk. The server resolves the registered key by its RFC 7638
        // thumbprint (computed from those members only), so alg/kid/use are redundant here and must
        // be stripped to stay schema-compliant.
        let mut jwk = self.jwks.keys[0].clone();
        jwk.common.key_algorithm = None;
        jwk.common.key_id = None;
        jwk.common.public_key_use = None;
        header.jwk = Some(jwk);

        Ok(jsonwebtoken::encode(&header, &payload, key)?)
    }

    pub fn registration_access_token(&self) -> Result<TokenData<ClientRegistrationAccessToken>> {
        insecure_decode(&self.registration_access_token).context("registration_access_token")
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct TokenExchangeResponse {
    access_token: Option<String>,
    refresh_token: Option<String>,
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

static PEM: LazyLock<Vec<u8>> = LazyLock::new(|| include_bytes!("ec-private.pem").to_vec());

static KEY: LazyLock<EncodingKey> = LazyLock::new(|| EncodingKey::from_ec_pem(&PEM).expect("ec"));

fn ec_public_spki_der_from_pkcs8_pem(private_pem: &[u8]) -> Result<Vec<u8>> {
    let pem_str = std::str::from_utf8(private_pem)?;
    let signing_key = SigningKey::from_pkcs8_pem(pem_str)?;
    let verifying_key = signing_key.verifying_key();

    // X.509 SubjectPublicKeyInfo DER
    let spki_der = verifying_key.to_public_key_der()?.as_bytes().to_vec();
    Ok(spki_der)
}

static PUBLIC_KEY: LazyLock<Vec<u8>> =
    LazyLock::new(|| ec_public_spki_der_from_pkcs8_pem(&PEM).expect("ec public"));

fn ec_public_pem(spki_der: &[u8]) -> Result<String> {
    let spki = SubjectPublicKeyInfoRef::try_from(spki_der)?;
    let pem = spki.to_pem(p256::pkcs8::LineEnding::LF)?;
    Ok(pem)
}

static PUBLIC_KEY_PEM: LazyLock<String> =
    LazyLock::new(|| ec_public_pem(&PUBLIC_KEY).expect("ec public pem"));

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

pub async fn register_client(
    client_registration_url: Url,
    jar: &Jar,
) -> Result<ClientRegistration> {
    let mut jwk = Jwk::from_encoding_key(&KEY, Algorithm::ES256)?;
    jwk.common.public_key_use = Some(PublicKeyUse::Signature);
    jwk.common.key_id = Some(jwk.thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256));

    let mut request = SHARED_CLIENT.post(client_registration_url.clone());

    if let Some(c) = jar.cookies(&client_registration_url) {
        request = request.header(COOKIE, c);
    }

    let response = send_retry_stale(
        request
            .json(&client_registration_request(jwk))
            .header("accept", "application/json"),
    )
    .await?;

    jar.set_cookies(
        &mut response.headers().get_all(SET_COOKIE).iter(),
        &client_registration_url,
    );

    // decode via text so failures carry WHO answered what — a bare .json()
    // reduces an nginx 502 page or a KC error response to the useless
    // "expected value at line 1 column 1"
    let status = response.status();
    let body = response.text().await?;
    let snippet: String = body.chars().take(200).collect();
    if !status.is_success() {
        bail!("client registration: HTTP {status}: {snippet}");
    }
    let registration = serde_json::from_str(&body).with_context(|| {
        format!("client registration: decoding response (HTTP {status}): {snippet}")
    })?;
    Ok(registration)
}

pub async fn get_nonce(nonce_url: Url, jar: &Jar) -> Result<String> {
    let mut request = SHARED_CLIENT.get(nonce_url.clone());

    if let Some(c) = jar.cookies(&nonce_url) {
        request = request.header(COOKIE, c);
    }
    let response = send_retry_stale(request).await?;

    jar.set_cookies(
        &mut response.headers().get_all(SET_COOKIE).iter(),
        &nonce_url,
    );

    response.text().await.context("getting nonce")
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

const OID_ADMISSION: Oid = oid!(1.3.36.8.3.3);

pub fn admission_from_x509(der: &[u8]) -> Result<AdmissionSyntax<'_>> {
    let (_, cert) = parse_x509_certificate(der).context("parse_x509_certificate")?;
    let admission_syntax = cert
        .extensions()
        .iter()
        .find(|e| e.oid == OID_ADMISSION)
        .ok_or_else(|| anyhow!("Admission extension (OID {}) not found", OID_ADMISSION))?
        .value;

    let (_, admission) = AdmissionSyntax::from_der(admission_syntax).unwrap();
    Ok(admission)
}

pub async fn create_smcb_token(
    smcb_key: &SmcBKey,
    token_url: Url,
    nonce: String,
    registration: &ClientRegistration,
    now: u64,
) -> Result<String> {
    let reg_nr = admission_from_x509(&smcb_key.cert)?
        .single_profession_info()?
        .registration_number()
        .context("missing registration number")?;
    // n.b. *not* base64-url, and Keycloak seems to require padding as well. See also:
    // https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6
    let ee_encoded = Base64::encode_string(&smcb_key.cert);

    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("JWT".to_string());
    header.x5c = Some(vec![ee_encoded]);

    let jwk = Jwk::from_encoding_key(&KEY, Algorithm::ES256).unwrap();
    let thumbprint = jwk.thumbprint(ThumbprintHash::SHA256);

    let id = json!({
        "jti": Uuid::new_v4().to_string(),
        "typ": "Bearer",
        "iss": registration.client_id,
        "azp": "target-client",
        "sub": reg_nr,
        // oauth authorization server / token_endpoint
        "aud": token_url.to_string(),
        "exp": now + 60,
        "iat": now,
        "nonce": nonce,
        "client_key": {
            "jkt": thumbprint,
        },
        "dpop_key": {
            "jkt": thumbprint,
        }
    });

    sign_jwt_brainpool(&header, &id, &smcb_key.key)
}

fn new_client_assertion(registration: &ClientRegistration, now: u64) -> Result<Value> {
    Ok(json!({
        "aud": [
            registration.registration_access_token()?.claims.aud
        ],
        "iat": now,
        // Generous lifetime so a request that stalls in flight (tail latency,
        // GC, checkpoint) still arrives before `exp`; the token endpoint gates
        // on exp against its own clock. A straggler beyond this is retried.
        "exp": now + 300,
        "iss": registration.client_id.clone(),
        "jti": Uuid::new_v4().to_string(),
        "sub": registration.client_id.clone(),
    }))
}

pub fn create_client_assertion(registration: &ClientRegistration, now: u64) -> Result<String> {
    let client_assertion = new_client_assertion(registration, now)?;

    registration.sign_jwt(None, client_assertion, &KEY)
}

pub fn create_client_assertion_with_attestation(
    nonce: String,
    registration: &ClientRegistration,
    now: u64,
) -> Result<String> {
    let mut client_assertion = new_client_assertion(registration, now)?;
    let nonce = Base64UrlUnpadded::decode_vec(&nonce)?;

    let encoding_key = EncodingKey::from_ec_pem(&PEM)?;
    let jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::ES256)?;
    let thumbprint =
        Base64UrlUnpadded::decode_vec(&jwk.thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256))?;

    let attestation_challenge: [u8; 32] = Sha256::digest([thumbprint, nonce].concat()).into();
    let attestation_challenge = Base64UrlUnpadded::encode_string(&attestation_challenge);

    let client_assertion = client_assertion.as_object_mut().context("as_object_mut")?;
    client_assertion.insert(
        "client_statement".to_string(),
        json!({
            "attestation_timestamp": now,
            "platform": "linux",
            "posture": {
                "arch": "aarch64",
                "attestation_challenge": attestation_challenge,
                "os": "Linux",
                "os_version": "os_version",
                "platform_product_id": {
                    "application_id": "app-id",
                    "packaging_type": "packaging",
                    "platform": "linux"
                },
                "product_id": "ZETA-Test-Client",
                "product_version": "0.0.1",
                "public_key": PUBLIC_KEY_PEM.clone(),
            },
            "posture_type": "software",
            "sub": registration.client_id.clone(),
        }),
    );
    registration.sign_jwt(None, client_assertion, &KEY)
}

pub fn client_builder(insecure: bool) -> ClientBuilder {
    Client::builder()
        .cookie_store(true) // session stickiness
        .use_rustls_tls()
        .danger_accept_invalid_certs(insecure)
        .pool_max_idle_per_host(1)
        .pool_idle_timeout(Duration::from_secs(5))
        .tcp_keepalive(Duration::from_secs(5))
    // .pool_max_idle_per_host(0)
    // .pool_idle_timeout(None)
    // .tcp_keepalive(None)
}

/// Send, retrying ONCE (on a fresh connection) when the request died on a
/// reused keepalive connection the server had just closed — nginx closes idle
/// keepalives on every config reload and keepalive_requests rollover, and the
/// reuse race is unavoidable client-side. Mainstream clients (OkHttp, Go
/// net/http, browsers) retry this case by default; reqwest leaves it to us.
/// Streaming bodies can't be replayed (try_clone fails) — those propagate the
/// original error.
pub async fn send_retry_stale(request: RequestBuilder) -> reqwest::Result<reqwest::Response> {
    let retry = request.try_clone();
    match request.send().await {
        Err(e) if is_stale_conn(&e) => match retry {
            Some(r) => r.send().await,
            None => Err(e),
        },
        res => res,
    }
}

fn is_stale_conn(e: &reqwest::Error) -> bool {
    let mut src = std::error::Error::source(e);
    while let Some(s) = src {
        if let Some(h) = s.downcast_ref::<hyper::Error>()
            && h.is_incomplete_message()
        {
            return true;
        }
        if let Some(io) = s.downcast_ref::<std::io::Error>()
            && io.kind() == std::io::ErrorKind::ConnectionReset
        {
            return true;
        }
        src = std::error::Error::source(s);
    }
    false
}

pub static SHARED_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    Client::builder()
        .cookie_store(false)
        .use_rustls_tls()
        .danger_accept_invalid_certs(true)
        .pool_max_idle_per_host(512)
        .pool_idle_timeout(Duration::from_secs(65)) // < NIC keepalive-timeout (default=75s)
        .tcp_keepalive(Duration::from_secs(30))
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .expect("SHARED_CLIENT")
});

#[cfg(test)]
mod tests {
    use super::*;

    fn test_registration() -> ClientRegistration {
        // Mimic register_client: the *registered* jwk legitimately carries alg/kid/use.
        let mut jwk = Jwk::from_encoding_key(&KEY, Algorithm::ES256).expect("jwk");
        jwk.common.public_key_use = Some(PublicKeyUse::Signature);
        jwk.common.key_id = Some(jwk.thumbprint(ThumbprintHash::SHA256));
        ClientRegistration {
            client_id: "test-client".to_string(),
            jwks: ClientRegistrationJwks { keys: vec![jwk] },
            registration_access_token: "unused".to_string(),
        }
    }

    /// The embedded header jwk must contain only the mandatory public-key members
    /// (client-assertion-jwt.yaml / dpop-token.yaml) — no alg/kid/use — while the key material
    /// stays intact so the server can still resolve the registered key by RFC 7638 thumbprint.
    #[test]
    fn sign_jwt_embeds_minimal_jwk() {
        let reg = test_registration();
        let expected_thumbprint = reg.jwks.keys[0].thumbprint(ThumbprintHash::SHA256);

        let jwt = reg
            .sign_jwt(None, serde_json::json!({ "sub": "test-client" }), &KEY)
            .expect("sign");

        let jwk = jsonwebtoken::decode_header(&jwt)
            .expect("header")
            .jwk
            .expect("embedded jwk");

        assert!(jwk.common.key_algorithm.is_none(), "jwk.alg must be absent");
        assert!(jwk.common.key_id.is_none(), "jwk.kid must be absent");
        assert!(jwk.common.public_key_use.is_none(), "jwk.use must be absent");
        assert_eq!(
            jwk.thumbprint(ThumbprintHash::SHA256),
            expected_thumbprint,
            "public key material must be preserved"
        );
    }
}
