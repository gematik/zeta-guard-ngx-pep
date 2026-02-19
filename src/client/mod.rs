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
use std::path::Path;
use std::sync::LazyLock;

use anyhow::{Context, bail};
use anyhow::{Result, anyhow};
use asn1_rs::FromDer;
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use jsonwebtoken::EncodingKey;
use jsonwebtoken::Header;
use jsonwebtoken::TokenData;
use jsonwebtoken::dangerous::insecure_decode;
use jsonwebtoken::jwk::{Jwk, PublicKeyUse};
use jsonwebtoken::{Algorithm, get_current_timestamp};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use p12_keystore::{KeyStore, KeyStoreEntry};
use p256::ecdsa::SigningKey;
use p256::pkcs8::der::EncodePem;
use p256::pkcs8::{DecodePrivateKey, EncodePublicKey, SubjectPublicKeyInfoRef};
use reqwest::{Client, RequestBuilder, Url};
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_json::json;
use sha2::Digest;
use sha2::Sha256;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use uuid::Uuid;
use x509_parser::der_parser::{Oid, oid};
use x509_parser::parse_x509_certificate;

use crate::client::asn1::AdmissionSyntax;
use crate::typify::DPoPProofJwtPayload;

pub mod asl;
mod asn1;

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
    client: &Client,
) -> Result<ClientRegistration> {
    let mut jwk = Jwk::from_encoding_key(&KEY, Algorithm::ES256)?;
    jwk.common.public_key_use = Some(PublicKeyUse::Signature);
    jwk.common.key_id = Some(jwk.thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256));

    let request = client_registration_request(jwk);

    let registration: ClientRegistration = client
        .post(client_registration_url)
        .json(&request)
        .header("accept", "application/json")
        .send()
        .await?
        .json()
        .await?;
    Ok(registration)
}

pub async fn get_nonce(nonce_url: Url, client: &Client) -> Result<String> {
    client
        .get(nonce_url)
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

const OID_ADMISSION: Oid = oid!(1.3.36.8.3.3);

pub fn admission_from_x509(der: &[u8]) -> Result<AdmissionSyntax<'_>> {
    let (_, cert) = parse_x509_certificate(der).context("parse_x509_certificate")?;
    let admission_syntax = cert
        .extensions()
        .iter()
        .find(|e| e.oid == OID_ADMISSION)
        .ok_or_else(|| anyhow!("Admission extension (OID {}) not found", OID_ADMISSION))?
        .value;

    let (_, admission) = AdmissionSyntax::from_der(admission_syntax)?;
    Ok(admission)
}

pub async fn read_smcb_p12(p12_path: &Path, p12_pass: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = vec![];
    File::open(p12_path).await?.read_to_end(&mut buf).await?;
    let keystore = KeyStore::from_pkcs12(&buf, p12_pass)?;
    let (_alias, chain) = keystore.private_key_chain().context("private_key_chain")?;
    let cert = chain.chain()[0].as_der().to_vec();
    let key = chain.key().to_vec();
    Ok((cert, key))
}

pub async fn create_smcb_token(
    p12_path: &Path,
    p12_pass: &str,
    auth_url: Url,
    nonce: String,
    registration: &ClientRegistration,
) -> Result<String> {
    let (cert, key) = read_smcb_p12(p12_path, p12_pass).await?;
    let reg_nr = admission_from_x509(&cert)?
        .single_profession_info()?
        .registration_number()
        .context("missing registration number")?;
    // n.b. *not* base64-url, and Keycloak seems to require padding as well. See also:
    // https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6
    let ee_encoded = Base64::encode_string(&cert);

    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("JWT".to_string());
    header.x5c = Some(vec![ee_encoded]);

    let now = get_current_timestamp();
    let id = json!({
        "jti": Uuid::new_v4().to_string(),
        "typ": "Bearer",
        "iss": registration.client_id,
        "azp": "target-client",
        "sub": reg_nr,
        "aud": [
            auth_url.to_string()
        ],
        "exp": now + 60,
        "iat": now,
        "nonce": nonce,
    });

    sign_jwt_brainpool(&header, &id, &key)
}

pub fn test_popp_token_payload(iat: u64, patient_proof_time: u64) -> Value {
    json!({
      "actorId": "883110000168650",
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

pub async fn create_popp_token(
    p12_path: &Path,
    p12_pass: &str,
    p12_alias: &str,
    iat: u64,
    patient_proof_time: u64,
) -> Result<String> {
    let mut buf = vec![];
    File::open(p12_path).await?.read_to_end(&mut buf).await?;
    let keystore = KeyStore::from_pkcs12(&buf, p12_pass)?;
    let Some(KeyStoreEntry::PrivateKeyChain(chain)) = keystore.entry(p12_alias) else {
        bail!("no PrivateKeyChain found at {p12_path:?} (alias={p12_alias})")
    };

    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("vnd.telematik.popp+jwt".to_string());
    header.kid = Some(p12_alias.to_string());
    let ee = Base64::encode_string(chain.chain()[0].as_der());
    header.x5c = Some(vec![ee]);

    let payload = test_popp_token_payload(iat, patient_proof_time);
    let key = EncodingKey::from_ec_der(chain.key());
    Ok(jsonwebtoken::encode(&header, &payload, &key)?)
}

pub fn create_dpop_proof(
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

async fn create_client_assertion(
    nonce: String,
    registration: &ClientRegistration,
) -> Result<String> {
    let now: i64 = get_current_timestamp().try_into().unwrap();
    let nonce = Base64UrlUnpadded::decode_vec(&nonce).expect("nonce");

    let public_key_hash: [u8; 32] = Sha256::digest(PUBLIC_KEY.clone()).into();
    let attestation_challenge: [u8; 32] =
        Sha256::digest([public_key_hash.to_vec(), nonce].concat()).into();
    let attestation_challenge = Base64::encode_string(&attestation_challenge);

    // TODO: client_assertion can't be constructed from the schema currently, because
    // client-self-assessment is not defined. Remove the json!() invocation below when this is fixed

    // let client_assertion = ClientAssertionJwtPayload {
    //     aud: vec![registration.registration_access_token()?.claims.aud],
    //     client_statement: None,
    //     exp: (get_current_timestamp() + 60).try_into().unwrap(),
    //     iss: registration.client_id.clone(),
    //     jti: Uuid::new_v4().to_string(),
    //     sub: registration.client_id.clone(),
    // };
    let client_assertion = json!({
        "aud": [
            registration.registration_access_token()?.claims.aud
        ],
        "iat": now,
        "exp": now + 10,
        "iss": registration.client_id.clone(),
        "jti": Uuid::new_v4().to_string(),
        "sub": registration.client_id.clone(),
        "urn:telematik:client-self-assessment": {
            "name": "name",
            "client_id": registration.client_id.clone(),
            "manufacturer_id": "manufacturerId",
            "manufacturer_name": "manufacturerName",
            "owner_mail": "manufacturer@example.invalid",
            "registration_timestamp": registration.registration_access_token()?.claims.iat,
            "platform_product_id": {
                "platform": "linux",
                "packaging_type": "source",
                "application_id": "none"
            }
        },
        "client_statement": {
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
                "product_id": "product_id",
                "product_version": "0.0.0",
                "public_key": PUBLIC_KEY_PEM.clone(),
            },
            "posture_type": "software",
            "sub": registration.client_id.clone(),
        },
    });
    registration.sign_jwt(None, client_assertion, &KEY)
}

pub async fn exchange_access_token(
    token_url: Url,
    nonce: String,
    registration: &ClientRegistration,
    smcb: &str,
    client: &Client,
) -> Result<String> {
    let client_assertion = create_client_assertion(nonce.clone(), registration).await?;
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

    let dpop = create_dpop_proof(registration, "POST", token_url.as_str(), None, None)?;

    let token: TokenExchangeResponse = client
        .post(token_url)
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

pub fn get_with_dpop(
    registration: &ClientRegistration,
    client: Client,
    access_token: &str,
    url: Url,
) -> Result<RequestBuilder> {
    let dpop = create_dpop_proof(
        registration,
        "GET",
        url.as_str(),
        Some(Base64UrlUnpadded::encode_string(&Sha256::digest(
            access_token,
        ))),
        None,
    )?;
    Ok(client
        .get(url)
        .bearer_auth(access_token)
        .header("dpop", &dpop))
}

pub fn post_with_dpop(
    registration: &ClientRegistration,
    client: Client,
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
