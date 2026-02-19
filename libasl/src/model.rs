/*-
 * #%L
 * libasl
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

use std::fmt::{Debug, Display};

use super::util::{validate_ecdh_pk, validate_pqc_pk};
use libcrux::kem::{self, PublicKey};
use libcrux_ml_kem::mlkem768::{MlKem768PrivateKey, MlKem768PublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PQC_PK_SIZE: usize = 1184;
pub type PqcPublicKey = MlKem768PublicKey;
pub const PQC_SK_SIZE: usize = 2400;
pub type PqcPrivateKey = MlKem768PrivateKey;

pub const ASL_VERSION: u8 = 2;

#[derive(Debug, Copy, Clone)]
pub enum MessageMode {
    Request,
    Response,
}

impl MessageMode {
    pub const fn as_byte(&self) -> u8 {
        match self {
            MessageMode::Request => 1,
            MessageMode::Response => 2,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Environment {
    Production,
    Testing,
}

impl Environment {
    pub const fn as_byte(&self) -> u8 {
        match self {
            Environment::Production => 1,
            Environment::Testing => 0,
        }
    }
}

pub struct PublicKeys {
    pub ecdh_pk: kem::PublicKey,
    pub pqc_pk: PqcPublicKey,
}

impl Clone for PublicKeys {
    fn clone(&self) -> Self {
        Self {
            ecdh_pk: PublicKey::decode(kem::Algorithm::Secp256r1, &self.ecdh_pk.encode()).unwrap(),
            pqc_pk: libcrux_ml_kem::MlKemPublicKey::from(self.pqc_pk.as_slice()),
        }
    }
}

impl Debug for PublicKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PublicKeys (opaque)")
    }
}

impl TryFrom<&AslKeys> for PublicKeys {
    type Error = AslError;
    fn try_from(value: &AslKeys) -> Result<Self, Self::Error> {
        Ok(Self {
            ecdh_pk: kem::PublicKey::decode(
                kem::Algorithm::Secp256r1,
                &validate_ecdh_pk(&value.ecdh_pk)?,
            )
            .map_err(|_| AslError::DecodingError)?,
            pqc_pk: libcrux_ml_kem::MlKemPublicKey::from(validate_pqc_pk(&value.pqc_pk)?),
        })
    }
}

pub struct PrivateKeys {
    pub ecdh_sk: kem::PrivateKey,
    pub pqc_sk: PqcPrivateKey,
}

impl Clone for PrivateKeys {
    fn clone(&self) -> Self {
        Self {
            ecdh_sk: kem::PrivateKey::decode(kem::Algorithm::Secp256r1, &self.ecdh_sk.encode())
                .unwrap(),
            pqc_sk: libcrux_ml_kem::MlKemPrivateKey::from(self.pqc_sk.as_slice()),
        }
    }
}

impl TryFrom<&AslPrivateKeys> for PrivateKeys {
    type Error = AslError;
    fn try_from(value: &AslPrivateKeys) -> Result<Self, Self::Error> {
        Ok(Self {
            ecdh_sk: kem::PrivateKey::decode(kem::Algorithm::Secp256r1, &value.ecdh_sk)
                .map_err(|_| AslError::BadFormat)?,
            pqc_sk: libcrux_ml_kem::MlKemPrivateKey::from(
                &value
                    .pqc_sk
                    .as_slice()
                    .try_into()
                    .map_err(|_| AslError::BadFormat)?,
            ),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AslKeys {
    #[serde(rename = "ECDH_PK")]
    pub ecdh_pk: ECDHKey,
    #[serde(rename = "ML-KEM-768_PK", with = "serde_bytes")]
    pub pqc_pk: Vec<u8>,
    pub iat: u64,
    pub exp: u64,
    pub comment: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignedAslKeys {
    #[serde(with = "serde_bytes")]
    pub signed_pub_keys: Vec<u8>,
    #[serde(rename = "signature-ES256", with = "serde_bytes")]
    pub signature_es256: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub cert_hash: Vec<u8>,
    pub cdv: u64,
    #[serde(with = "serde_bytes")]
    pub ocsp_response: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AslPrivateKeys {
    #[serde(rename = "ECDH_SK")]
    pub ecdh_sk: Vec<u8>,
    #[serde(rename = "ML-KEM-768_SK", with = "serde_bytes")]
    pub pqc_sk: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ECDHKey {
    pub crv: String,
    #[serde(with = "serde_bytes")]
    pub x: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub y: Vec<u8>,
}

impl From<Vec<u8>> for ECDHKey {
    fn from(bytes: Vec<u8>) -> ECDHKey {
        let mut x = bytes;
        let y = x.split_off(32);
        ECDHKey {
            crv: String::from("P-256"),
            x,
            y,
        }
    }
}

pub const MESSAGE_TYPE_1: &str = "M1";

#[derive(Debug, Serialize, Deserialize)]
pub struct Message1 {
    #[serde(rename = "MessageType")]
    pub message_type: String, // "M1"
    #[serde(rename = "ECDH_PK")]
    pub ecdh_pk: ECDHKey,
    #[serde(rename = "ML-KEM-768_PK", with = "serde_bytes")]
    pub pqc_pk: Vec<u8>,
}

pub const MESSAGE_TYPE_2: &str = "M2";

#[derive(Debug, Serialize, Deserialize)]
pub struct Message2 {
    #[serde(rename = "MessageType")]
    pub message_type: String, // "M2"
    #[serde(rename = "ECDH_ct")]
    pub ecdh_ct: ECDHKey, // Warning, misleading field name!
    #[serde(rename = "ML-KEM-768_ct", with = "serde_bytes")]
    pub pqc_ct: Vec<u8>,
    #[serde(rename = "AEAD_ct", with = "serde_bytes")]
    pub aead_ct: Vec<u8>,
}

pub const MESSAGE_TYPE_3: &str = "M3";

#[derive(Debug, Serialize, Deserialize)]
pub struct Message3 {
    #[serde(rename = "MessageType")]
    pub message_type: String, // "M3"
    #[serde(rename = "AEAD_ct", with = "serde_bytes")]
    pub aead_ct: Vec<u8>,
    #[serde(rename = "AEAD_ct_key_confirmation", with = "serde_bytes")]
    pub aead_ct_key_confirmation: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Message3InnerLayer {
    #[serde(rename = "ECDH_ct")]
    pub ecdh_ct: ECDHKey, // Warning, misleading field name!
    #[serde(rename = "ML-KEM-768_ct", with = "serde_bytes")]
    pub pqc_ct: Vec<u8>,
    #[serde(rename = "ERP")]
    pub erp: bool,
    #[serde(rename = "ESO")]
    pub eso: bool,
}

pub const MESSAGE_TYPE_4: &str = "M4";

#[derive(Debug, Serialize, Deserialize)]
pub struct Message4 {
    #[serde(rename = "MessageType")]
    pub message_type: String, // "M4"
    #[serde(rename = "AEAD_ct_key_confirmation", with = "serde_bytes")]
    pub aead_ct_key_confirmation: Vec<u8>,
}

pub const MESSAGE_TYPE_ERROR: &str = "Error";

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    #[serde(rename = "MessageType")]
    pub message_type: &'static str, // "Error"
    #[serde(rename = "ErrorCode")]
    pub error_code: u32,
    #[serde(rename = "ErrorMessage")]
    pub error_message: &'static str,
}

#[derive(Debug, Error)]
pub enum AslError {
    DecodingError,     // Fehler in einer Kodierung bspw. der CBOR-Kodierung
    MissingParameters, // notwendige Datenfelder bspw. in der Handshake fehlen
    DecryptionFailure, // Eine AES/GCM-Entschlüsselung ergibt das Symbol "FAIL".
    WrongEnvironment,  // Falsches PU/nonPU-Flag
    TranscriptError, // Im Handshake wird Ungleichheit zwischen den beiden Transskript-Hashwerten festgestellt.
    BadFormat, // Die erste Sanity-Prüfung des erweiterten Chiffrat bspw. bei A_26928-* schlägt fehl.
    NotRequest, // Falscher Wert im Request/Respose-Flag, A_26928-* (Prüfschritt 3)
    UnknownKeyID, // KeyID passt nicht zur CID
    UnknownCID, // unbekannte CID
    ServerUnavailable, // Resource-Server nicht erreichbar beim Forwarding
    ServerTimeout, // Resource-Server liefert keine Antwort
    DatabaseError, // DB-Aufruf liefert anderen Fehlercode als 200 OK oder 404 Not Found
    InternalError, // Sonstiger unerwarteter interner Fehler
}

impl AslError {
    pub const fn status(&self) -> u32 {
        match self {
            AslError::DecodingError => 400,
            AslError::MissingParameters => 400,
            AslError::DecryptionFailure => 403,
            AslError::WrongEnvironment => 403,
            AslError::TranscriptError => 403,
            AslError::BadFormat => 400,
            AslError::NotRequest => 403,
            AslError::UnknownKeyID => 403,
            AslError::UnknownCID => 403,
            AslError::ServerUnavailable => 502,
            AslError::ServerTimeout => 504,
            AslError::DatabaseError => 503,
            AslError::InternalError => 500,
        }
    }

    pub const fn code(&self) -> u32 {
        match self {
            AslError::DecodingError => 1,
            AslError::MissingParameters => 2,
            AslError::DecryptionFailure => 3,
            AslError::WrongEnvironment => 4,
            AslError::TranscriptError => 5,
            AslError::BadFormat => 6,
            AslError::NotRequest => 7,
            AslError::UnknownKeyID => 8,
            AslError::UnknownCID => 9,
            AslError::ServerUnavailable => 10,
            AslError::ServerTimeout => 11,
            AslError::DatabaseError => 12,
            AslError::InternalError => 13,
        }
    }

    pub const fn message(&self) -> &'static str {
        match self {
            AslError::DecodingError => "Decoding Error",
            AslError::MissingParameters => "Missing Parameters",
            AslError::DecryptionFailure => "GCM returns FAIL",
            AslError::WrongEnvironment => "PU/nonPU Failure",
            AslError::TranscriptError => "Transscript Error",
            AslError::BadFormat => "bad format: extended ciphertext",
            AslError::NotRequest => "is not a request",
            AslError::UnknownKeyID => "unknow KeyID",
            AslError::UnknownCID => "unknown CID",
            AslError::ServerUnavailable => "Resource Server unavailable",
            AslError::ServerTimeout => "Resource Server timed out",
            AslError::DatabaseError => "Database Error",
            AslError::InternalError => "Internal error",
        }
    }

    pub fn to_response(&self) -> Vec<u8> {
        serde_cbor::to_vec(&ErrorResponse {
            message_type: MESSAGE_TYPE_ERROR,
            error_code: self.code(),
            error_message: self.message(),
        })
        .unwrap()
    }
}

impl Display for AslError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}
