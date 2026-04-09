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

use std::fmt::Debug;

use super::util::{validate_ecdh_pk, validate_pqc_pk};
use anyhow::{Context, anyhow};
use libcrux_kem as kem;
use libcrux_kem::PublicKey;
use libcrux_ml_kem::mlkem768::{MlKem768PrivateKey, MlKem768PublicKey};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
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

#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum Environment {
    #[default]
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
            .to_error()
            .map_err(AslError::DecodingError)?,
            pqc_pk: libcrux_ml_kem::MlKemPublicKey::from(validate_pqc_pk(&value.pqc_pk)?),
        })
    }
}

pub struct PrivateKeys {
    pub ecdh_sk: kem::PrivateKey,
    pub pqc_sk: PqcPrivateKey,
}

static DEFAULT_ECDH_SK: &str = "af5b31d69d3f9e12ada4400b969823005209edc8740fb54fe45a74a634eddff4";
static DEFAULT_PQC_SK: &str = "84428ca0db4237d1172a0b0eaf4917b47cc608b5a92a7710d236c5a84cb542b96f8fd870fd849494434ca2ba9e78c945d411bc0abc8b1a7c1a90c581792b2cbd397f9450b6bcf4ced316260f687bf7cacb89187213a67930904797720331534211fa32709ac07113949bc84c95f65c089689fd02bbbe02678a3c04e76948dd33385fa159da10acf3605d7b858d9e59a44212c963eb25fd3459ee956d01a729f9840a53630cbe8980cd7c7f907c0619a803f22a94f963aed29999e6fc982cf7be5ee9bdfcd28729587fb7c98f9686b99f55c3b60a8504e826e463be1905883175237596cad2a190e3134851274ce3078ad4195392c625bf4b7d5ff783760598d41451ea1626159192a569b345031f38b6b26f7c735ea836d9a6bfba217d5305393728a5feac4220f1bb3c551a975a89fe8b0e22f5b0c011ac6afb8f94d9c684b3151828a8296aacfcf195a5434a4ad4917c5859ceeca071ebcebed6918b7b6ce70c9027a9ba1bc07f77fac5401c8b6172a994f67170ec244018af976694b62245cb099ed29b2c4c807e63b3bee5bb3f21c869554a3c0f1c9457b1a2b6d7337cd2aeff0466d62598d7fc6c5bb7108a6c710f5acf6f656bbbba60301784e0785b375b761340ba8146164adaa8ec780309d34eaa8933d94797741b9fbb85c84e1a7156e3ac741c2008134a0807946282923e138a4b26aa69f02b3fd55b0898ceb074443a554e8ea80cbd206413c7cd2196734aec6fa6931919db0c7aea5e7c240d582318aa396d5c130992ac58a7693e0b5a6ba6d83fd5483d2dda4260471799fb9cabbcad0560762c5a2286cba1ce482082183460131ef78cb2a3ab8e3c7786b2222e73f4a90a478b1064c9ffe04289fca983a9b203fca00c0abf10ca2197e778d959c0621b8f7b3c2b22fc65613a987a26a7c82a63c7627c75e16c7df6c0506aac3a9b590f52696cebaefef367f9312c9d0b89b771b7d44a47ad0060753752522b79bd423ad239121db9c42c9860d5bc7179d962e6d6a99e8a285b975840aa761bfc7aaa835888a23dc4009621415763689ed0167b5573917a6010fdf97ddc047abd073efa733fa95574054571bd16988c6605381b73b9f023742a3f4c8b38ac702576e241a41987a1a4a128d2223125a4bdbc33ef65af4282c8bbea453ac86d612c6c9c26754efa6921941b5d2c09a020aff2d4a3bcd41a0959125e9b6261321a920c89658671db665e582bcc3d877b9d04c5c90680b11607beb1c1fb73a6a2903b1a9c3e2d0b36d45713b65199b3e85c74441b650cba37119b8219bf88688445c7336de1495705c2145883d1d25512b7478394039092242094345e2406d8c57cb7543481e27cafd749e8f8bbe900450ab9459fd58f06ab24ae5a522f8c510e0034bdf4cf46618e34fc57e9ccc124a203a985ca6aab7fcadac9023ca78303238ce2143a2ca4b97800eec0b0b2e27f56813fb1778f56e69684a53d10e63ff89bb8e0d908b1c72a2d2bb04d2562edd4a007bc1533795e77436667c5794bd2015f1805fe2c01ecaa1e3827b1b227b08b6115674157679697b1900dd03822abba0803bcc3d7644d2150b2c3974b9fa80ab82842aafa3691964837e43a56070e11da26b5dc97ac36028ba414a6c01844c3050d40b2636098a4d3a3d28741d358716ff8c1509cab01aa03c0f796ae92834440cd23f53c5d787cb8184a2a6b98f9e1bab3a8c5fe4b04b4fccf5e770a94677d91236fc06bccef73ad594456487a4547235e6b5811fb805b65b74eca47ac6d997e8896b15e5099891855bfc86e4f2967912b6c98398c05b70c590386f5f844e33a336d2b911b9923294393973389e05536a40751ee2910bfe373cc973509c9c093b1a3fc704e3273c6d4574ef3b1425aa56a026a2a0ff17d61164d3d8729f7b56da0805630d24dad8bbedef2186b0107762b86cd078def21b0e8e8b67ba8c301ab73d70325ac6b5654c058e5c01d1d6966f30b161fab8639c5608fbb8b590b4e5d4615814322b4e75ca7c2cfdbecc2c09c4d97608ffd5c239dd46b203c125db68771499f1b26a36deb7f46d7c98d4357de70a10e199036755eee93159dc247039bce6e729d9ef77574f2c02d2847f046105d646786b514daf7a57c935b7605361d01248d5b9b7e72516e78992a28030d553b8884c11765b3542a6dcd782c5a4a2278939b62b14979a968a9f9168eba89c19cb7bda956768b059fe8b8d6c080e1d590fb0a163f536b8c7988057c5d88357756dc9def5b8583823a0fc720d0dc646b9537eb776604eb2a93996a91e73b409a1552e78102a97201ac4da5ca547016ba0e6645c8d16b995338a366422a173da7851651d78b98e897ce23a253a09e8ce57b6779609ea204b24b13a44663ea4a17231895f898ceb2f915cd177efef3c88e6b41d2c3a74f40502c9350628a74c63b3673d4915f68349af7c9141c5f8dd906061c074bdb2d59f87ac5116cc84ba13c398ba203c6039c2bc4ac6a774160db218a1401714584b247235c8100463da3352fc566f12ab9fe387b62b0c269a628d31219b532a8d8f397ad455fee1c7647f612d129961c07b01960393c491a323b236be64b826a87c00bba4603cab7b2165ce869eda4ccca15bc98479409c09f1d491c0498aab2d29d29c51b6d784d07c86580251c822b26cfe1684c75422ffbcffad011528394e9bc63a827484fb05279ba06a0c7aab211aeb4e9c72af72a3e31ccb6d60bfbe03efdf41895a455f2199e9f4b7168f51f95932c2210bc1a197e7d991ea4111188717123d407960303b34613347443b885651c6038ea3686598813071a9f0f320fc1b94d96f56fb0a1587ea32ec7e86cc5793b412c4e33f770633c675e6288eb23c31b630ebd916b871b098e787e79fb3f7cacc8aa559196a4c6dfd3bb9fcc436a43491a66018d10b14cd219ac9c320c487c02c7a49b88b3fa1bb35172b9e79b42e6d2af7f8582853641a8f8a047f402cd17631a50c5a6d02d5df4236e421a880b8bd4749a01a4c70ef8bb8080301b828922e70f5dc05f10759e2f18096986301b52989a4552eaf67d1499a7fbe6298eb5b39a9750877c17d6e630fb9830cdca38a4c8b401a853f773a64738548989241926905f77a9f240b0393c4222286eaef145db2a7486593e8111b4f8c56507293ada2313e336847708a9c57213c83ccae273897efc6110205153d5189f823d8c744772c22d07e92709006a1e45614e431cee4aa3a2e4bff6c7796989ab5c81f61dd423624ae8595744f831e1f5b5c56e8ccde0384d1f312ea66a1cdfac9c8c2d698e58b5036ba871f4247d845fd97265bdef1ba1db360721d462bacd71c3bcfa015553f4dae1ed82b59a1e0b2af4acdd5039aed98f1e55f26a66b391ae";

impl Default for PrivateKeys {
    fn default() -> Self {
        let ecdh_sk_bytes = hex::decode(DEFAULT_ECDH_SK).unwrap();
        let pqc_sk_bytes = hex::decode(DEFAULT_PQC_SK).unwrap();
        let pqc_sk_array: &[u8; PQC_SK_SIZE] = pqc_sk_bytes.as_slice().try_into().unwrap();
        Self {
            ecdh_sk: kem::PrivateKey::decode(kem::Algorithm::Secp256r1, ecdh_sk_bytes.as_slice())
                .unwrap(),
            pqc_sk: libcrux_ml_kem::MlKemPrivateKey::from(pqc_sk_array),
        }
    }
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

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct CertData {
    #[serde(with = "serde_bytes")]
    pub cert: Vec<u8>, // DER-kodiertes-AUT-ZETA/ASL-Zertifikat,
    #[serde(with = "serde_bytes")]
    pub ca: Vec<u8>, // DER-kodiertes-Komponenten-PKI-CA-aus-dem-"cert"-kommt,
    pub rca_chain: Vec<ByteBuf>, // [Cross-Zertifikat-1, ..., Cross-Zertifikat-n],
}

impl CertData {
    pub fn to_vec(&self) -> Result<Vec<u8>, AslError> {
        Ok(serde_cbor::to_vec(self).context("serde_cbor")?)
    }
}

#[derive(Serialize, Deserialize)]
pub struct AslKeys {
    #[serde(rename = "ECDH_PK")]
    pub ecdh_pk: ECDHKey,
    #[serde(rename = "ML-KEM-768_PK", with = "serde_bytes")]
    pub pqc_pk: Vec<u8>,
    pub iat: u64,
    pub exp: u64,
    pub comment: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
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

impl SignedAslKeys {
    pub fn version(&self) -> String {
        format!("{}-{}", hex::encode(&self.cert_hash), self.cdv)
    }
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

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    #[serde(rename = "MessageType")]
    pub message_type: String, // "Error"
    #[serde(rename = "ErrorCode")]
    pub error_code: u32,
    #[serde(rename = "ErrorMessage")]
    pub error_message: String,
}

#[derive(Error, Debug)]
pub enum AslError {
    #[error("decoding error: {0}")]
    DecodingError(#[source] anyhow::Error), // Fehler in einer Kodierung bspw. der CBOR-Kodierung
    #[error("missing parameters")]
    MissingParameters, // notwendige Datenfelder bspw. in der Handshake fehlen
    #[error("GCM returns FAIL")]
    DecryptionFailure, // Eine AES/GCM-Entschlüsselung ergibt das Symbol "FAIL".
    #[error("PU/nonPU failure")]
    WrongEnvironment, // Falsches PU/nonPU-Flag
    #[error("transcript error")]
    TranscriptError, // Im Handshake wird Ungleichheit zwischen den beiden Transskript-Hashwerten festgestellt.
    #[error("bad format: extended ciphertext")]
    BadFormat, // Die erste Sanity-Prüfung des erweiterten Chiffrat bspw. bei A_26928-* schlägt fehl.
    #[error("is not a request")]
    NotRequest, // Falscher Wert im Request/Respose-Flag, A_26928-* (Prüfschritt 3)
    #[error("unknown KeyID")]
    UnknownKeyID, // KeyID passt nicht zur CID
    #[error("unknown CID")]
    UnknownCID, // unbekannte CID
    // custom types, not specified
    #[error("key signature invalid")]
    VerificationError, // Prüfung der signierten öffentlichen Schlüssel fehlerhaft
    #[error("bad request: {0}")]
    BadRequest(#[source] anyhow::Error),
    #[error("internal error: {0}")]
    InternalError(#[from] anyhow::Error),
}

impl AslError {
    pub const fn status(&self) -> u32 {
        match self {
            AslError::DecodingError(_) => 400,
            AslError::MissingParameters => 400,
            AslError::DecryptionFailure => 403,
            AslError::WrongEnvironment => 403,
            AslError::TranscriptError => 403,
            AslError::BadFormat => 400,
            AslError::NotRequest => 403,
            AslError::UnknownKeyID => 403,
            AslError::UnknownCID => 403,
            AslError::VerificationError => 500,
            AslError::BadRequest(_) => 400,
            AslError::InternalError(_) => 500,
        }
    }

    pub const fn code(&self) -> u32 {
        match self {
            AslError::DecodingError(_) => 1,
            AslError::MissingParameters => 2,
            AslError::DecryptionFailure => 3,
            AslError::WrongEnvironment => 4,
            AslError::TranscriptError => 5,
            AslError::BadFormat => 6,
            AslError::NotRequest => 7,
            AslError::UnknownKeyID => 8,
            AslError::UnknownCID => 9,
            AslError::VerificationError => 100,
            AslError::BadRequest(_) => 101,
            AslError::InternalError(_) => 102,
        }
    }

    pub fn to_response(&self) -> Vec<u8> {
        serde_cbor::to_vec(&ErrorResponse {
            message_type: MESSAGE_TYPE_ERROR.to_string(),
            error_code: self.code(),
            error_message: self.to_string(),
        })
        .unwrap()
    }
}

// The libcrux error types don't implement std::error::Error, so its Results can't be mapped to
// AslError easily.
pub trait ToError<R> {
    fn to_error(self) -> R;
}

impl<T, E: Debug> ToError<Result<T, anyhow::Error>> for Result<T, E> {
    /// Any Result with a Debug error type can be made into a Result<_, std::error::Error> via the
    /// anyhow! macro. This can then be mapped into thiserror types.
    ///
    /// # Example
    ///
    /// ```
    /// use std::{fmt::Debug, result::Result};
    ///
    /// use asl::{AslError, ToError};
    ///
    /// // This Result's error type is not std::error::Error!
    /// pub fn asl_function<E: Debug>(result: Result<(), E>) -> Result<(), AslError> {
    ///     // will return AslError::InternalError via #[from]
    ///     Ok(result.to_error()?)
    /// }
    ///
    /// pub fn asl_function2<E: Debug>(result: Result<(), E>) -> Result<(), AslError> {
    ///     // no closure, you can pass in a tuple struct variant instead
    ///     result.to_error().map_err(AslError::BadRequest)
    /// }
    /// ```
    fn to_error(self) -> Result<T, anyhow::Error> {
        self.map_err(|e| anyhow!("{e:?}"))
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use libcrux_traits::aead::typed_refs::EncryptError;
    use std::fmt::Debug;

    use crate::{AslError, ErrorResponse, ToError};

    fn returning_asl_error<T: Debug>(value: Result<(), T>) -> Result<(), AslError> {
        Ok(value.to_error()?)
    }

    #[test]
    fn convert_libcrux_errors_to_error() {
        let result: Result<(), EncryptError> = Err(EncryptError::Unknown);

        let result = result.to_error();

        assert!(result.is_err_and(|e| e.to_string() == "Unknown"));

        let result = returning_asl_error(Err(EncryptError::Unknown));
        assert!(result.is_err_and(|e| {
            matches!(e, AslError::InternalError(..)) && e.to_string() == "internal error: Unknown"
        }));
    }

    #[test]
    fn to_response() -> anyhow::Result<()> {
        let error = AslError::BadRequest(anyhow!("coz"));
        let response = error.to_response();
        let response: ErrorResponse = serde_cbor::from_slice(&response)?;
        assert!(response.message_type == "Error");
        assert!(response.error_code == 101);
        assert!(response.error_message == "bad request: coz");

        Ok(())
    }
}
