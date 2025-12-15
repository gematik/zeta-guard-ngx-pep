/*-
 * #%L
 * libasl
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

use super::model::*;
use super::util::*;
use libcrux::{digest, ecdh, kem, signature};
use libcrux_ml_kem::mlkem768;

pub fn generate_raw_keys() -> Result<(PublicKeys, PrivateKeys), AslError> {
    let (ecdh_sk_bytes, ecdh_pk_bytes) = RNG.with_borrow_mut(|rng| {
        ecdh::key_gen(ecdh::Algorithm::P256, rng).map_err(|_| AslError::InternalError)
    })?;
    let rv: [u8; 64] =
        RNG.with_borrow_mut(|rng| rng.generate_array().map_err(|_| AslError::InternalError))?;
    let pqc = mlkem768::generate_key_pair(rv);
    raw_keys_from_bytes(
        &ecdh_sk_bytes,
        &ecdh_pk_bytes,
        pqc.sk().as_slice(),
        pqc.pk().as_slice(),
    )
}

pub fn raw_keys_from_bytes(
    ecdh_sk_bytes: &[u8],
    ecdh_pk_bytes: &[u8],
    pqc_sk_bytes: &[u8],
    pqc_pk_bytes: &[u8],
) -> Result<(PublicKeys, PrivateKeys), AslError> {
    let ecdh_sk = kem::PrivateKey::decode(kem::Algorithm::Secp256r1, ecdh_sk_bytes)
        .map_err(|_| AslError::BadFormat)?;
    let ecdh_pk = kem::PublicKey::decode(kem::Algorithm::Secp256r1, ecdh_pk_bytes)
        .map_err(|_| AslError::BadFormat)?;

    let pqc_sk_bytes: &[u8; PQC_SK_SIZE] =
        pqc_sk_bytes.try_into().map_err(|_| AslError::BadFormat)?;
    let pqc_pk_bytes: &[u8; PQC_PK_SIZE] =
        pqc_pk_bytes.try_into().map_err(|_| AslError::BadFormat)?;
    let pqc_sk = libcrux_ml_kem::MlKemPrivateKey::from(pqc_sk_bytes);
    let pqc_pk = libcrux_ml_kem::MlKemPublicKey::from(pqc_pk_bytes);

    Ok((
        PublicKeys { ecdh_pk, pqc_pk },
        PrivateKeys { ecdh_sk, pqc_sk },
    ))
}

pub fn generate_asl_keys(
    days_valid: u64,
    comment: &str,
) -> Result<(AslKeys, AslPrivateKeys), AslError> {
    let (pk, sk) = generate_raw_keys()?;
    let now = utc_now();
    Ok((
        AslKeys::new(&pk, now, days_valid, comment),
        AslPrivateKeys::new(&sk),
    ))
}

impl AslPrivateKeys {
    pub fn new(sk: &PrivateKeys) -> Self {
        Self {
            ecdh_sk: sk.ecdh_sk.encode(),
            pqc_sk: sk.pqc_sk.as_slice().to_vec(),
        }
    }
}

impl AslKeys {
    pub fn new(pk: &PublicKeys, issued_utc: u64, days_valid: u64, comment: &str) -> Self {
        Self {
            ecdh_pk: ECDHKey::from(pk.ecdh_pk.encode()),
            pqc_pk: pk.pqc_pk.as_slice().to_vec(),
            iat: issued_utc,
            exp: issued_utc + days_valid * SECONDS_PER_DAY,
            comment: String::from(comment),
        }
    }

    pub fn sign(
        self: &Self,
        signer_der: &[u8],
        signer_sk: &[u8],
        version: u64,
    ) -> Result<SignedAslKeys, AslError> {
        let signed_pub_keys = serde_cbor::to_vec(&self).map_err(|_| AslError::InternalError)?;
        let signature_es256 = RNG
            .with_borrow_mut(|rng| {
                signature::sign(
                    signature::Algorithm::EcDsaP256(signature::DigestAlgorithm::Sha256),
                    &signed_pub_keys,
                    signer_sk,
                    rng,
                )
                .map_err(|_| AslError::InternalError)
            })?
            .into_vec();
        let cert_hash = digest::hash(digest::Algorithm::Sha256, signer_der);

        let signed = SignedAslKeys {
            signed_pub_keys,
            signature_es256,
            cert_hash,
            cdv: version,
            ocsp_response: None,
        };
        Ok(signed)
    }
}

const SECONDS_PER_DAY: u64 = 60 * 60 * 24;
