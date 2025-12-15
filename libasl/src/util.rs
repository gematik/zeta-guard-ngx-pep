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
use libcrux::{aead, digest, drbg::Drbg, hkdf, kem};
use libcrux_ml_kem::mlkem768;
use std::cell::RefCell;
use std::time::{SystemTime, UNIX_EPOCH};

thread_local! {
    #[cfg(test)]
    pub static RNG: RefCell<Drbg> = RefCell::new(Drbg::new_with_entropy(
        digest::Algorithm::Sha256, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16].as_ref()).unwrap());
    #[cfg(not(test))]
    pub static RNG: RefCell<Drbg> = RefCell::new(Drbg::new(digest::Algorithm::Sha256).unwrap());
}

pub fn utc_now() -> u64 {
    let now = SystemTime::now();
    let since_epoch = now
        .duration_since(UNIX_EPOCH)
        .expect("system time before epoch");
    since_epoch.as_secs()
}

pub(crate) fn hkdf_expand(secret: &[u8], out_len: usize) -> Result<Vec<u8>, AslError> {
    // Note: This emulates the reference implementation, which uses a zero salt block and empty info
    let salt = [0u8; 32]; // 32 zeroes block
    let info = [0u8; 0]; // empty
    let res = hkdf::hkdf(hkdf::Algorithm::Sha256, &salt, &secret, &info, out_len)
        .map_err(|_| AslError::InternalError)?;
    if res.len() != out_len {
        return Err(AslError::InternalError);
    }
    Ok(res)
}

pub(crate) fn validate_ecdh_pk(pk: &ECDHKey) -> Result<Vec<u8>, AslError> {
    if pk.crv != "P-256" {
        return Err(AslError::MissingParameters);
    }
    if pk.x.len() != 32 {
        return Err(AslError::MissingParameters);
    }
    if pk.y.len() != 32 {
        return Err(AslError::MissingParameters);
    }

    let mut encoded = pk.x.clone();
    encoded.extend(&pk.y);
    Ok(encoded)
}

pub(crate) fn validate_pqc_pk(pk: &[u8]) -> Result<[u8; PQC_PK_SIZE], AslError> {
    if pk.len() != PQC_PK_SIZE {
        return Err(AslError::MissingParameters);
    }
    let arr: [u8; PQC_PK_SIZE] = pk.try_into().map_err(|_| AslError::DecodingError)?;
    Ok(arr)
}

pub(crate) struct HandshakeMaterial {
    pub ss_p: Vec<u8>, // either ss_e or ss_s, depending on where it is used
    pub ecdh_ct: Vec<u8>,
    pub pqc_ct: Vec<u8>,
}

pub(crate) fn derive_handshake_material(
    ecdh_pk: &ECDHKey,
    pqc_pk: &[u8],
) -> Result<HandshakeMaterial, AslError> {
    let ecdh_pk_bytes = validate_ecdh_pk(ecdh_pk)?;
    let ecdh_pk_obj = kem::PublicKey::decode(kem::Algorithm::Secp256r1, &ecdh_pk_bytes)
        .map_err(|_| AslError::DecodingError)?;

    let pqc_pk_bytes = validate_pqc_pk(pqc_pk)?;
    let pqc_pk_obj = libcrux_ml_kem::MlKemPublicKey::from(pqc_pk_bytes);

    let (ss_p, ecdh_ct, pqc_ct) = RNG.with_borrow_mut(|rng| {
        let (ss_p_ecdh_t1, ecdh_ct_t) =
            kem::encapsulate(&ecdh_pk_obj, rng).map_err(|_| AslError::InternalError)?;
        let mut ss_p_ecdh_t = ss_p_ecdh_t1.encode();
        ss_p_ecdh_t.truncate(32); // restrict to X coordinate, like in TLS 1.3 (RFC 8446 7.4.2)

        let pqc_random: [u8; 32] = rng.generate_array().map_err(|_| AslError::InternalError)?;
        let (pqc_ct_t, ss_p_pqc_t) = mlkem768::encapsulate(&pqc_pk_obj, pqc_random);

        let mut ss_p_t = ss_p_ecdh_t;
        ss_p_t.extend(ss_p_pqc_t);
        Ok((ss_p_t, ecdh_ct_t.encode(), pqc_ct_t.as_slice().to_vec()))
    })?;

    Ok(HandshakeMaterial {
        ss_p,
        ecdh_ct,
        pqc_ct,
    })
}

pub(crate) struct HandshakeKeys {
    pub k1_c2s: Vec<u8>,
    pub k1_s2c: Vec<u8>,
}

pub(crate) fn derive_handshake_keys(ss_p: &[u8]) -> Result<HandshakeKeys, AslError> {
    let mat = hkdf_expand(&ss_p, 64)?;
    let mut k1_c2s = mat;
    let k1_s2c = k1_c2s.split_off(32);
    Ok(HandshakeKeys { k1_c2s, k1_s2c })
}

pub(crate) fn derive_shared_secret(
    ecdh_pk: &kem::PrivateKey,
    pqc_pk: &PqcPrivateKey,
    ecdh_ct: &ECDHKey,
    pqc_ct: &[u8],
) -> Result<Vec<u8>, AslError> {
    let ecdh_ct_bytes = validate_ecdh_pk(ecdh_ct)?;
    let ecdh_ct_obj = kem::Ct::decode(kem::Algorithm::Secp256r1, &ecdh_ct_bytes)
        .map_err(|_| AslError::MissingParameters)?;
    let ss_p_ecdh_obj =
        kem::decapsulate(&ecdh_ct_obj, ecdh_pk).map_err(|_| AslError::DecryptionFailure)?;
    let mut ss_p_ecdh = ss_p_ecdh_obj.encode();
    ss_p_ecdh.truncate(32); // restrict to X coordinate, like in TLS 1.3 (RFC 8446 7.4.2)

    let pqc_ct_bytes: [u8; 1088] = pqc_ct.try_into().map_err(|_| AslError::MissingParameters)?;
    let pqc_ct_obj = mlkem768::MlKem768Ciphertext::from(pqc_ct_bytes);
    let ss_p_pqc = mlkem768::decapsulate(pqc_pk, &pqc_ct_obj);

    let mut ss_p = ss_p_ecdh;
    ss_p.extend(ss_p_pqc.as_slice());

    Ok(ss_p)
}

pub(crate) struct SessionKeys {
    pub k2_c2s_key_confirmation: Vec<u8>,
    pub k2_c2s_app_data: Vec<u8>,
    pub k2_s2c_key_confirmation: Vec<u8>,
    pub k2_s2c_app_data: Vec<u8>,
    pub key_id: Vec<u8>,
}

pub(crate) fn derive_session_keys(ss_e: &[u8], ss_s: &[u8]) -> Result<SessionKeys, AslError> {
    let mut ss = Vec::with_capacity(ss_e.len() + ss_s.len());
    ss.extend(ss_e);
    ss.extend(ss_s);

    let mut mat = hkdf_expand(&ss, 160)?;

    Ok(SessionKeys {
        k2_c2s_key_confirmation: mat.drain(..32).collect(),
        k2_c2s_app_data: mat.drain(..32).collect(),
        k2_s2c_key_confirmation: mat.drain(..32).collect(),
        k2_s2c_app_data: mat.drain(..32).collect(),
        key_id: mat.drain(..32).collect(),
    })
}

pub(crate) fn encrypt_handshake(key: &[u8], plain: &[u8]) -> Result<Vec<u8>, AslError> {
    let key_obj = aead::Key::from_slice(aead::Algorithm::Aes256Gcm, key)
        .map_err(|_| AslError::DecodingError)?;
    let iv: aead::Iv = RNG.with_borrow_mut(|rng| aead::Iv::generate(rng));
    let aad: [u8; 0] = []; // unused

    let mut res: Vec<u8> = Vec::with_capacity(12 + plain.len() + 16);
    res.extend(&iv.0);

    let (tag, ct) =
        aead::encrypt_detached(&key_obj, plain, iv, aad).map_err(|_| AslError::InternalError)?;
    res.extend(&ct);
    res.extend(tag.as_ref());

    Ok(res)
}

pub(crate) fn decrypt_handshake(key: &[u8], crypt: &[u8]) -> Result<Vec<u8>, AslError> {
    let key_obj = aead::Key::from_slice(aead::Algorithm::Aes256Gcm, key)
        .map_err(|_| AslError::InternalError)?;
    if crypt.len() < 12 + 16 {
        return Err(AslError::DecryptionFailure);
    };
    let iv_bytes: &[u8; 12] = &crypt[..12]
        .try_into()
        .map_err(|_| AslError::InternalError)?;
    let tag_bytes: &[u8] = &crypt[crypt.len() - 16..];
    let msg: &[u8] = &crypt[12..crypt.len() - 16];
    let aad: [u8; 0] = []; // unused

    let iv = aead::Iv(*iv_bytes);
    let tag = aead::Tag::from_slice(&tag_bytes).map_err(|_| AslError::InternalError)?;
    let plain = aead::decrypt_detached(&key_obj, &msg, iv, &aad, &tag);
    let res = plain.map_err(|_| AslError::DecryptionFailure)?;

    Ok(res)
}

pub(crate) fn encrypt_session(
    key: &aead::Key,
    key_id: &[u8],
    env: Environment,
    mode: MessageMode,
    req_ctr: u64,
    enc_ctr: u64,
    plain: &[u8],
) -> Result<Vec<u8>, AslError> {
    let req_ctr_bytes = req_ctr.to_be_bytes();
    let enc_ctr_bytes = enc_ctr.to_be_bytes();

    let mut header = Vec::with_capacity(43);
    header.push(ASL_VERSION);
    header.push(env.as_byte());
    header.push(mode.as_byte());
    header.extend(req_ctr_bytes);
    header.extend(key_id);

    let iv_random = RNG
        .with_borrow_mut(|rng| rng.generate_vec(4))
        .map_err(|_| AslError::InternalError)?;
    let mut iv_bytes: Vec<u8> = Vec::with_capacity(12);
    iv_bytes.extend(iv_random);
    iv_bytes.extend(enc_ctr_bytes);
    let iv: aead::Iv = aead::Iv::new(&iv_bytes).map_err(|_| AslError::InternalError)?;

    let mut res: Vec<u8> = Vec::with_capacity(12 + plain.len() + 16);
    res.extend(&header);
    res.extend(&iv.0);
    let (tag, ct) =
        aead::encrypt_detached(&key, plain, iv, &header).map_err(|_| AslError::InternalError)?;

    res.extend(&ct);
    res.extend(tag.as_ref());

    Ok(res)
}

pub(crate) fn decrypt_session(
    key: &aead::Key,
    expect_key_id: &[u8],
    expect_env: Environment,
    expect_mode: MessageMode,
    cipher: &[u8],
) -> Result<(u64, Vec<u8>), AslError> {
    if cipher.len() < 72 {
        return Err(AslError::BadFormat);
    }
    let header = &cipher[..43];
    let crypt = &cipher[43..];

    let version = header[0];
    if version != ASL_VERSION {
        return Err(AslError::BadFormat);
    }

    let is_pu = header[1];
    if is_pu != expect_env.as_byte() {
        return Err(AslError::WrongEnvironment);
    }

    let is_req = header[2];
    if is_req != expect_mode.as_byte() {
        return Err(AslError::NotRequest);
    }

    let req_ctr_bytes: [u8; 8] = header[3..11].try_into().map_err(|_| AslError::BadFormat)?;
    let req_ctr = u64::from_be_bytes(req_ctr_bytes);

    let key_id = &header[11..];
    if key_id != expect_key_id {
        return Err(AslError::UnknownKeyID);
    }

    if crypt.len() < 12 + 16 {
        return Err(AslError::DecryptionFailure);
    };
    let iv_bytes: &[u8; 12] = &crypt[..12]
        .try_into()
        .map_err(|_| AslError::InternalError)?;
    let tag_bytes: &[u8] = &crypt[crypt.len() - 16..];
    let msg: &[u8] = &crypt[12..crypt.len() - 16];

    let iv = aead::Iv(*iv_bytes);
    let tag = aead::Tag::from_slice(&tag_bytes).map_err(|_| AslError::InternalError)?;
    let plain = aead::decrypt_detached(&key, &msg, iv, &header, &tag);
    let res = plain.map_err(|_| AslError::DecryptionFailure)?;

    Ok((req_ctr, res))
}
