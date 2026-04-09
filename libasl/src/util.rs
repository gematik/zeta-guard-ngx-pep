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

use super::model::*;
use anyhow::anyhow;
use libcrux_aead::Aead;
use libcrux_kem as kem;
use libcrux_ml_kem::mlkem768;
use libcrux_traits::aead::typed_refs::Aead as _;
#[cfg(test)]
use rand::SeedableRng;
use rand::{Rng, RngCore};
use std::cell::RefCell;
use std::time::{SystemTime, UNIX_EPOCH};

thread_local! {
    #[cfg(test)]
    pub static RNG: RefCell<rand::rngs::StdRng> = RefCell::new(
        rand::rngs::StdRng::from_seed([
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        ])
    );
    #[cfg(not(test))]
    pub static RNG: RefCell<rand::rngs::ThreadRng> = RefCell::new(rand::rng());
}

pub fn utc_now() -> u64 {
    let now = SystemTime::now();
    let since_epoch = now
        .duration_since(UNIX_EPOCH)
        .expect("system time before epoch");
    since_epoch.as_secs()
}

pub(crate) fn hkdf_expand(secret: &[u8], out: &mut [u8]) -> Result<(), AslError> {
    // Note: This emulates the reference implementation, which uses a zero salt block and empty info
    let salt = [0u8; 32]; // 32 zeroes block
    let info = [0u8; 0]; // empty
    libcrux_hkdf::hkdf(libcrux_hkdf::Algorithm::Sha256, out, &salt, secret, &info)
        .map_err(|_| anyhow!("hkdf failure"))?;
    Ok(())
}

pub(crate) fn validate_ecdh_pk(pk: &ECDHKey) -> Result<[u8; 64], AslError> {
    if pk.crv != "P-256" || pk.x.len() != 32 || pk.y.len() != 32 {
        return Err(AslError::MissingParameters);
    }
    let mut encoded = [0u8; 64];
    encoded[..32].copy_from_slice(&pk.x);
    encoded[32..].copy_from_slice(&pk.y);
    Ok(encoded)
}

pub(crate) fn validate_pqc_pk(pk: &[u8]) -> Result<[u8; PQC_PK_SIZE], AslError> {
    if pk.len() != PQC_PK_SIZE {
        return Err(AslError::MissingParameters);
    }
    let arr: [u8; PQC_PK_SIZE] = pk.try_into().to_error().map_err(AslError::DecodingError)?;
    Ok(arr)
}

pub(crate) struct HandshakeMaterial {
    pub ss_p: [u8; 64], // either ss_e or ss_s, depending on where it is used
    pub ecdh_ct: Vec<u8>,
    pub pqc_ct: Vec<u8>,
}

pub(crate) fn derive_handshake_material(
    ecdh_pk: &ECDHKey,
    pqc_pk: &[u8],
) -> Result<HandshakeMaterial, AslError> {
    let ecdh_pk_bytes = validate_ecdh_pk(ecdh_pk)?;
    let ecdh_pk_obj = kem::PublicKey::decode(kem::Algorithm::Secp256r1, &ecdh_pk_bytes)
        .to_error()
        .map_err(AslError::DecodingError)?;

    let pqc_pk_bytes = validate_pqc_pk(pqc_pk)?;
    let pqc_pk_obj = libcrux_ml_kem::MlKemPublicKey::from(pqc_pk_bytes);

    let (ss_p, ecdh_ct, pqc_ct) = RNG.with_borrow_mut(|rng| -> Result<_, AslError> {
        let (ss_p_ecdh_t1, ecdh_ct_t) = ecdh_pk_obj.encapsulate(rng).to_error()?;
        let ss_p_ecdh_enc = ss_p_ecdh_t1.encode();

        let pqc_random: [u8; 32] = rng.random();
        let (pqc_ct_t, ss_p_pqc_t) = mlkem768::encapsulate(&pqc_pk_obj, pqc_random);

        let mut ss_p = [0u8; 64];
        // ..32: restrict to X coordinate, like in TLS 1.3 (RFC 8446 7.4.2)
        ss_p[..32].copy_from_slice(&ss_p_ecdh_enc[..32]);
        ss_p[32..].copy_from_slice(ss_p_pqc_t.as_slice());
        Ok((ss_p, ecdh_ct_t.encode(), pqc_ct_t.as_slice().to_vec()))
    })?;

    Ok(HandshakeMaterial {
        ss_p,
        ecdh_ct,
        pqc_ct,
    })
}

pub(crate) struct HandshakeKeys {
    pub k1_c2s: [u8; 32],
    pub k1_s2c: [u8; 32],
}

pub(crate) fn derive_handshake_keys(ss_p: &[u8]) -> Result<HandshakeKeys, AslError> {
    let mut mat = [0u8; 64];
    hkdf_expand(ss_p, &mut mat)?;
    let mut k1_c2s = [0u8; 32];
    let mut k1_s2c = [0u8; 32];
    k1_c2s.copy_from_slice(&mat[..32]);
    k1_s2c.copy_from_slice(&mat[32..]);
    Ok(HandshakeKeys { k1_c2s, k1_s2c })
}

pub(crate) fn derive_shared_secret(
    ecdh_sk: &kem::PrivateKey,
    pqc_sk: &PqcPrivateKey,
    ecdh_ct: &ECDHKey,
    pqc_ct: &[u8],
) -> Result<[u8; 64], AslError> {
    let ecdh_ct_bytes = validate_ecdh_pk(ecdh_ct)?;
    let ecdh_ct_obj = kem::Ct::decode(kem::Algorithm::Secp256r1, &ecdh_ct_bytes)
        .map_err(|_| AslError::MissingParameters)?;
    let ss_p_ecdh_obj = ecdh_ct_obj
        .decapsulate(ecdh_sk)
        .map_err(|_| AslError::DecryptionFailure)?;
    let ss_p_ecdh_enc = ss_p_ecdh_obj.encode();

    let pqc_ct_bytes: [u8; 1088] = pqc_ct.try_into().map_err(|_| AslError::MissingParameters)?;
    let pqc_ct_obj = mlkem768::MlKem768Ciphertext::from(pqc_ct_bytes);
    let ss_p_pqc = mlkem768::decapsulate(pqc_sk, &pqc_ct_obj);

    let mut ss_p = [0u8; 64];

    // ..32: restrict to X coordinate, like in TLS 1.3 (RFC 8446 7.4.2)
    ss_p[..32].copy_from_slice(&ss_p_ecdh_enc[..32]);
    ss_p[32..].copy_from_slice(ss_p_pqc.as_slice());

    Ok(ss_p)
}

pub(crate) struct SessionKeys {
    pub k2_c2s_key_confirmation: [u8; 32],
    pub k2_c2s_app_data: [u8; 32],
    pub k2_s2c_key_confirmation: [u8; 32],
    pub k2_s2c_app_data: [u8; 32],
    pub key_id: [u8; 32],
}

pub(crate) fn derive_session_keys(
    ss_e: &[u8; 64],
    ss_s: &[u8; 64],
) -> Result<SessionKeys, AslError> {
    let mut ss = [0u8; 128];
    ss[..64].copy_from_slice(ss_e);
    ss[64..].copy_from_slice(ss_s);
    let mut mat = [0u8; 160];
    hkdf_expand(&ss, &mut mat)?;

    // Safety: all slices are exactly 32 bytes from a 160-byte buffer
    let at = |i: usize| -> [u8; 32] { mat[i * 32..(i + 1) * 32].try_into().unwrap() };
    Ok(SessionKeys {
        k2_c2s_key_confirmation: at(0),
        k2_c2s_app_data: at(1),
        k2_s2c_key_confirmation: at(2),
        k2_s2c_app_data: at(3),
        key_id: at(4),
    })
}

/// Overhead for handshake AEAD: IV + tag
pub(crate) const HANDSHAKE_OVERHEAD: usize = 12 + 16;

/// Encrypt `plain` into `out`, which must be exactly `plain.len() + HANDSHAKE_OVERHEAD` bytes.
/// Layout: iv (12) || ciphertext (N) || tag (16).
pub(crate) fn encrypt_handshake(
    key_bytes: &[u8],
    plain: &[u8],
    out: &mut [u8],
) -> Result<(), AslError> {
    assert_eq!(out.len(), HANDSHAKE_OVERHEAD + plain.len());

    let algo = Aead::AesGcm256;
    let key = algo
        .new_key(key_bytes)
        .map_err(|_| anyhow!("invalid key length"))?;

    RNG.with_borrow_mut(|rng| rng.fill_bytes(&mut out[..12]));

    let (iv_slice, rest) = out.split_at_mut(12);
    let (ct_buf, _tag_buf) = rest.split_at_mut(plain.len());

    let nonce = algo
        .new_nonce(iv_slice)
        .map_err(|_| anyhow!("invalid nonce"))?;
    let mut tag_bytes = [0u8; 16];
    let tag = algo
        .new_tag_mut(&mut tag_bytes)
        .map_err(|_| anyhow!("invalid tag"))?;

    let aad: [u8; 0] = []; // unused
    key.encrypt(ct_buf, tag, nonce, &aad, plain)
        .map_err(|e| anyhow!("aead encrypt: {e}"))?;

    out[12 + plain.len()..].copy_from_slice(&tag_bytes);
    Ok(())
}

/// Decrypt `crypt` into `out`, which must be exactly `crypt.len() - HANDSHAKE_OVERHEAD` bytes.
pub(crate) fn decrypt_handshake(
    key_bytes: &[u8],
    crypt: &[u8],
    out: &mut [u8],
) -> Result<(), AslError> {
    if crypt.len() < HANDSHAKE_OVERHEAD {
        return Err(AslError::DecryptionFailure);
    }
    let plain_len = crypt.len() - HANDSHAKE_OVERHEAD;
    assert_eq!(out.len(), plain_len);

    let algo = Aead::AesGcm256;
    let key = algo
        .new_key(key_bytes)
        .map_err(|_| anyhow!("invalid key length"))?;

    let iv = &crypt[..12];
    let tag_slice = &crypt[crypt.len() - 16..];
    let ct = &crypt[12..crypt.len() - 16];

    let nonce = algo
        .new_nonce(iv)
        .map_err(|_| AslError::DecryptionFailure)?;
    let tag = algo
        .new_tag(tag_slice)
        .map_err(|_| AslError::DecryptionFailure)?;
    let aad: [u8; 0] = []; // unused
    key.decrypt(out, nonce, &aad, ct, tag)
        .map_err(|_| AslError::DecryptionFailure)?;

    Ok(())
}

/// Session header size: 1 (version) + 1 (env) + 1 (mode) + 8 (req_ctr) + 32 (key_id) = 43
const SESSION_HEADER_SIZE: usize = 43;
/// Overhead per encrypted session message: header + IV + tag
pub const SESSION_OVERHEAD: usize = SESSION_HEADER_SIZE + 12 + 16;

/// Encrypt `plain` into `out`, which must be exactly `plain.len() + SESSION_OVERHEAD` bytes.
/// Layout: header (43) || iv (12) || ciphertext (N) || tag (16).
#[allow(clippy::too_many_arguments)]
pub(crate) fn encrypt_session(
    key_bytes: &[u8; 32],
    key_id: &[u8; 32],
    env: Environment,
    mode: MessageMode,
    req_ctr: u64,
    enc_ctr: u64,
    plain: &[u8],
    out: &mut [u8],
) -> Result<(), AslError> {
    assert_eq!(out.len(), SESSION_OVERHEAD + plain.len());

    let algo = Aead::AesGcm256;
    let key = algo
        .new_key(key_bytes)
        .map_err(|_| anyhow!("invalid key length"))?;

    // Write header in-place
    out[0] = ASL_VERSION;
    out[1] = env.as_byte();
    out[2] = mode.as_byte();
    out[3..11].copy_from_slice(&req_ctr.to_be_bytes());
    out[11..43].copy_from_slice(key_id);

    // Build IV: 4 random bytes || enc_ctr
    RNG.with_borrow_mut(|rng| {
        rng.fill_bytes(&mut out[SESSION_HEADER_SIZE..SESSION_HEADER_SIZE + 4])
    });
    out[SESSION_HEADER_SIZE + 4..SESSION_HEADER_SIZE + 12].copy_from_slice(&enc_ctr.to_be_bytes());

    // Encrypt: ciphertext at [55..55+N], tag at [55+N..71+N]
    let ct_start = SESSION_HEADER_SIZE + 12;
    let (pre, rest) = out.split_at_mut(ct_start);
    let (ct_buf, tag_buf) = rest.split_at_mut(plain.len());

    let nonce = algo
        .new_nonce(&pre[SESSION_HEADER_SIZE..])
        .map_err(|_| anyhow!("invalid nonce"))?;
    let mut tag_bytes = [0u8; 16];
    let tag = algo
        .new_tag_mut(&mut tag_bytes)
        .map_err(|_| anyhow!("invalid tag"))?;

    key.encrypt(ct_buf, tag, nonce, &pre[..SESSION_HEADER_SIZE], plain)
        .map_err(|e| anyhow!("aead encrypt: {e}"))?;

    tag_buf.copy_from_slice(&tag_bytes);
    Ok(())
}

/// Decrypt `cipher` into `out`, which must be exactly `cipher.len() - SESSION_OVERHEAD` bytes.
/// Returns the request counter from the header.
pub(crate) fn decrypt_session(
    key_bytes: &[u8; 32],
    expect_key_id: &[u8; 32],
    expect_env: Environment,
    expect_mode: MessageMode,
    cipher: &[u8],
    out: &mut [u8],
) -> Result<u64, AslError> {
    if cipher.len() < SESSION_OVERHEAD + 1 {
        return Err(AslError::BadFormat);
    }
    let plain_len = cipher.len() - SESSION_OVERHEAD;
    assert_eq!(out.len(), plain_len);

    let algo = Aead::AesGcm256;
    let key = algo
        .new_key(key_bytes)
        .map_err(|_| anyhow!("invalid key length"))?;

    let header = &cipher[..SESSION_HEADER_SIZE];
    let crypt = &cipher[SESSION_HEADER_SIZE..];

    if header[0] != ASL_VERSION {
        return Err(AslError::BadFormat);
    }
    if header[1] != expect_env.as_byte() {
        return Err(AslError::WrongEnvironment);
    }
    if header[2] != expect_mode.as_byte() {
        return Err(AslError::NotRequest);
    }

    let req_ctr = u64::from_be_bytes(header[3..11].try_into().map_err(|_| AslError::BadFormat)?);

    if &header[11..] != expect_key_id {
        return Err(AslError::UnknownKeyID);
    }

    let iv = &crypt[..12];
    let tag_slice = &crypt[crypt.len() - 16..];
    let ct = &crypt[12..crypt.len() - 16];

    let nonce = algo
        .new_nonce(iv)
        .map_err(|_| AslError::DecryptionFailure)?;
    let tag = algo
        .new_tag(tag_slice)
        .map_err(|_| AslError::DecryptionFailure)?;

    key.decrypt(out, nonce, header, ct, tag)
        .map_err(|_| AslError::DecryptionFailure)?;

    Ok(req_ctr)
}
