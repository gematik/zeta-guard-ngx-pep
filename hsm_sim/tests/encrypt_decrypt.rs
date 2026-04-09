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

mod common;

use hsm_sim::proto::{DecryptRequest, EncryptRequest, SymmetricEncryptionAlgorithm};

#[tokio::test]
async fn encrypt_decrypt_roundtrip() {
    let mut client = common::hsm_client().await;

    let plaintext = b"this is a secret DEK for testing".to_vec();
    let key_id = "my-test-kek".to_string();

    let enc_resp = client
        .encrypt(EncryptRequest {
            key_id: key_id.clone(),
            plaintext: plaintext.clone(),
            algorithm: SymmetricEncryptionAlgorithm::Aes256Gcm.into(),
            associated_data: b"some-aad".to_vec(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_ne!(enc_resp.ciphertext, plaintext);
    assert_eq!(enc_resp.iv.len(), 12);
    assert_eq!(enc_resp.tag.len(), 16);

    let dec_resp = client
        .decrypt(DecryptRequest {
            key_id: key_id.clone(),
            ciphertext: enc_resp.ciphertext,
            algorithm: SymmetricEncryptionAlgorithm::Aes256Gcm.into(),
            iv: enc_resp.iv,
            tag: enc_resp.tag,
            associated_data: b"some-aad".to_vec(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(dec_resp.plaintext, plaintext);
}

#[tokio::test]
async fn decrypt_with_wrong_key_id_fails() {
    let mut client = common::hsm_client().await;

    let enc_resp = client
        .encrypt(EncryptRequest {
            key_id: "key-alpha".to_string(),
            plaintext: b"secret data".to_vec(),
            algorithm: SymmetricEncryptionAlgorithm::Aes256Gcm.into(),
            associated_data: vec![],
        })
        .await
        .unwrap()
        .into_inner();

    let result = client
        .decrypt(DecryptRequest {
            key_id: "key-beta".to_string(),
            ciphertext: enc_resp.ciphertext,
            algorithm: SymmetricEncryptionAlgorithm::Aes256Gcm.into(),
            iv: enc_resp.iv,
            tag: enc_resp.tag,
            associated_data: vec![],
        })
        .await;

    assert!(result.is_err(), "decrypt with wrong key_id should fail");
}

#[tokio::test]
async fn decrypt_with_wrong_aad_fails() {
    let mut client = common::hsm_client().await;

    let enc_resp = client
        .encrypt(EncryptRequest {
            key_id: "aad-test-key".to_string(),
            plaintext: b"secret data".to_vec(),
            algorithm: SymmetricEncryptionAlgorithm::Aes256Gcm.into(),
            associated_data: b"correct-aad".to_vec(),
        })
        .await
        .unwrap()
        .into_inner();

    let result = client
        .decrypt(DecryptRequest {
            key_id: "aad-test-key".to_string(),
            ciphertext: enc_resp.ciphertext,
            algorithm: SymmetricEncryptionAlgorithm::Aes256Gcm.into(),
            iv: enc_resp.iv,
            tag: enc_resp.tag,
            associated_data: b"wrong-aad".to_vec(),
        })
        .await;

    assert!(result.is_err(), "decrypt with wrong AAD should fail");
}

#[tokio::test]
async fn decrypt_with_wrong_iv_fails() {
    let mut client = common::hsm_client().await;

    let enc_resp = client
        .encrypt(EncryptRequest {
            key_id: "iv-test-key".to_string(),
            plaintext: b"secret data".to_vec(),
            algorithm: SymmetricEncryptionAlgorithm::Aes256Gcm.into(),
            associated_data: vec![],
        })
        .await
        .unwrap()
        .into_inner();

    let wrong_iv = vec![0xffu8; 12];

    let result = client
        .decrypt(DecryptRequest {
            key_id: "iv-test-key".to_string(),
            ciphertext: enc_resp.ciphertext,
            algorithm: SymmetricEncryptionAlgorithm::Aes256Gcm.into(),
            iv: wrong_iv,
            tag: enc_resp.tag,
            associated_data: vec![],
        })
        .await;

    assert!(result.is_err(), "decrypt with wrong IV should fail");
}
