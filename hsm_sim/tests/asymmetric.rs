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

use hsm_sim::proto::{DigestAlgorithm, GetCertificateRequest, GetPublicKeyRequest, SignRequest};

#[tokio::test]
async fn get_public_key_p256() {
    let mut client = common::hsm_client().await;

    let resp = client
        .get_public_key(GetPublicKeyRequest {
            key_id: "test-key.p256".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(
        resp.public_key_pem
            .starts_with("-----BEGIN PUBLIC KEY-----")
    );
    assert!(!resp.public_key_der.is_empty());
    assert!(resp.jwk_json.contains("\"crv\":\"P-256\""));
}

#[tokio::test]
async fn get_public_key_is_deterministic() {
    let mut client = common::hsm_client().await;

    let resp1 = client
        .get_public_key(GetPublicKeyRequest {
            key_id: "determinism.p256".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    let resp2 = client
        .get_public_key(GetPublicKeyRequest {
            key_id: "determinism.p256".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp1.public_key_pem, resp2.public_key_pem);
    assert_eq!(resp1.public_key_der, resp2.public_key_der);
    assert_eq!(resp1.jwk_json, resp2.jwk_json);
}

#[tokio::test]
async fn get_public_key_different_key_ids_differ() {
    let mut client = common::hsm_client().await;

    let resp_a = client
        .get_public_key(GetPublicKeyRequest {
            key_id: "key-a.p256".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    let resp_b = client
        .get_public_key(GetPublicKeyRequest {
            key_id: "key-b.p256".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_ne!(resp_a.public_key_der, resp_b.public_key_der);
}

#[tokio::test]
async fn get_public_key_invalid_suffix_rejected() {
    let mut client = common::hsm_client().await;

    let result = client
        .get_public_key(GetPublicKeyRequest {
            key_id: "no-curve-suffix".to_string(),
        })
        .await;

    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn sign_and_verify_p256() {
    let mut client = common::hsm_client().await;
    let key_id = "sign-test.p256".to_string();

    let pub_resp = client
        .get_public_key(GetPublicKeyRequest {
            key_id: key_id.clone(),
        })
        .await
        .unwrap()
        .into_inner();

    // Hash the data ourselves (NONE = pre-hashed)
    let data = b"hello world";
    let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), data).unwrap();

    let sign_resp = client
        .sign(SignRequest {
            key_id: key_id.clone(),
            data: digest.to_vec(),
            algorithm: DigestAlgorithm::None.into(),
        })
        .await
        .unwrap()
        .into_inner();

    // Signature should be 64 bytes (P-256 P1363: 32+32)
    assert_eq!(sign_resp.signature.len(), 64);

    // Verify: convert P1363 -> DER, verify with public key
    let r = openssl::bn::BigNum::from_slice(&sign_resp.signature[..32]).unwrap();
    let s = openssl::bn::BigNum::from_slice(&sign_resp.signature[32..]).unwrap();
    let ecdsa_sig = openssl::ecdsa::EcdsaSig::from_private_components(r, s).unwrap();

    let pkey = openssl::pkey::PKey::public_key_from_der(&pub_resp.public_key_der).unwrap();
    let ec_key = pkey.ec_key().unwrap();
    assert!(ecdsa_sig.verify(&digest, &ec_key).unwrap());
}

#[tokio::test]
async fn sign_with_server_side_hashing() {
    let mut client = common::hsm_client().await;
    let key_id = "hash-test.p256".to_string();

    let pub_resp = client
        .get_public_key(GetPublicKeyRequest {
            key_id: key_id.clone(),
        })
        .await
        .unwrap()
        .into_inner();

    let data = b"server will hash this";

    let sign_resp = client
        .sign(SignRequest {
            key_id: key_id.clone(),
            data: data.to_vec(),
            algorithm: DigestAlgorithm::Sha256.into(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(sign_resp.signature.len(), 64);

    // Verify: we hash locally to get the same digest the server used
    let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), data).unwrap();
    let r = openssl::bn::BigNum::from_slice(&sign_resp.signature[..32]).unwrap();
    let s = openssl::bn::BigNum::from_slice(&sign_resp.signature[32..]).unwrap();
    let ecdsa_sig = openssl::ecdsa::EcdsaSig::from_private_components(r, s).unwrap();

    let pkey = openssl::pkey::PKey::public_key_from_der(&pub_resp.public_key_der).unwrap();
    let ec_key = pkey.ec_key().unwrap();
    assert!(ecdsa_sig.verify(&digest, &ec_key).unwrap());
}

#[tokio::test]
async fn get_certificate_returns_valid_chain() {
    let mut client = common::hsm_client().await;
    let key_id = "cert-test.p256".to_string();

    let resp = client
        .get_certificate(GetCertificateRequest {
            key_id: key_id.clone(),
        })
        .await
        .unwrap()
        .into_inner();

    // Leaf cert
    assert!(
        resp.certificate_pem
            .starts_with("-----BEGIN CERTIFICATE-----")
    );
    let leaf = openssl::x509::X509::from_pem(resp.certificate_pem.as_bytes()).unwrap();
    assert_eq!(
        leaf.subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .unwrap()
            .data()
            .as_utf8()
            .unwrap()
            .to_string(),
        key_id
    );

    // Chain: [leaf, CA]
    assert_eq!(resp.certificate_chain_pem.len(), 2);
    let ca = openssl::x509::X509::from_pem(resp.certificate_chain_pem[1].as_bytes()).unwrap();
    assert_eq!(
        ca.subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .unwrap()
            .data()
            .as_utf8()
            .unwrap()
            .to_string(),
        "HSM Simulator CA"
    );

    // Verify leaf is signed by CA
    let ca_pkey = ca.public_key().unwrap();
    assert!(leaf.verify(&ca_pkey).unwrap());
}

#[tokio::test]
async fn get_certificate_is_deterministic() {
    let mut client = common::hsm_client().await;

    let resp1 = client
        .get_certificate(GetCertificateRequest {
            key_id: "det-cert.p256".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    let resp2 = client
        .get_certificate(GetCertificateRequest {
            key_id: "det-cert.p256".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp1.certificate_pem, resp2.certificate_pem);
}

#[tokio::test]
async fn get_certificate_leaf_matches_public_key() {
    let mut client = common::hsm_client().await;
    let key_id = "key-cert-match.p256".to_string();

    let pub_resp = client
        .get_public_key(GetPublicKeyRequest {
            key_id: key_id.clone(),
        })
        .await
        .unwrap()
        .into_inner();

    let cert_resp = client
        .get_certificate(GetCertificateRequest {
            key_id: key_id.clone(),
        })
        .await
        .unwrap()
        .into_inner();

    let leaf = openssl::x509::X509::from_pem(cert_resp.certificate_pem.as_bytes()).unwrap();
    let cert_pubkey_der = leaf.public_key().unwrap().public_key_to_der().unwrap();

    assert_eq!(cert_pubkey_der, pub_resp.public_key_der);
}
