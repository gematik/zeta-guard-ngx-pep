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

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::{X509, X509Builder, X509NameBuilder};
use tonic::{Request, Response, Status};

pub mod proto {
    tonic::include_proto!("gematik.zetaguard.hsmproxy.v1");

    pub const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("hsm_proxy_descriptor");
}

use proto::hsm_proxy_service_server::HsmProxyService;
use proto::{
    DecryptRequest, DecryptResponse, DigestAlgorithm, EccCurve, EncryptRequest, EncryptResponse,
    GetCertificateRequest, GetCertificateResponse, GetPublicKeyRequest, GetPublicKeyResponse,
    HealthCheckRequest, HealthCheckResponse, SignRequest, SignResponse,
    SymmetricEncryptionAlgorithm, health_check_response::ServingStatus,
};

// not gated so we can import it from nginx module its easily.
// hsm_sim is test infra anyways, so we don't need to control the compilation unit as tightly
pub mod tests;

// =============================================================================
// Error conversion
// =============================================================================

fn internal(err: anyhow::Error) -> Status {
    Status::internal(format!("{err:#}"))
}

// =============================================================================
// Certificate Authority — loaded from ca.key + ca.crt
// =============================================================================

pub struct CertAuthority {
    key: PKey<Private>,
    cert: X509,
}

impl CertAuthority {
    pub fn load(dir: &Path) -> Result<Self> {
        let key_pem = std::fs::read(dir.join("ca.key")).context("reading ca.key")?;
        let key = PKey::private_key_from_pem(&key_pem).context("parsing ca.key")?;
        let cert_pem = std::fs::read(dir.join("ca.crt")).context("reading ca.crt")?;
        let cert = X509::from_pem(&cert_pem).context("parsing ca.crt")?;
        Ok(Self { key, cert })
    }
}

// =============================================================================
// HKDF-based EC key derivation
// =============================================================================

fn parse_curve(key_id: &str) -> Result<(Nid, EccCurve, usize), Status> {
    if key_id.ends_with(".p256") {
        Ok((Nid::X9_62_PRIME256V1, EccCurve::NistP256, 32))
    } else if key_id.ends_with(".p384") {
        Ok((Nid::SECP384R1, EccCurve::NistP384, 48))
    } else if key_id.ends_with(".p521") {
        Ok((Nid::SECP521R1, EccCurve::NistP521, 66))
    } else {
        Err(Status::invalid_argument(
            "key_id must end with .p256, .p384, or .p521",
        ))
    }
}

/// Derive a deterministic EC private key from a key_id via HKDF-SHA256.
/// The curve is parsed from the key_id suffix (.p256, .p384, .p521).
fn derive_ec_key(key_id: &str, nid: Nid, scalar_len: usize) -> Result<EcKey<Private>> {
    let mut raw = vec![0u8; scalar_len];
    openssl::kdf::hkdf(
        openssl::md::Md::sha256(),
        key_id.as_bytes(),
        Some(b"hsm_sim_ec_salt"),
        Some(b"hsm_sim_ec_private_key"),
        openssl::kdf::HkdfMode::ExtractAndExpand,
        None,
        &mut raw,
    )
    .context("HKDF")?;

    // Convert raw bytes to a valid EC private key scalar in [1, order-1]
    let group = EcGroup::from_curve_name(nid).context("EcGroup")?;
    let mut ctx = BigNumContext::new().context("BigNumContext")?;

    let mut order = BigNum::new().context("BigNum")?;
    group.order(&mut order, &mut ctx).context("curve order")?;

    let raw_bn = BigNum::from_slice(&raw).context("BigNum from_slice")?;

    // scalar = (raw mod (order - 1)) + 1, ensuring scalar in [1, order-1]
    let one = BigNum::from_u32(1).context("BigNum")?;
    let mut order_minus_1 = BigNum::new().context("BigNum")?;
    order_minus_1
        .checked_sub(&order, &one)
        .context("order - 1")?;

    let mut scalar = BigNum::new().context("BigNum")?;
    scalar
        .nnmod(&raw_bn, &order_minus_1, &mut ctx)
        .context("nnmod")?;
    scalar.add_word(1).context("add_word")?;

    // Compute public key = scalar * generator
    let mut pub_point = EcPoint::new(&group).context("EcPoint")?;
    pub_point
        .mul_generator(&group, &scalar, &ctx)
        .context("mul_generator")?;

    let ec_key =
        EcKey::from_private_components(&group, &scalar, &pub_point).context("EcKey build")?;
    ec_key.check_key().context("EC key check")?;

    Ok(ec_key)
}

/// Derive a serial number from key_id via HKDF (16 bytes, positive).
fn derive_serial(key_id: &str) -> Result<Asn1Integer> {
    let mut raw = [0u8; 16];
    openssl::kdf::hkdf(
        openssl::md::Md::sha256(),
        key_id.as_bytes(),
        Some(b"hsm_sim_ec_salt"),
        Some(b"hsm_sim_cert_serial"),
        openssl::kdf::HkdfMode::ExtractAndExpand,
        None,
        &mut raw,
    )
    .context("HKDF")?;

    // Ensure the high bit is clear so the serial is positive
    raw[0] &= 0x7f;

    let bn = BigNum::from_slice(&raw).context("BigNum")?;
    Asn1Integer::from_bn(&bn).context("Asn1Integer")
}

/// Generate a leaf certificate signed by the CA.
fn generate_cert(key_id: &str, ec_key: &EcKey<Private>, ca: &CertAuthority) -> Result<X509> {
    let pkey = PKey::from_ec_key(ec_key.clone()).context("PKey from EcKey")?;

    let mut builder = X509Builder::new().context("X509Builder")?;
    builder.set_version(2).context("set_version")?; // v3

    let serial = derive_serial(key_id)?;
    builder.set_serial_number(&serial).context("set_serial")?;

    let mut name_builder = X509NameBuilder::new().context("X509NameBuilder")?;
    name_builder
        .append_entry_by_text("CN", key_id)
        .context("append CN")?;
    let subject = name_builder.build();
    builder.set_subject_name(&subject).context("set_subject")?;

    builder
        .set_issuer_name(ca.cert.subject_name())
        .context("set_issuer")?;

    // notBefore: Unix epoch
    let not_before = Asn1Time::from_unix(0).context("not_before")?;
    builder
        .set_not_before(&not_before)
        .context("set_not_before")?;

    // notAfter: 2337-01-01T00:00:00Z
    let not_after = Asn1Time::from_unix(11_581_401_600).context("not_after")?;
    builder.set_not_after(&not_after).context("set_not_after")?;

    builder.set_pubkey(&pkey).context("set_pubkey")?;

    builder
        .sign(&ca.key, MessageDigest::sha256())
        .context("sign cert")?;

    Ok(builder.build())
}

// =============================================================================
// Persistent disk cache with atomic writes
// =============================================================================

/// Filesystem cache that uses atomic write (write to temp file, rename) to
/// prevent readers from seeing partially written files.
pub struct CacheDir {
    dir: PathBuf,
}

impl CacheDir {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Read a cached file, or return None if it doesn't exist.
    async fn read(&self, name: &str) -> Option<Vec<u8>> {
        tokio::fs::read(self.dir.join(name)).await.ok()
    }

    /// Atomically write a file: write to a temp file (via mkstemp) in the
    /// same directory, then rename into place. Readers never see partial
    /// content. Best-effort — logs a warning on failure.
    async fn write(&self, name: &str, data: &[u8]) {
        use std::io::Write;

        let target = self.dir.join(name);
        let dir = self.dir.clone();
        let data = data.to_vec();
        let _ = tokio::task::spawn_blocking(move || -> Result<()> {
            let mut tmp = tempfile::NamedTempFile::new_in(&dir).context("creating temp file")?;
            tmp.write_all(&data).context("writing temp file")?;
            tmp.persist(&target)
                .map_err(|e| anyhow::anyhow!("rename to {}: {e}", target.display()))?;
            Ok(())
        })
        .await
        .ok()
        .and_then(|r| {
            if let Err(e) = &r {
                eprintln!("[hsm_sim] Warning: cache write failed for {name}: {e:#}");
            }
            r.ok()
        });
    }

    /// Load or derive+cache an EC key.
    async fn ec_key(&self, key_id: &str) -> Result<(EcKey<Private>, EccCurve), Status> {
        let (nid, curve, scalar_len) = parse_curve(key_id)?;
        let file = format!("{key_id}.key.pem");

        if let Some(pem) = self.read(&file).await {
            let ec_key = tokio::task::spawn_blocking(move || -> Result<EcKey<Private>> {
                let pkey = PKey::private_key_from_pem(&pem).context("parsing cached key")?;
                pkey.ec_key().context("ec_key from cached PKey")
            })
            .await
            .map_err(|e| Status::internal(format!("spawn_blocking: {e}")))?
            .map_err(internal)?;
            return Ok((ec_key, curve));
        }

        let kid = key_id.to_string();
        let (ec_key, pem) =
            tokio::task::spawn_blocking(move || -> Result<(EcKey<Private>, Vec<u8>)> {
                let ec_key = derive_ec_key(&kid, nid, scalar_len)?;
                let pkey = PKey::from_ec_key(ec_key.clone()).context("PKey")?;
                let pem = pkey.private_key_to_pem_pkcs8().context("PEM encode")?;
                Ok((ec_key, pem))
            })
            .await
            .map_err(|e| Status::internal(format!("spawn_blocking: {e}")))?
            .map_err(internal)?;

        self.write(&file, &pem).await;

        Ok((ec_key, curve))
    }

    /// Load or derive+generate+cache a certificate.
    async fn cert(
        &self,
        key_id: &str,
        ec_key: &EcKey<Private>,
        ca: &Arc<CertAuthority>,
    ) -> Result<X509, Status> {
        let file = format!("{key_id}.cert.pem");

        if let Some(pem) = self.read(&file).await {
            let cert = tokio::task::spawn_blocking(move || -> Result<X509> {
                X509::from_pem(&pem).context("parsing cached cert")
            })
            .await
            .map_err(|e| Status::internal(format!("spawn_blocking: {e}")))?
            .map_err(internal)?;
            return Ok(cert);
        }

        let kid = key_id.to_string();
        let ek = ec_key.clone();
        let ca = ca.clone();
        let (cert, pem) = tokio::task::spawn_blocking(move || -> Result<(X509, Vec<u8>)> {
            let cert = generate_cert(&kid, &ek, &ca)?;
            let pem = cert.to_pem().context("cert to_pem")?;
            Ok((cert, pem))
        })
        .await
        .map_err(|e| Status::internal(format!("spawn_blocking: {e}")))?
        .map_err(internal)?;

        self.write(&file, &pem).await;

        Ok(cert)
    }
}

// =============================================================================
// AES key derivation (for symmetric Encrypt/Decrypt)
// =============================================================================

fn derive_aes_key(key_id: &str) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    openssl::kdf::hkdf(
        openssl::md::Md::sha256(),
        key_id.as_bytes(),
        Some(b"hsm_sim_kek_salt"),
        Some(b"hsm_sim_aes256_key"),
        openssl::kdf::HkdfMode::ExtractAndExpand,
        None,
        &mut key,
    )
    .context("HKDF")?;
    Ok(key)
}

// =============================================================================
// gRPC service implementation
// =============================================================================

pub struct HsmProxyServiceImpl {
    pub ca: Option<Arc<CertAuthority>>,
    pub cache: CacheDir,
}

#[tonic::async_trait]
impl HsmProxyService for HsmProxyServiceImpl {
    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let req = request.into_inner();

        let (ec_key, curve) = self.cache.ec_key(&req.key_id).await?;

        eprintln!(
            "[hsm_sim] Sign request: key_id='{}', data_len={}, algorithm={:?}",
            req.key_id,
            req.data.len(),
            DigestAlgorithm::try_from(req.algorithm).unwrap_or(DigestAlgorithm::None),
        );

        let digest_algorithm = DigestAlgorithm::try_from(req.algorithm)
            .map_err(|_| Status::invalid_argument("Invalid digest algorithm"))?;

        let signature = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
            let digest = match digest_algorithm {
                DigestAlgorithm::None => {
                    let expected_len = match curve {
                        EccCurve::NistP256 => 32,
                        EccCurve::NistP384 => 48,
                        EccCurve::NistP521 => 64,
                        _ => anyhow::bail!("Unsupported curve"),
                    };
                    anyhow::ensure!(
                        req.data.len() == expected_len,
                        "Pre-hashed data must be {expected_len} bytes for {curve:?}, got {}",
                        req.data.len()
                    );
                    req.data.clone()
                }
                DigestAlgorithm::Sha256 => openssl::hash::hash(MessageDigest::sha256(), &req.data)
                    .context("SHA-256")?
                    .to_vec(),
                DigestAlgorithm::Sha384 => openssl::hash::hash(MessageDigest::sha384(), &req.data)
                    .context("SHA-384")?
                    .to_vec(),
                DigestAlgorithm::Sha512 => openssl::hash::hash(MessageDigest::sha512(), &req.data)
                    .context("SHA-512")?
                    .to_vec(),
            };

            let ecdsa_sig =
                openssl::ecdsa::EcdsaSig::sign(&digest, &ec_key).context("ECDSA sign")?;

            // Convert to IEEE P1363 format (raw R|S)
            let r = ecdsa_sig.r().to_vec();
            let s = ecdsa_sig.s().to_vec();

            let component_len = match curve {
                EccCurve::NistP256 => 32,
                EccCurve::NistP384 => 48,
                EccCurve::NistP521 => 66,
                _ => anyhow::bail!("Unsupported curve"),
            };

            let mut signature = vec![0u8; component_len * 2];
            let r_offset = component_len - r.len();
            let s_offset = component_len - s.len();
            signature[r_offset..component_len].copy_from_slice(&r);
            signature[component_len + s_offset..].copy_from_slice(&s);

            Ok(signature)
        })
        .await
        .map_err(|e| Status::internal(format!("spawn_blocking: {e}")))?
        .map_err(internal)?;

        eprintln!(
            "[hsm_sim] Signed with key '{}': {} bytes P1363",
            req.key_id,
            signature.len()
        );

        Ok(Response::new(SignResponse {
            signature,
            key_id: req.key_id,
        }))
    }

    async fn get_public_key(
        &self,
        request: Request<GetPublicKeyRequest>,
    ) -> Result<Response<GetPublicKeyResponse>, Status> {
        let req = request.into_inner();
        let (ec_key, curve) = self.cache.ec_key(&req.key_id).await?;

        eprintln!("[hsm_sim] GetPublicKey request: key_id='{}'", req.key_id);

        let resp = tokio::task::spawn_blocking(move || -> Result<GetPublicKeyResponse> {
            let pkey = PKey::from_ec_key(ec_key.clone()).context("PKey")?;
            let pem = pkey.public_key_to_pem().context("public key PEM")?;
            let pem_str = String::from_utf8(pem).context("PEM UTF-8")?;
            let der = pkey.public_key_to_der().context("public key DER")?;

            let mut ctx = BigNumContext::new().context("BigNumContext")?;
            let pub_bytes = ec_key
                .public_key()
                .to_bytes(
                    ec_key.group(),
                    openssl::ec::PointConversionForm::UNCOMPRESSED,
                    &mut ctx,
                )
                .context("EC point encode")?;

            let (crv, coord_len) = match curve {
                EccCurve::NistP256 => ("P-256", 32),
                EccCurve::NistP384 => ("P-384", 48),
                EccCurve::NistP521 => ("P-521", 66),
                _ => anyhow::bail!("Unsupported curve"),
            };

            let x = &pub_bytes[1..1 + coord_len];
            let y = &pub_bytes[1 + coord_len..1 + 2 * coord_len];

            let x_b64 = base64url_encode(x);
            let y_b64 = base64url_encode(y);

            let jwk_json = format!(r#"{{"kty":"EC","crv":"{crv}","x":"{x_b64}","y":"{y_b64}"}}"#,);

            Ok(GetPublicKeyResponse {
                public_key_pem: pem_str,
                public_key_der: der,
                jwk_json,
            })
        })
        .await
        .map_err(|e| Status::internal(format!("spawn_blocking: {e}")))?
        .map_err(internal)?;

        Ok(Response::new(resp))
    }

    async fn health_check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        Ok(Response::new(HealthCheckResponse {
            status: ServingStatus::Serving.into(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            hsm_info: "HSM Simulator".to_string(),
        }))
    }

    async fn encrypt(
        &self,
        request: Request<EncryptRequest>,
    ) -> Result<Response<EncryptResponse>, Status> {
        let req = request.into_inner();

        let algorithm = SymmetricEncryptionAlgorithm::try_from(req.algorithm)
            .map_err(|_| Status::invalid_argument("Invalid algorithm"))?;
        if algorithm != SymmetricEncryptionAlgorithm::Aes256Gcm {
            return Err(Status::unimplemented("Only AES_256_GCM is supported"));
        }

        let kid = req.key_id.clone();
        let resp = tokio::task::spawn_blocking(move || -> Result<EncryptResponse> {
            let key = derive_aes_key(&req.key_id)?;

            let mut iv = vec![0u8; 12];
            openssl::rand::rand_bytes(&mut iv).context("RNG")?;

            let mut tag = vec![0u8; 16];
            let ciphertext = openssl::symm::encrypt_aead(
                openssl::symm::Cipher::aes_256_gcm(),
                &key,
                Some(&iv),
                req.associated_data.as_slice(),
                &req.plaintext,
                &mut tag,
            )
            .context("AES-GCM encrypt")?;

            Ok(EncryptResponse {
                ciphertext,
                iv,
                tag,
            })
        })
        .await
        .map_err(|e| Status::internal(format!("spawn_blocking: {e}")))?
        .map_err(internal)?;

        eprintln!(
            "[hsm_sim] Encrypt: key_id='{}', ciphertext_len={}",
            kid,
            resp.ciphertext.len(),
        );

        Ok(Response::new(resp))
    }

    async fn decrypt(
        &self,
        request: Request<DecryptRequest>,
    ) -> Result<Response<DecryptResponse>, Status> {
        let req = request.into_inner();

        let algorithm = SymmetricEncryptionAlgorithm::try_from(req.algorithm)
            .map_err(|_| Status::invalid_argument("Invalid algorithm"))?;
        if algorithm != SymmetricEncryptionAlgorithm::Aes256Gcm {
            return Err(Status::unimplemented("Only AES_256_GCM is supported"));
        }

        let kid = req.key_id.clone();
        let resp = tokio::task::spawn_blocking(move || -> Result<DecryptResponse> {
            let key = derive_aes_key(&req.key_id)?;

            let plaintext = openssl::symm::decrypt_aead(
                openssl::symm::Cipher::aes_256_gcm(),
                &key,
                Some(&req.iv),
                req.associated_data.as_slice(),
                &req.ciphertext,
                &req.tag,
            )
            .context("AES-GCM decrypt")?;

            Ok(DecryptResponse { plaintext })
        })
        .await
        .map_err(|e| Status::internal(format!("spawn_blocking: {e}")))?
        .map_err(internal)?;

        eprintln!(
            "[hsm_sim] Decrypt: key_id='{}', plaintext_len={}",
            kid,
            resp.plaintext.len(),
        );

        Ok(Response::new(resp))
    }

    async fn get_certificate(
        &self,
        request: Request<GetCertificateRequest>,
    ) -> Result<Response<GetCertificateResponse>, Status> {
        let ca = self
            .ca
            .as_ref()
            .ok_or_else(|| Status::unavailable("No CA configured"))?;

        let req = request.into_inner();
        let (ec_key, _curve) = self.cache.ec_key(&req.key_id).await?;

        eprintln!("[hsm_sim] GetCertificate request: key_id='{}'", req.key_id);

        let cert = self.cache.cert(&req.key_id, &ec_key, ca).await?;

        let ca_cert = ca.cert.clone();
        let resp = tokio::task::spawn_blocking(move || -> Result<GetCertificateResponse> {
            let leaf_pem =
                String::from_utf8(cert.to_pem().context("cert to_pem")?).context("PEM UTF-8")?;
            let ca_pem =
                String::from_utf8(ca_cert.to_pem().context("CA to_pem")?).context("PEM UTF-8")?;

            Ok(GetCertificateResponse {
                certificate_pem: leaf_pem.clone(),
                certificate_chain_pem: vec![leaf_pem, ca_pem],
            })
        })
        .await
        .map_err(|e| Status::internal(format!("spawn_blocking: {e}")))?
        .map_err(internal)?;

        Ok(Response::new(resp))
    }
}

fn base64url_encode(data: &[u8]) -> String {
    use openssl::base64::encode_block;
    encode_block(data)
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}
