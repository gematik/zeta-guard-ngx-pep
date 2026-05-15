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

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use asl::roots::build_cert_data;
use asl::{Config, Environment, ToError, generate_asl_keys};
use openssl::asn1::Asn1Time;
use openssl::ec::EcKey;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::ocsp::{OcspCertId, OcspRequest};
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::Signer;
use openssl::x509::{X509, X509NameRef};

use crate::ossl_store;

#[derive(Default)]
pub struct OcspConfig {
    pub url: Option<String>,
    pub ttl: Duration,
    pub cert_id: Option<OcspCertId>,
    pub request: Vec<u8>,
}

#[derive(Default)]
pub struct AslConfig {
    pub asl: Config,
    pub ocsp: OcspConfig,
}

use crate::conf::OcspMode;

fn load_file(name: &str) -> Result<Vec<u8>> {
    fs::read(name).context(format!("failed to load asl keys {:?}", &name))
}

fn parse_certificate(name: &str) -> Result<X509> {
    X509::from_pem(&load_file(name)?).to_error()
}

fn get_public_key(cert: &X509) -> Result<EcKey<Public>> {
    let pkey = cert.public_key()?;
    let ec = pkey.ec_key()?;
    Ok(ec)
}

fn load_private_key(name: &str, pubkey: &EcKey<Public>) -> Result<PKey<Private>> {
    if let Some(stripped) = name.strip_prefix("store:") {
        return ossl_store::load_pkey(stripped);
    }

    let ec_key =
        EcKey::private_key_from_pem(&load_file(name)?).context("could not parse ASL signer key")?;

    let mut ctx = openssl::bn::BigNumContext::new()?;
    let points_equal = ec_key
        .public_key()
        .eq(ec_key.group(), pubkey.public_key(), &mut ctx)
        .context("could not compare ASL signer key and certificate")?;
    if !points_equal {
        bail!("ASL signer key does not match certificate");
    }

    Ok(PKey::from_ec_key(ec_key)?)
}

#[inline(always)]
fn get_cn(name: &X509NameRef) -> Option<String> {
    name.entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|cn| Some(cn.data().as_utf8().ok()?.to_string()))
}

fn get_cert_info(der: &[u8]) -> Option<(String, String)> {
    let cert = X509::from_der(der).ok()?;
    Some((get_cn(cert.subject_name())?, get_cn(cert.issuer_name())?))
}

fn parse_ocsp_url(cert: &X509) -> Option<String> {
    Some(
        cert.authority_info()?
            .iter()
            .find(|ext| ext.method().nid() == Nid::AD_OCSP)?
            .location()
            .uri()?
            .to_string(),
    )
}

fn expires_soon(cert: &X509) -> bool {
    Asn1Time::days_from_now(7)
        .map(|soon| cert.not_after().lt(&soon))
        .unwrap_or(false)
}

fn ecdsa_sign(signer_pk: &PKey<Private>, data: &[u8]) -> Result<Vec<u8>> {
    Signer::new(MessageDigest::sha256(), signer_pk)?
        .sign_oneshot_to_vec(data)
        .context("ECDSA signature")
}

fn build_ocsp_request(subject: &X509, issuer: &X509) -> Result<(OcspCertId, Vec<u8>)> {
    // Weirdness since OcspCertId is not cloneable
    let cert_id1 = OcspCertId::from_cert(MessageDigest::sha1(), subject, issuer)?;
    let cert_id2 = OcspCertId::from_cert(MessageDigest::sha1(), subject, issuer)?;
    let mut ocsp_request = OcspRequest::new()?;
    ocsp_request.add_id(cert_id1)?;
    Ok((cert_id2, ocsp_request.to_der()?))
}

pub fn asl_file_path(conf_dir: &Path, maybe_file: &Option<String>) -> Option<String> {
    maybe_file.as_ref().map(|file| {
        if file.starts_with("store:") {
            file.to_string()
        } else {
            conf_dir.join(file).to_string_lossy().to_string()
        }
    })
}

#[allow(clippy::too_many_arguments)]
pub fn create_asl_config(
    is_testing: bool,
    signer_cert_file: Option<String>,
    signer_key_file: Option<String>,
    ca_cert_file: Option<String>,
    roots_file: Option<String>,
    rca: Option<String>,
    ocsp_mode: OcspMode,
    ocsp_ttl: Duration,
) -> Result<AslConfig> {
    if signer_cert_file.is_none()
        && signer_key_file.is_none()
        && ca_cert_file.is_none()
        && roots_file.is_none()
    {
        return Ok(AslConfig::default());
    }
    if !(signer_cert_file.is_some()
        && signer_key_file.is_some()
        && ca_cert_file.is_some()
        && roots_file.is_some())
    {
        bail!("must have either all or none of ASL signer_cert, signer_key, ca_cert, roots_json");
    }

    let signer = parse_certificate(&signer_cert_file.unwrap())?;
    let signer_der = signer.to_der()?;
    let ca = parse_certificate(&ca_cert_file.unwrap())?;
    let ca_der = ca.to_der()?;

    if expires_soon(&signer) {
        println!(
            "WARNING, ASL signer certificate expires soon: {}",
            signer.not_after()
        );
    }

    let roots_bytes = load_file(&roots_file.unwrap())?;
    let cert_data = build_cert_data(&signer_der, &ca_der, &roots_bytes, rca, &get_cert_info)
        .context("failed to build ASL cert data")?;

    let signer_pk = get_public_key(&signer)?;
    let signer_sk = load_private_key(&signer_key_file.unwrap(), &signer_pk)?;
    let (server_keys, private_keys) =
        generate_asl_keys(30, "").context("failed to generate ASL keys")?;
    let signed_keys = server_keys
        .sign_with(&signer_der, 1, |data| ecdsa_sign(&signer_sk, data))
        .context("failed to sign ASL keys")?;

    let asl_env = if is_testing {
        Environment::Testing
    } else {
        Environment::Production
    };

    let asl_config = Config::new_with_keys(asl_env, signed_keys, private_keys, cert_data)
        .context("failed to build ASL configuration")?;

    let ocsp_url = match ocsp_mode {
        OcspMode::Disable => None,
        OcspMode::Cert => parse_ocsp_url(&signer),
        OcspMode::Override(uri) => Some(uri.to_string()),
    };
    let (cert_id, ocsp_request) =
        build_ocsp_request(&signer, &ca).context("failed to generate OCSP request")?;
    let ocsp_config = OcspConfig {
        url: ocsp_url,
        ttl: ocsp_ttl,
        cert_id: Some(cert_id),
        request: ocsp_request,
    };

    Ok(AslConfig {
        asl: asl_config,
        ocsp: ocsp_config,
    })
}
