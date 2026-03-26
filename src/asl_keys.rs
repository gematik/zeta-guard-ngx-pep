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

use anyhow::{Context, Result, bail};
use asl::roots::build_cert_data;
use asl::{Config, Environment, ToError, generate_asl_keys};
use sec1::EcPrivateKey;
use sec1::der::Decode;
use sec1::pkcs8::PrivateKeyInfo;
use std::fs;
use std::path::{Path, PathBuf};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::oid_registry::Oid;
use x509_parser::oid_registry::asn1_rs::oid;
use x509_parser::parse_x509_certificate;
use x509_parser::prelude::{Pem, parse_x509_pem};
use x509_parser::x509::X509Name;

fn load_file(name: &Path) -> Result<Vec<u8>> {
    fs::read(name).context(format!("failed to load asl keys {:?}", &name))
}

fn load_pem_entry(name: &Path) -> Result<Vec<u8>> {
    Ok(parse_x509_pem(&load_file(name)?).to_error()?.1.contents)
}

fn parse_certificate(der: &[u8]) -> Result<X509Certificate<'_>> {
    Ok(parse_x509_certificate(der).to_error()?.1)
}

fn load_private_key(blob: &[u8], pubkey: &[u8]) -> Result<Vec<u8>> {
    let pem = Pem::iter_from_buffer(blob)
        .filter_map(|entry| entry.ok())
        .find(|entry| entry.label.contains("PRIVATE KEY"))
        .context("could not parse ASL private key")?;

    let ec_pk_bytes: Vec<u8> = match pem.label.as_str() {
        "EC PRIVATE KEY" => Ok(pem.contents),
        "PRIVATE KEY" => PrivateKeyInfo::from_der(&pem.contents)
            .map(|pkcs8| pkcs8.private_key.to_vec())
            .to_error(),
        _ => bail!("could not parse ASL private key"), // should not happen with filter above
    }?;

    let ec_key = EcPrivateKey::from_der(&ec_pk_bytes).context("could not parse EC private key")?;

    if let Some(pk) = ec_key.public_key
        && pk != pubkey
    {
        bail!("ASL signer key does not match certificate");
    }

    Ok(ec_key.private_key.to_vec())
}

#[inline(always)]
fn get_cn(name: &X509Name) -> Option<String> {
    name.iter_common_name()
        .next()
        .and_then(|entry| entry.as_str().ok())
        .map(|s| s.to_string())
}

fn get_cert_info(der: &[u8]) -> Option<(String, String)> {
    let cert = parse_certificate(der).ok()?;
    Some((
        get_cn(&cert.tbs_certificate.subject)?,
        get_cn(&cert.tbs_certificate.issuer)?,
    ))
}

const AUTHORITY_INFO_ACCESS_OID: Oid = oid! {1.3.6.1.5.5.7.1.1};
const ACCESS_METHOD_OCSP_OID: Oid = oid! {1.3.6.1.5.5.7.48.1};

fn parse_ocsp_url(cert: &X509Certificate) -> Option<String> {
    if let Ok(maybe_ext) = cert.get_extension_unique(&AUTHORITY_INFO_ACCESS_OID)
        && let Some(opt_ext) = maybe_ext
        && let ParsedExtension::AuthorityInfoAccess(ocsp_ext) = opt_ext.parsed_extension()
    {
        return ocsp_ext
            .accessdescs
            .iter()
            .find(|desc| desc.access_method == ACCESS_METHOD_OCSP_OID)
            .map(|desc| &desc.access_location)
            .and_then(|loc| match loc {
                GeneralName::URI(str) => Some(str.to_string()),
                _ => None,
            });
    }
    None
}

const SECONDS_PER_WEEK: f64 = 604800f64;
fn expires_soon(cert: &X509Certificate) -> bool {
    cert.tbs_certificate
        .validity
        .time_to_expiration()
        .map_or(false, |expires| expires.as_seconds_f64() < SECONDS_PER_WEEK)
}

pub fn asl_file_path(conf_dir: &Path, maybe_file: &Option<String>) -> Option<PathBuf> {
    maybe_file.as_ref().map(|file| conf_dir.join(file))
}

pub fn create_asl_config(
    is_testing: bool,
    signer_cert_file: Option<PathBuf>,
    signer_key_file: Option<PathBuf>,
    ca_cert_file: Option<PathBuf>,
    roots_file: Option<PathBuf>,
    rca: Option<String>,
    ocsp_url: Option<String>,
) -> Result<Config> {
    if signer_cert_file.is_none()
        && signer_key_file.is_none()
        && ca_cert_file.is_none()
        && roots_file.is_none()
    {
        return Ok(Config::default());
    }
    if !(signer_cert_file.is_some()
        && signer_key_file.is_some()
        && ca_cert_file.is_some()
        && roots_file.is_some())
    {
        anyhow::bail!(
            "must have either all or none of ASL signer_cert, signer_key, ca_cert, roots_json"
        );
    }

    let signer_der = load_pem_entry(&signer_cert_file.unwrap())?;
    let signer = parse_certificate(&signer_der)?;
    let ca_der = load_pem_entry(&ca_cert_file.unwrap())?;
    let _ca = parse_certificate(&ca_der)?;

    if expires_soon(&signer) {
        println!(
            "WARNING, ASL signer certificate expires soon: {}",
            signer.validity.not_after
        );
    }

    let roots_bytes = load_file(&roots_file.unwrap())?;
    let cert_data = build_cert_data(&signer_der, &ca_der, &roots_bytes, rca, &get_cert_info)
        .context("failed to build ASL cert data")?;

    let signer_pk = signer.subject_pki.subject_public_key.as_ref();
    let signer_sk = load_private_key(&load_file(&signer_key_file.unwrap())?, signer_pk)?;
    let (server_keys, private_keys) =
        generate_asl_keys(30, "").context("failed to generate ASL keys")?;
    let signed_keys = server_keys
        .sign(&signer_der, &signer_sk, 1)
        .context("failed to sign ASL keys")?;

    let asl_env = if is_testing {
        Environment::Testing
    } else {
        Environment::Production
    };

    let ocsp = ocsp_url.or(parse_ocsp_url(&signer));

    let config = Config::new_with_keys(asl_env, signed_keys, private_keys, cert_data, ocsp)
        .context("failed to build ASL configuration")?;

    Ok(config)
}
