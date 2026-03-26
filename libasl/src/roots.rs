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

use crate::CertData;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;

// According to A_26922, rca_chain must start at RCA7
const ROOT_NAME_RCA7: &str = "GEM.RCA7";
const ROOT_NAME_RCA7_TEST: &str = "GEM.RCA7 TEST-ONLY";

#[derive(Debug, Error)]
pub enum RootsError {
    Decoding,
    Format,
    Consistency { issue: String },
}

impl Display for RootsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RootsError::Decoding => write!(f, "Failed to decode certificate"),
            RootsError::Format => write!(f, "Roots file is not in JSON format"),
            RootsError::Consistency { issue } => {
                write!(f, "Inconsistent roots file: {}", issue)
            }
        }
    }
}

mod base64_vec {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer};
    use serde_bytes::ByteBuf;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ByteBuf, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = STANDARD
            .decode(&s)
            .map_err(|e| D::Error::custom(format!("invalid base64: {e}")))?;
        Ok(ByteBuf::from(bytes))
    }
}

#[allow(dead_code)]
#[derive(Deserialize, PartialEq)]
struct Root {
    #[serde(with = "base64_vec")]
    cert: ByteBuf,
    cn: String,
    name: String,
    #[serde(with = "base64_vec")]
    next: ByteBuf,
    nva: String,
    nvb: String,
    #[serde(with = "base64_vec")]
    prev: ByteBuf,
    ski: String,
}

#[inline(always)]
fn find_by_cn<'a>(roots: &'a [Root], cn: &str) -> Option<&'a Root> {
    roots.iter().find(|root| root.cn == cn)
}

pub type CertResolver = dyn Fn(&[u8]) -> Option<(String, String)>; // der -> subject_cn, issuer_cn

pub fn get_roots_chain(
    roots_blob: &[u8],
    root_name: Option<String>,
    issuer_cn: &str,
    cert_info: &CertResolver,
) -> Result<Vec<ByteBuf>, RootsError> {
    let roots: Vec<Root> = serde_json::from_slice(&roots_blob).map_err(|_| RootsError::Format)?;

    let initial = root_name
        .and_then(|name| find_by_cn(&roots, &name))
        .or_else(|| {
            find_by_cn(&roots, ROOT_NAME_RCA7).or_else(|| find_by_cn(&roots, ROOT_NAME_RCA7_TEST))
        })
        .ok_or(RootsError::Consistency {
            issue: "initial root CA not found".to_string(),
        })?;

    let issuer = find_by_cn(&roots, issuer_cn).ok_or(RootsError::Consistency {
        issue: "issuer's root CA not found".to_string(),
    })?;

    let mut rca_chain: Vec<ByteBuf> = Vec::new();
    let mut current = initial;
    while current != issuer {
        if current.next.is_empty() {
            return Err(RootsError::Consistency {
                issue: format!("no more certificates after root CA: {}", current.cn),
            });
        }
        let (subject_cn, issuer_cn) = cert_info(&current.next).ok_or(RootsError::Decoding)?;
        if issuer_cn != current.cn {
            return Err(RootsError::Consistency {
                issue: format!("invalid next certificate for root CA: {}", current.cn),
            });
        }
        rca_chain.push(current.next.clone());

        current =
            roots
                .iter()
                .find(|root| root.cn == subject_cn)
                .ok_or(RootsError::Consistency {
                    issue: format!("no root CA: {}", subject_cn),
                })?;
    }

    Ok(rca_chain)
}

pub fn build_cert_data(
    signer_cert: &[u8],
    ca_cert: &[u8],
    roots_blob: &[u8],
    rca: Option<String>,
    cert_info: &CertResolver,
) -> Result<CertData, RootsError> {
    let (_, signer_issuer_cn) = cert_info(&signer_cert).ok_or(RootsError::Decoding)?;
    let (ca_subject_cn, ca_issuer_cn) = cert_info(&ca_cert).ok_or(RootsError::Decoding)?;

    if signer_issuer_cn != ca_subject_cn {
        return Err(RootsError::Consistency {
            issue: "CA is not the issuer of the signer certificate".to_string(),
        });
    }

    let rca_chain = get_roots_chain(roots_blob, rca, &ca_issuer_cn, cert_info)?;

    Ok(CertData {
        cert: signer_cert.to_vec(),
        ca: ca_cert.to_vec(),
        rca_chain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use x509_parser::{parse_x509_certificate};
    use x509_parser::pem::Pem;
    use x509_parser::prelude::X509Name;

    #[inline(always)]
    pub fn get_cn<'a>(name: &'a X509Name) -> Option<&'a str> {
        name.iter_common_name()
            .next()
            .and_then(|attr| attr.as_str().ok())
    }

    pub fn get_cert_info(cert: &[u8]) -> Option<(String, String)> {
        let (_, parsed) = parse_x509_certificate(cert).ok()?;
        let subject = get_cn(parsed.subject())?;
        let issuer = get_cn(parsed.issuer())?;
        Some((subject.to_string(), issuer.to_string()))
    }

    fn load_file(name: &str) -> Vec<u8> {
        fs::read(name).unwrap()
    }

    fn load_pem_cert(name: &str) -> Vec<u8> {
        let blob = load_file(name);
        let pem = Pem::iter_from_buffer(&blob)
            .next()
            .expect("PEM block missing")
            .expect("Failed to parse PEM");
        assert_eq!(pem.label, "CERTIFICATE", "Expected a CERTIFICATE PEM block");
        pem.contents
    }

    fn rca1_name() -> Option<String> {
        Some("FAKE.RCA1".to_string())
    }

    const ISSUER: &str = "FAKE.RCA3";

    #[test]
    fn handles_chain_with_single_element() {
        let maybe_certs = get_roots_chain(
            &load_file("fixtures/roots.json"),
            rca1_name(),
            "FAKE.RCA1",
            &get_cert_info,
        );
        assert!(maybe_certs.is_ok());
        let certs = maybe_certs.unwrap();

        assert_eq!(certs.len(), 0); // root itself is not part of chain
    }

    #[test]
    fn rejects_chain_if_not_json() {
        let no_json = "This is no JSON content".as_bytes();
        let maybe_certs = get_roots_chain(no_json, rca1_name(), ISSUER, &get_cert_info);
        assert!(matches!(maybe_certs, Err(RootsError::Format)));
    }

    #[test]
    fn rejects_chain_if_wrong_content() {
        let maybe_certs = get_roots_chain(
            &load_file("fixtures/no_roots.json"),
            rca1_name(),
            ISSUER,
            &get_cert_info,
        );
        assert!(matches!(maybe_certs, Err(RootsError::Format)));
    }

    #[test]
    fn rejects_chain_if_no_root() {
        let maybe_certs = get_roots_chain(
            &load_file("fixtures/roots.json"),
            Some("no such root".to_string()),
            ISSUER,
            &get_cert_info,
        );
        assert!(matches!(maybe_certs, Err(RootsError::Consistency { .. })));
        if let RootsError::Consistency { issue } = maybe_certs.unwrap_err() {
            assert!(issue.contains("initial root CA not found"));
        }
    }

    #[test]
    fn rejects_chain_if_no_issuer() {
        let maybe_certs = get_roots_chain(
            &load_file("fixtures/roots.json"),
            rca1_name(),
            "no such issuer",
            &get_cert_info,
        );
        assert!(matches!(maybe_certs, Err(RootsError::Consistency { .. })));
        if let RootsError::Consistency { issue } = maybe_certs.unwrap_err() {
            assert!(issue.contains("issuer's root CA not found"));
        }
    }

    #[test]
    fn rejects_chain_if_not_chained() {
        let maybe_certs = get_roots_chain(
            &load_file("fixtures/no_chain.json"),
            rca1_name(),
            ISSUER,
            &get_cert_info,
        );
        assert!(matches!(maybe_certs, Err(RootsError::Consistency { .. })));
        if let RootsError::Consistency { issue } = maybe_certs.unwrap_err() {
            assert!(issue.contains("no root CA:"));
        }
    }

    #[test]
    fn rejects_chain_with_issuer_before_start() {
        let maybe_certs = get_roots_chain(
            &load_file("fixtures/roots.json"),
            Some("FAKE.RCA2".to_string()),
            "FAKE.RCA1",
            &get_cert_info,
        );
        assert!(matches!(maybe_certs, Err(RootsError::Consistency { .. })));
        if let RootsError::Consistency { issue } = maybe_certs.unwrap_err() {
            assert!(issue.contains("no more certificates after root CA:"));
        }
    }

    #[test]
    fn builds_cert_data() {
        let maybe_cert_data = build_cert_data(
            &load_pem_cert("fixtures/signer_cert.pem"),
            &load_pem_cert("fixtures/issuer_cert.pem"),
            &load_file("fixtures/roots.json"),
            rca1_name(),
            &get_cert_info,
        );
        assert!(maybe_cert_data.is_ok());
        let cert_data = maybe_cert_data.unwrap();

        assert_eq!(cert_data.rca_chain.len(), 2);
    }

    #[test]
    fn rejects_bad_signer_cert() {
        let maybe_cert_data = build_cert_data(
            "not a DER encoded cert".as_bytes(),
            &load_pem_cert("fixtures/issuer_cert.pem"),
            &load_file("fixtures/roots.json"),
            rca1_name(),
            &get_cert_info,
        );
        assert!(matches!(maybe_cert_data, Err(RootsError::Decoding)));
    }

    #[test]
    fn rejects_bad_issuer_cert() {
        let maybe_cert_data = build_cert_data(
            &load_pem_cert("fixtures/signer_cert.pem"),
            "not a DER encoded cert".as_bytes(),
            &load_file("fixtures/roots.json"),
            rca1_name(),
            &get_cert_info,
        );
        assert!(matches!(maybe_cert_data, Err(RootsError::Decoding)));
    }

    #[test]
    fn rejects_inconsistent_certs() {
        let maybe_cert_data = build_cert_data(
            &load_pem_cert("fixtures/signer_self_cert.pem"),
            &load_pem_cert("fixtures/issuer_cert.pem"),
            &load_file("fixtures/roots.json"),
            rca1_name(),
            &get_cert_info,
        );
        assert!(matches!(maybe_cert_data, Err(RootsError::Consistency {..})));
        if let RootsError::Consistency { issue } = maybe_cert_data.unwrap_err() {
            assert!(issue.contains("CA is not the issuer of the signer certificate"));
        }
    }
}
