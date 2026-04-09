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

//! Minimal OCSP responder for integration tests.
//!
//! Receives OCSP requests (HTTP POST with application/ocsp-request),
//! and returns a "good" OCSP response signed by the issuer CA.

use anyhow::{Context, Result};
use const_oid::db::rfc5912::ECDSA_WITH_SHA_256;
use der::asn1::BitString;
use der::{DateTime, Decode, Encode};
use http::StatusCode;
use http::header::CONTENT_TYPE;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_ocsp::{
    AsResponseBytes, BasicOcspResponse, CertStatus, OcspGeneralizedTime, OcspRequest, OcspResponse,
    OcspResponseStatus, ResponderId, ResponseData, SingleResponse, Version,
};

struct OcspState {
    issuer_name: x509_cert::name::Name,
    signing_key: openssl::pkey::PKey<openssl::pkey::Private>,
}

impl OcspState {
    fn load(conf_dir: &Path) -> Result<Self> {
        let issuer_pem =
            std::fs::read(conf_dir.join("issuer_cert.pem")).context("read issuer_cert.pem")?;
        let issuer_cert =
            openssl::x509::X509::from_pem(&issuer_pem).context("parse issuer_cert.pem")?;
        let issuer_der = issuer_cert.to_der().context("issuer to DER")?;
        let parsed =
            x509_cert::Certificate::from_der(&issuer_der).context("parse issuer DER cert")?;
        let issuer_name = parsed.tbs_certificate.subject;

        let key_pem =
            std::fs::read(conf_dir.join("issuer_key.pem")).context("read issuer_key.pem")?;
        let signing_key =
            openssl::pkey::PKey::private_key_from_pem(&key_pem).context("parse issuer_key.pem")?;

        Ok(Self {
            issuer_name,
            signing_key,
        })
    }

    fn build_response(&self, request_der: &[u8]) -> Result<Vec<u8>> {
        let ocsp_req = OcspRequest::from_der(request_der).context("decode OCSP request")?;

        let single_req = ocsp_req
            .tbs_request
            .request_list
            .first()
            .context("empty request list")?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time");
        let this_update =
            OcspGeneralizedTime::from(DateTime::from_unix_duration(now).expect("datetime"));
        let next_update_duration = now + std::time::Duration::from_secs(3600);
        let next_update = OcspGeneralizedTime::from(
            DateTime::from_unix_duration(next_update_duration).expect("datetime"),
        );

        let response_data = ResponseData {
            version: Version::V1,
            responder_id: ResponderId::ByName(self.issuer_name.clone()),
            produced_at: this_update,
            responses: vec![SingleResponse {
                cert_id: single_req.req_cert.clone(),
                cert_status: CertStatus::good(),
                this_update,
                next_update: Some(next_update),
                single_extensions: None,
            }],
            response_extensions: None,
        };

        // Encode TBS response data, then sign with issuer key
        let tbs_der = response_data.to_der().context("encode ResponseData")?;

        let mut signer =
            openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &self.signing_key)
                .context("Signer::new")?;
        let signature = signer.sign_oneshot_to_vec(&tbs_der).context("sign")?;

        let basic_response = BasicOcspResponse {
            tbs_response_data: response_data,
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA_256,
                parameters: None,
            },
            signature: BitString::from_bytes(&signature).context("BitString")?,
            certs: None,
        };

        // AsResponseBytes handles wrapping in ResponseBytes with the correct OID
        let response_bytes = basic_response
            .to_response_bytes()
            .context("to_response_bytes")?;

        let ocsp_response = OcspResponse {
            response_status: OcspResponseStatus::Successful,
            response_bytes: Some(response_bytes),
        };

        ocsp_response.to_der().context("encode OcspResponse")
    }
}

async fn handle_request(
    req: Request<Incoming>,
    state: Arc<OcspState>,
) -> Result<Response<http_body_util::Full<hyper::body::Bytes>>, hyper::Error> {
    use http_body_util::BodyExt;

    let body = req.collect().await?.to_bytes();

    match state.build_response(&body) {
        Ok(response_der) => {
            eprintln!(
                "[ocsp-responder] responded with {} bytes",
                response_der.len()
            );
            let resp = Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/ocsp-response")
                .body(http_body_util::Full::new(response_der.into()))
                .unwrap();
            Ok(resp)
        }
        Err(e) => {
            eprintln!("[ocsp-responder] error: {e:#}");
            let resp = Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(http_body_util::Full::new(
                    format!("{e:#}").into_bytes().into(),
                ))
                .unwrap();
            Ok(resp)
        }
    }
}

/// Start a minimal OCSP responder on the given port.
/// Returns when the listener shuts down (i.e., when the spawned task is aborted).
pub async fn ocsp_responder(port: u16, conf_dir: &Path) -> Result<()> {
    let state = Arc::new(OcspState::load(conf_dir)?);
    let listener = TcpListener::bind(("127.1.33.7", port)).await?;
    eprintln!("[ocsp-responder] listening on 127.1.33.7:{port}");

    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        let state = state.clone();
                        handle_request(req, state)
                    }),
                )
                .await
            {
                eprintln!("[ocsp-responder] connection error: {e}");
            }
        });
    }
}
