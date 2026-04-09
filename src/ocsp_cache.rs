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
use crate::{CLIENT, log_debug};
use anyhow::{Context, bail};
use asl::Config;
use der::{DateTime, Decode};
use http::header::CONTENT_TYPE;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use x509_ocsp::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus};

#[derive(Clone, Default)]
struct CachedOcspResponse {
    data: Option<Vec<u8>>,
    expires: Duration,
}

pub static OCSP_CACHE: OnceLock<OcspCache> = OnceLock::new();

pub struct OcspCache {
    ocsp_url: Option<String>,
    ocsp_request: Vec<u8>,
    ocsp_ttl: Duration,
    ocsp_response: RwLock<CachedOcspResponse>,
}

impl OcspCache {
    pub fn init(conf: &Config) {
        OCSP_CACHE.get_or_init(|| OcspCache {
            ocsp_url: conf.ocsp_url.clone(),
            ocsp_request: conf.ocsp_request.clone(),
            ocsp_ttl: conf.ocsp_ttl,
            ocsp_response: RwLock::new(CachedOcspResponse::default()),
        });
    }

    pub async fn get_ocsp(&self) -> Option<Vec<u8>> {
        // OCSP stapling disabled
        #[allow(clippy::question_mark)]
        if self.ocsp_url.is_none() {
            return None;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current timestamp");

        // Still valid in cache? (read locked)
        {
            let cached = self.ocsp_response.read().await;
            if cached.expires > now {
                return cached.data.clone();
            }
        }

        // fetch a new response
        let response = self.refresh_ocsp(now).await.unwrap_or_else(|err| {
            log_debug!("OCSP refresh failed: {err}");
            CachedOcspResponse {
                data: None,
                expires: now + Duration::from_mins(1), // backoff in case of failure
            }
        });

        // Update cache (write locked)
        let mut cached = self.ocsp_response.write().await;
        *cached = response;
        log_debug!(
            "OCSP cache updated, expires {}",
            DateTime::from_unix_duration(cached.expires).expect("date conversion")
        );

        cached.data.clone()
    }

    async fn refresh_ocsp(&self, now: Duration) -> anyhow::Result<CachedOcspResponse> {
        let client = CLIENT.get().expect("client");
        let response = client
            .post(self.ocsp_url.as_ref().unwrap())
            .header(CONTENT_TYPE, "application/ocsp-request")
            .body(self.ocsp_request.clone())
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        let expires = verify_ocsp(&response, now + self.ocsp_ttl)?;
        Ok(CachedOcspResponse {
            data: Some(response.to_vec()),
            expires,
        })
    }
}

fn verify_ocsp(response: &[u8], max_expires: Duration) -> anyhow::Result<Duration> {
    let ocsp = OcspResponse::from_der(response).context("parse ocsp response")?;
    if ocsp.response_status != OcspResponseStatus::Successful || ocsp.response_bytes.is_none() {
        bail!("bad response {:?}", ocsp.response_status);
    }

    let inner = BasicOcspResponse::from_der(ocsp.response_bytes.unwrap().response.as_bytes())?;
    if inner.tbs_response_data.responses.len() != 1 {
        bail!(
            "invalid response length {}",
            inner.tbs_response_data.responses.len()
        );
    }

    let single = &inner.tbs_response_data.responses[0];
    if single.cert_status != CertStatus::good() {
        bail!("invalid certificate status {:?}", single.cert_status);
    }

    let mut expires = single
        .next_update
        .map_or(max_expires, |date| date.as_ref().to_unix_duration());
    if expires > max_expires {
        expires = max_expires
    }

    Ok(expires)
}

pub fn ocsp_cache() -> &'static OcspCache {
    OCSP_CACHE.get().expect("OcspCache not initialized")
}
