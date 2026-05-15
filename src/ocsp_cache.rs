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
use crate::asl_keys::OcspConfig;
use crate::{CLIENT, log_debug};
use anyhow::{Context, anyhow, bail};
use foreign_types::ForeignTypeRef;
use http::header::CONTENT_TYPE;
use openssl::asn1::{Asn1GeneralizedTimeRef, Asn1Time, Asn1TimeRef};
use openssl::ocsp::{OcspCertId, OcspCertStatus, OcspResponse};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

#[derive(Clone, Default)]
struct CachedOcspResponse {
    data: Option<Vec<u8>>,
    expires: Duration,
}

pub static OCSP_CACHE: OnceLock<OcspCache> = OnceLock::new();

pub struct OcspCache {
    ocsp_url: Option<String>,
    ocsp_request: Vec<u8>,
    ocsp_cert_id: Option<OcspCertId>,
    ocsp_ttl: Duration,
    ocsp_response: RwLock<CachedOcspResponse>,
}

impl OcspCache {
    pub fn init(conf: OcspConfig) {
        OCSP_CACHE.get_or_init(|| OcspCache {
            ocsp_url: conf.url,
            ocsp_request: conf.request,
            ocsp_cert_id: conf.cert_id,
            ocsp_ttl: conf.ttl,
            ocsp_response: RwLock::new(CachedOcspResponse::default()),
        });
    }

    pub async fn get_ocsp(&self) -> Option<Vec<u8>> {
        // OCSP stapling disabled
        #[allow(clippy::question_mark)]
        if self.ocsp_url.is_none() || self.ocsp_cert_id.is_none() {
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
        if let Ok(date) = Asn1Time::from_unix(cached.expires.as_secs() as i64) {
            log_debug!("OCSP cache updated, expires {}", date.to_string());
        }

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
        let expires = verify_ocsp(
            &response,
            self.ocsp_cert_id.as_ref().unwrap(),
            now + self.ocsp_ttl,
        )?;
        Ok(CachedOcspResponse {
            data: Some(response.to_vec()),
            expires,
        })
    }
}

fn verify_ocsp(
    response: &[u8],
    cert_id: &OcspCertId,
    max_expires: Duration,
) -> anyhow::Result<Duration> {
    let ocsp = OcspResponse::from_der(response).context("parse ocsp response")?;
    let inner = ocsp
        .basic()
        .context(format!("bad response {:?}", ocsp.status()))?;

    let single = inner
        .find_status(cert_id)
        .ok_or_else(|| anyhow!("invalid response content"))?;
    if single.status != OcspCertStatus::GOOD {
        bail!("invalid certificate status {:?}", single.status);
    }

    let mut expires = match single.next_update() {
        Some(weird) => asn1_gtime_to_duration(weird),
        None => Ok(max_expires),
    }?;
    if expires > max_expires {
        expires = max_expires
    }

    Ok(expires)
}

pub fn asn1_gtime_to_duration(time: &Asn1GeneralizedTimeRef) -> anyhow::Result<Duration> {
    let epoch = Asn1Time::from_unix(0)?;

    // SAFETY: Asn1GeneralizedTime and Asn1Time use the same struct under the hood.
    // Also, we just borrow the pointer, it still gets freed once Asn1GeneralizedTime drops.
    let time_ref: &Asn1TimeRef = unsafe { Asn1TimeRef::from_ptr(time.as_ptr() as *mut _) };

    let diff = epoch.diff(time_ref)?;
    let total_secs = diff.days as i64 * 86_400 + diff.secs as i64;
    if total_secs < 0 {
        bail!("cannot convert time before the Unix epoch");
    }
    Ok(Duration::from_secs(total_secs as u64))
}

pub fn ocsp_cache() -> &'static OcspCache {
    OCSP_CACHE.get().expect("OcspCache not initialized")
}
