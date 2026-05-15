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

use jsonwebtoken::jwk::Jwk;
#[cfg(test)]
use mockall::automock;
use reqwest::header::{CACHE_CONTROL, ETAG, LAST_MODIFIED};
use std::time::Duration;
use tokio::time::Instant;

#[cfg_attr(test, automock, allow(unused))]
pub trait JwkCacheOps {
    async fn fetch_pdp(&self) -> anyhow::Result<()>;
    async fn get_jwk_pdp(&self, kid: String, client_ip: Option<String>) -> anyhow::Result<Jwk>;
    async fn fetch_popp(&self) -> anyhow::Result<()>;
    async fn get_jwk_popp(&self, kid: String, client_ip: Option<String>) -> anyhow::Result<Jwk>;
}

// --- HTTP cache metadata ---

#[derive(Debug, Clone, Default)]
struct HttpCacheMeta {
    etag: Option<String>,
    last_modified: Option<String>,
    /// Derived from Cache-Control: max-age
    max_age: Option<Duration>,
    /// Monotonic instant for freshness checks
    fetched_at: Option<Instant>,
    /// Wall-clock epoch seconds for logging
    fetched_at_epoch: u64,
}

impl HttpCacheMeta {
    fn is_fresh(&self) -> bool {
        match (self.fetched_at, self.max_age) {
            (Some(at), Some(max_age)) => at.elapsed() < max_age,
            _ => false,
        }
    }

    /// True if the cache is still trustworthy enough to use even when the
    /// most recent refresh attempt failed: within `max_age + grace` of the
    /// last successful fetch. `max_age` defaults to 0 if the server didn't
    /// say (so the trust window is just `grace`).
    fn trustworthy(&self, grace: Duration) -> bool {
        match self.fetched_at {
            Some(at) => at.elapsed() < self.max_age.unwrap_or_default() + grace,
            None => false,
        }
    }

    fn from_response(resp: &reqwest::Response) -> Self {
        let h = resp.headers();
        Self {
            etag: h.get(ETAG).and_then(|v| v.to_str().ok()).map(Into::into),
            last_modified: h
                .get(LAST_MODIFIED)
                .and_then(|v| v.to_str().ok())
                .map(Into::into),
            max_age: Self::parse_max_age(h),
            fetched_at: Some(Instant::now()),
            fetched_at_epoch: jsonwebtoken::get_current_timestamp(),
        }
    }

    /// Merge metadata from a (possibly 304) response, keeping existing values
    /// for headers the server didn't repeat.
    fn merge_response(&mut self, resp: &reqwest::Response) {
        let h = resp.headers();
        if let Some(etag) = h.get(ETAG).and_then(|v| v.to_str().ok()) {
            self.etag = Some(etag.into());
        }
        if let Some(lm) = h.get(LAST_MODIFIED).and_then(|v| v.to_str().ok()) {
            self.last_modified = Some(lm.into());
        }
        if let Some(ma) = Self::parse_max_age(h) {
            self.max_age = Some(ma);
        }
        self.fetched_at = Some(Instant::now());
        self.fetched_at_epoch = jsonwebtoken::get_current_timestamp();
    }

    fn parse_max_age(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
        let cc = headers.get(CACHE_CONTROL)?.to_str().ok()?;
        for directive in cc.split(',') {
            let d = directive.trim();
            if let Some(val) = d.strip_prefix("max-age=") {
                return val.trim().parse::<u64>().ok().map(Duration::from_secs);
            }
        }
        None
    }

    fn format_epoch_compact(epoch: u64) -> String {
        let t: libc::time_t = epoch as _;
        let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
        let tm = unsafe {
            libc::gmtime_r(&t, tm.as_mut_ptr());
            tm.assume_init()
        };
        format!(
            "{:02}{:02}{:02} {:02}:{:02}",
            (tm.tm_year + 1900) % 100,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
        )
    }
}

impl std::fmt::Display for HttpCacheMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ts = Self::format_epoch_compact(self.fetched_at_epoch);
        write!(f, "@{ts}")?;
        if let Some(ma) = self.max_age {
            write!(f, " max-age={}", ma.as_secs())?;
        }
        if let Some(etag) = &self.etag {
            let short = etag.get(..8).unwrap_or(etag);
            write!(f, " etag={short}\u{2026}")?;
        }
        if let Some(lm) = &self.last_modified {
            write!(f, " lm={lm}")?;
        }
        Ok(())
    }
}

#[cfg_attr(test, allow(unused))]
mod prod {
    use std::collections::HashMap;

    use anyhow::{Context, anyhow, bail};
    use base64ct::Base64;
    use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation, jwk::JwkSet};
    use reqwest::StatusCode;
    use reqwest::header::{IF_MODIFIED_SINCE, IF_NONE_MATCH};
    use tokio::{sync::RwLock, time::Instant};

    use crate::spawn_compat;

    use {
        super::{HttpCacheMeta, JwkCacheOps},
        crate::{CLIENT, conf::MainConfig, log_debug},
        jsonwebtoken::jwk::Jwk,
        ngx::async_::sleep,
        serde::Deserialize,
        std::sync::OnceLock,
        std::time::Duration,
    };

    use base64ct::Encoding;
    fn is_base64url_char(byte: u8) -> bool {
        matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')
    }

    /// Send a GET with conditional headers (If-None-Match / If-Modified-Since).
    /// Caller checks `resp.status() == 304` to distinguish cache hit from new data.
    /// When `xff` is set, an X-Forwarded-For header is added so the IdP can
    /// attribute the request to the client that triggered a force-refresh.
    async fn conditional_get(
        client: &reqwest::Client,
        url: &str,
        meta: &HttpCacheMeta,
        xff: Option<&str>,
    ) -> anyhow::Result<reqwest::Response> {
        let mut req = client.get(url);
        if let Some(etag) = &meta.etag {
            req = req.header(IF_NONE_MATCH, etag.as_str());
        }
        if let Some(lm) = &meta.last_modified {
            req = req.header(IF_MODIFIED_SINCE, lm.as_str());
        }
        if let Some(xff) = xff {
            req = req.header("X-Forwarded-For", xff);
        }
        let resp = req.send().await?;
        if resp.status() == StatusCode::NOT_MODIFIED {
            Ok(resp)
        } else {
            Ok(resp.error_for_status()?)
        }
    }

    // --- Data types ---

    #[derive(Deserialize)]
    pub struct OidcConfig {
        pub jwks_uri: String,
        pub issuer: String,
    }

    #[derive(Debug, Deserialize)]
    struct EntityStatement {
        metadata: Metadata,
        jwks: JwkSet,
    }

    #[derive(Debug, Deserialize)]
    struct Metadata {
        oauth_resource: OauthResource,
    }

    #[derive(Debug, Deserialize)]
    struct OauthResource {
        signed_jwks_uri: String,
    }

    #[derive(Debug, Deserialize)]
    struct SignedJwkSet {
        #[serde(flatten)]
        jwks: JwkSet,
    }

    /// Cached OIDC discovery result (PDP path).
    struct OidcCacheEntry {
        jwks_uri: String,
        meta: HttpCacheMeta,
    }

    /// Cached entity statement (PoPP path).
    struct EntityCacheEntry {
        jwks: JwkSet,
        signed_jwks_uri: String,
        meta: HttpCacheMeta,
    }

    pub static JWK_CACHE: OnceLock<JwkCache> = OnceLock::new();

    #[derive(Debug, Default)]
    struct JwkStore {
        keys: HashMap<String, Jwk>, // put into map for faster access
        meta: HttpCacheMeta,
    }

    trait JwksOps {
        async fn get_key(&self, kid: &str) -> Option<Jwk>;
    }

    impl JwksOps for RwLock<Option<JwkStore>> {
        async fn get_key(&self, kid: &str) -> Option<Jwk> {
            let jwks = self.read().await;
            jwks.as_ref().and_then(|jwks| jwks.keys.get(kid).cloned())
        }
    }

    pub struct JwkCache {
        pdp_issuer: String,
        pdp_oidc: RwLock<Option<OidcCacheEntry>>,
        pdp_jwks: RwLock<Option<JwkStore>>,
        popp_issuer: Option<String>,
        popp_entity: RwLock<Option<EntityCacheEntry>>,
        popp_jwks: RwLock<Option<JwkStore>>,
        refresh_interval: Duration,
    }

    impl JwkCache {
        pub fn init(conf: &MainConfig) {
            let cache = JWK_CACHE.get_or_init(|| JwkCache {
                pdp_issuer: conf.pdp_issuer.as_ref().expect("issuer").clone(),
                pdp_oidc: Default::default(),
                pdp_jwks: Default::default(),
                popp_issuer: conf.popp_issuer.clone(),
                popp_entity: Default::default(),
                popp_jwks: Default::default(),
                refresh_interval: conf.jwks_refresh_interval,
            });
            spawn_compat(cache.cache_worker()).detach();
        }

        async fn cache_worker(&'static self) {
            loop {
                let start = Instant::now();
                let _ = self.fetch_pdp().await;
                let _ = self.fetch_popp().await;
                let elapsed = Instant::now().duration_since(start);
                if elapsed < self.refresh_interval {
                    sleep(self.refresh_interval - elapsed).await;
                }
            }
        }

        /// Wrapper around [`Self::fetch_pdp_inner`] that drops the cached data on refresh failure
        /// after a grace period (see [`HttpCacheMeta::trustworthy`]).
        async fn refresh_pdp(&self, force: bool, xff: Option<&str>) -> anyhow::Result<()> {
            let result = self.fetch_pdp_inner(force, xff).await;
            if let Err(e) = &result {
                let grace = self.refresh_interval;
                // Take write locks first (in inner's lock order) and re-check
                // trustworthiness inside, so a concurrent successful refresh
                // can't be clobbered by our drop.
                let mut oidc_guard = self.pdp_oidc.write().await;
                let mut jwks_guard = self.pdp_jwks.write().await;
                let trustworthy = jwks_guard
                    .as_ref()
                    .is_some_and(|s| s.meta.trustworthy(grace));
                if trustworthy {
                    log_debug!("jwk_cache[pdp]: ERROR refresh failed (in grace, cache kept): {e}");
                } else {
                    *jwks_guard = None;
                    *oidc_guard = None;
                    log_debug!(
                        "jwk_cache[pdp]: ERROR refresh failed past grace, cache dropped: {e}"
                    );
                }
            }
            result
        }

        /// Wrapper around [`Self::fetch_popp_inner`] that drops the cached data on refresh failure
        /// after a grace period (see [`HttpCacheMeta::trustworthy`]).
        async fn refresh_popp(&self, force: bool, xff: Option<&str>) -> anyhow::Result<()> {
            let result = self.fetch_popp_inner(force, xff).await;
            if let Err(e) = &result {
                let grace = self.refresh_interval;
                let mut entity_guard = self.popp_entity.write().await;
                let mut jwks_guard = self.popp_jwks.write().await;
                let trustworthy = jwks_guard
                    .as_ref()
                    .is_some_and(|s| s.meta.trustworthy(grace));
                if trustworthy {
                    log_debug!("jwk_cache[popp]: ERROR refresh failed (in grace, cache kept): {e}");
                } else {
                    *jwks_guard = None;
                    *entity_guard = None;
                    log_debug!(
                        "jwk_cache[popp]: ERROR refresh failed past grace, cache dropped: {e}"
                    );
                }
            }
            result
        }

        /// Fetch PDP JWKS, respecting HTTP cache semantics.
        /// When `force` is false, cached responses that are still fresh are kept.
        /// When `force` is true (on-demand kid miss), freshness is bypassed but
        /// conditional GET is still used to save bandwidth.
        async fn fetch_pdp_inner(&self, force: bool, xff: Option<&str>) -> anyhow::Result<()> {
            let client = CLIENT.get().expect("client");
            let issuer = self.pdp_issuer.trim_end_matches('/');

            // --- Step 1: resolve JWKS URI via OIDC discovery ---
            let jwks_uri = {
                let cached = self.pdp_oidc.read().await;
                if !force && cached.as_ref().is_some_and(|c| c.meta.is_fresh()) {
                    cached.as_ref().unwrap().jwks_uri.clone()
                } else {
                    let old_meta = cached.as_ref().map(|c| c.meta.clone()).unwrap_or_default();
                    drop(cached);

                    let well_known = format!("{issuer}/.well-known/openid-configuration");

                    let resp = conditional_get(client, &well_known, &old_meta, xff).await?;

                    let mut pdp_oidc = self.pdp_oidc.write().await;
                    if resp.status() == StatusCode::NOT_MODIFIED {
                        let entry = pdp_oidc
                            .as_mut()
                            .ok_or_else(|| anyhow!("pdp: 304 but no cached OIDC config"))?;
                        entry.meta.merge_response(&resp);
                        log_debug!("jwk_cache[pdp]: OIDC discovery 304 not modified");
                        entry.jwks_uri.clone()
                    } else {
                        let meta = HttpCacheMeta::from_response(&resp);
                        let cfg: OidcConfig = resp.json().await?;
                        if cfg.issuer != self.pdp_issuer {
                            bail!("pdp: issuer mismatch");
                        }
                        let uri = cfg.jwks_uri.clone();
                        *pdp_oidc = Some(OidcCacheEntry {
                            jwks_uri: uri.clone(),
                            meta,
                        });
                        uri
                    }
                }
            };

            // --- Step 2: fetch JWKS ---
            let old_meta = {
                let cached = self.pdp_jwks.read().await;
                if !force && cached.as_ref().is_some_and(|s| s.meta.is_fresh()) {
                    log_debug!("jwk_cache[pdp]: JWKS still fresh, skipping fetch");
                    return Ok(());
                }

                cached.as_ref().map(|s| s.meta.clone()).unwrap_or_default()
            };

            let resp = conditional_get(client, &jwks_uri, &old_meta, xff).await?;

            let mut pdp_jwks = self.pdp_jwks.write().await;
            if resp.status() == StatusCode::NOT_MODIFIED {
                if let Some(store) = pdp_jwks.as_mut() {
                    store.meta.merge_response(&resp);
                    let kids: Vec<_> = store.keys.keys().collect();
                    log_debug!("jwk_cache[pdp]: 304 {}, kids={kids:?}", store.meta);
                }
            } else {
                let meta = HttpCacheMeta::from_response(&resp);
                let jwk_set: JwkSet = resp.json().await?;
                let mut jwks = JwkStore {
                    meta,
                    ..Default::default()
                };
                for jwk in jwk_set.keys {
                    let kid = jwk.common.key_id.as_ref().expect("kid").clone();
                    let existing = jwks.keys.insert(kid.clone(), jwk);
                    if existing.is_some() {
                        bail!("pdp: duplicate kid: {kid}");
                    }
                }
                let kids: Vec<_> = jwks.keys.keys().collect();
                log_debug!("jwk_cache[pdp]: refresh {}, kids={kids:?}", jwks.meta);
                pdp_jwks.replace(jwks);
            }

            Ok(())
        }

        /// Fetch PoPP JWKS via entity statement indirection, respecting HTTP cache
        /// semantics. See [`Self::fetch_pdp_inner`] for `force` semantics.
        async fn fetch_popp_inner(&self, force: bool, xff: Option<&str>) -> anyhow::Result<()> {
            // config for now; once federation master provides services list, use it to discover PoPP
            let issuer = self.popp_issuer.clone();
            match issuer {
                Some(issuer) => {
                    let client = CLIENT.get().expect("client");
                    let issuer = issuer.trim_end_matches('/');

                    let mut validation = Validation::new(Algorithm::ES256);
                    validation.validate_aud = false; // disabled until we know how this behaves in production
                    validation.validate_nbf = true; // validate if present
                    validation.set_required_spec_claims(&["exp"]);

                    // --- Step 1: resolve signed_jwks_uri + entity JWKS via entity statement ---
                    let (entity_jwks, signed_jwks_url) = {
                        let cached = self.popp_entity.read().await;
                        if !force && cached.as_ref().is_some_and(|c| c.meta.is_fresh()) {
                            let c = cached.as_ref().unwrap();
                            (c.jwks.clone(), c.signed_jwks_uri.clone())
                        } else {
                            let entity_url = format!("{issuer}/.well-known/openid-federation");
                            let old_meta =
                                cached.as_ref().map(|c| c.meta.clone()).unwrap_or_default();

                            drop(cached);

                            let resp = conditional_get(client, &entity_url, &old_meta, xff).await?;

                            let mut popp_entity = self.popp_entity.write().await;
                            if resp.status() == StatusCode::NOT_MODIFIED {
                                let entry = popp_entity.as_mut().ok_or_else(|| {
                                    anyhow!("popp: 304 but no cached entity statement")
                                })?;
                                entry.meta.merge_response(&resp);
                                log_debug!("jwk_cache[popp]: entity statement 304 not modified");
                                (entry.jwks.clone(), entry.signed_jwks_uri.clone())
                            } else {
                                let meta = HttpCacheMeta::from_response(&resp);
                                let entity_bytes = resp.bytes().await?;
                                if !is_base64url_char(entity_bytes[0]) {
                                    bail!(
                                        "Bad PoPP entity statement: {}",
                                        Base64::encode_string(&entity_bytes)
                                    );
                                }
                                let entity_statement_insecure: TokenData<EntityStatement> =
                                    jsonwebtoken::dangerous::insecure_decode(&entity_bytes)
                                        .context("fetch PoPP entity statement")?;
                                let entity_kid =
                                    entity_statement_insecure.header.kid.ok_or_else(|| {
                                        anyhow!("missing kid header in entity statement")
                                    })?;
                                let entity_key = entity_statement_insecure
                                    .claims
                                    .jwks
                                    .find(&entity_kid)
                                    .and_then(|key| DecodingKey::from_jwk(key).ok())
                                    .ok_or_else(|| {
                                        anyhow!("missing or invalid key '{}'", entity_kid)
                                    })?;
                                let entity_statement: EntityStatement =
                                    jsonwebtoken::decode(entity_bytes, &entity_key, &validation)
                                        .context("fetch PoPP signed key set")?
                                        .claims;

                                let mut jwks_url =
                                    entity_statement.metadata.oauth_resource.signed_jwks_uri;
                                if !jwks_url.to_ascii_lowercase().starts_with("http") {
                                    if jwks_url.starts_with('/') {
                                        jwks_url = format!("{issuer}{jwks_url}");
                                    } else {
                                        jwks_url = format!("{issuer}/{jwks_url}");
                                    }
                                }

                                let jwks = entity_statement.jwks.clone();
                                *popp_entity = Some(EntityCacheEntry {
                                    jwks: entity_statement.jwks,
                                    signed_jwks_uri: jwks_url.clone(),
                                    meta,
                                });
                                (jwks, jwks_url)
                            }
                        }
                    };

                    // --- Step 2: fetch signed JWKS ---
                    let old_meta = {
                        let cached = self.popp_jwks.read().await;
                        if !force && cached.as_ref().is_some_and(|s| s.meta.is_fresh()) {
                            log_debug!("jwk_cache[popp]: signed JWKS still fresh, skipping fetch");
                            return Ok(());
                        }
                        cached.as_ref().map(|s| s.meta.clone()).unwrap_or_default()
                    };

                    let resp = conditional_get(client, &signed_jwks_url, &old_meta, xff).await?;

                    let mut popp_jwks = self.popp_jwks.write().await;

                    if resp.status() == StatusCode::NOT_MODIFIED {
                        if let Some(store) = popp_jwks.as_mut() {
                            store.meta.merge_response(&resp);
                            let kids: Vec<_> = store.keys.keys().collect();
                            log_debug!("jwk_cache[popp]: 304 {}, kids={kids:?}", store.meta);
                        }
                    } else {
                        let meta = HttpCacheMeta::from_response(&resp);
                        let jwks_bytes = resp.bytes().await?;
                        if !is_base64url_char(jwks_bytes[0]) {
                            bail!(
                                "Bad PoPP signed JWKS: {}",
                                Base64::encode_string(&jwks_bytes)
                            );
                        }
                        let jwks_header = jsonwebtoken::decode_header(&jwks_bytes)?;
                        let jwks_kid = jwks_header
                            .kid
                            .ok_or_else(|| anyhow!("missing kid header in signed JWKS"))?;
                        let jwks_key = entity_jwks
                            .find(&jwks_kid)
                            .and_then(|key| DecodingKey::from_jwk(key).ok())
                            .ok_or_else(|| anyhow!("missing or invalid key '{}'", jwks_kid))?;
                        let signed_jwks: SignedJwkSet =
                            jsonwebtoken::decode(jwks_bytes, &jwks_key, &validation)
                                .context("fetch PoPP signed key set")?
                                .claims;

                        let mut jwks = JwkStore {
                            meta,
                            ..Default::default()
                        };
                        for jwk in signed_jwks.jwks.keys {
                            let kid = jwk.common.key_id.as_ref().expect("kid").clone();
                            let existing = jwks.keys.insert(kid.clone(), jwk);
                            if existing.is_some() {
                                bail!("popp: duplicate kid: {kid}");
                            }
                        }
                        let kids: Vec<_> = jwks.keys.keys().collect();
                        log_debug!("jwk_cache[popp]: refresh {}, kids={kids:?}", jwks.meta);
                        popp_jwks.replace(jwks);
                    }
                }
                None => {
                    log_debug!("jwk_cache[popp]: no pep_popp_issuer configured, skipping refresh");
                }
            };
            Ok(())
        }
    }

    impl JwkCacheOps for JwkCache {
        async fn fetch_pdp(&self) -> anyhow::Result<()> {
            self.refresh_pdp(false, None).await
        }

        async fn get_jwk_pdp(&self, kid: String, client_ip: Option<String>) -> anyhow::Result<Jwk> {
            let mut jwk = self.pdp_jwks.get_key(&kid).await;
            if jwk.is_none() {
                log_debug!(
                    "jwk_cache[pdp]: {kid} not found (have {:?}), refresh and retry…",
                    self.pdp_jwks.read().await
                );
                self.refresh_pdp(true, client_ip.as_deref()).await?;
                jwk = self.pdp_jwks.get_key(&kid).await;
            }
            jwk.ok_or_else(|| anyhow!("pdp: {kid} not found"))
        }

        async fn fetch_popp(&self) -> anyhow::Result<()> {
            self.refresh_popp(false, None).await
        }

        async fn get_jwk_popp(
            &self,
            kid: String,
            client_ip: Option<String>,
        ) -> anyhow::Result<Jwk> {
            if self.popp_issuer.is_none() {
                bail!("popp: no pep_popp_issuer configured");
            }

            let mut jwk = self.popp_jwks.get_key(&kid).await;
            if jwk.is_none() {
                log_debug!(
                    "jwk_cache[popp]: {kid} not found (have {:?}), refresh and retry…",
                    self.popp_jwks.read().await
                );
                self.refresh_popp(true, client_ip.as_deref()).await?;
                jwk = self.popp_jwks.get_key(&kid).await;
            }
            jwk.ok_or_else(|| anyhow!("popp: {kid} not found"))
        }
    }

    pub fn jwk_cache() -> &'static impl JwkCacheOps {
        JWK_CACHE.get().expect("JwkCache not initialized")
    }
}
#[cfg(not(test))]
pub use prod::*;

#[cfg(test)]
pub use mock::*;

#[cfg(test)]
mod mock {
    use super::*;
    use std::sync::LazyLock;
    use tokio::sync::RwLock;

    pub static JWK_CACHE_MOCK: LazyLock<RwLock<MockJwkCacheOps>> =
        LazyLock::new(|| RwLock::new(MockJwkCacheOps::new()));

    impl JwkCacheOps for RwLock<MockJwkCacheOps> {
        async fn fetch_pdp(&self) -> anyhow::Result<()> {
            let guard = self.read().await;
            guard.fetch_pdp().await
        }

        async fn get_jwk_pdp(&self, kid: String, client_ip: Option<String>) -> anyhow::Result<Jwk> {
            let guard = self.read().await;
            guard.get_jwk_pdp(kid, client_ip).await
        }

        async fn fetch_popp(&self) -> anyhow::Result<()> {
            let guard = self.read().await;
            guard.fetch_popp().await
        }

        async fn get_jwk_popp(
            &self,
            kid: String,
            client_ip: Option<String>,
        ) -> anyhow::Result<Jwk> {
            let guard = self.read().await;
            guard.get_jwk_popp(kid, client_ip).await
        }
    }

    pub async fn with_jwk_cache_mock<T>(f: impl FnOnce(&mut MockJwkCacheOps) -> T) -> T {
        let mut g = JWK_CACHE_MOCK.write().await;
        f(&mut g)
    }

    pub async fn reset_jwk_cache_mock() {
        *JWK_CACHE_MOCK.write().await = MockJwkCacheOps::new();
    }

    pub fn jwk_cache() -> &'static impl JwkCacheOps {
        &*JWK_CACHE_MOCK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderMap;

    fn meta_with(etag: Option<&str>, lm: Option<&str>, max_age: Option<u64>) -> HttpCacheMeta {
        HttpCacheMeta {
            etag: etag.map(Into::into),
            last_modified: lm.map(Into::into),
            max_age: max_age.map(Duration::from_secs),
            fetched_at: Some(Instant::now()),
            fetched_at_epoch: 1744300000,
        }
    }

    // --- is_fresh ---

    #[test]
    fn fresh_when_within_max_age() {
        let meta = meta_with(None, None, Some(300));
        assert!(meta.is_fresh());
    }

    #[test]
    fn stale_when_max_age_zero() {
        let meta = meta_with(None, None, Some(0));
        assert!(!meta.is_fresh());
    }

    #[test]
    fn stale_when_no_max_age() {
        let meta = meta_with(Some("\"abc\""), None, None);
        assert!(!meta.is_fresh());
    }

    #[test]
    fn stale_when_no_fetched_at() {
        let meta = HttpCacheMeta {
            max_age: Some(Duration::from_secs(300)),
            ..Default::default()
        };
        assert!(!meta.is_fresh());
    }

    #[test]
    fn stale_when_default() {
        assert!(!HttpCacheMeta::default().is_fresh());
    }

    // --- trustworthy ---

    #[test]
    fn trustworthy_within_max_age() {
        let meta = meta_with(None, None, Some(300));
        assert!(meta.trustworthy(Duration::from_secs(60)));
    }

    #[test]
    fn trustworthy_within_grace_when_no_max_age() {
        // Server didn't send Cache-Control: max_age defaults to 0, but grace
        // alone keeps the cache trustworthy briefly past last fetch.
        let meta = meta_with(Some("\"abc\""), None, None);
        assert!(meta.trustworthy(Duration::from_secs(60)));
    }

    #[test]
    fn trustworthy_within_grace_when_max_age_zero() {
        let meta = meta_with(None, None, Some(0));
        assert!(meta.trustworthy(Duration::from_secs(60)));
    }

    #[test]
    fn untrustworthy_when_no_fetched_at() {
        let meta = HttpCacheMeta {
            max_age: Some(Duration::from_secs(300)),
            ..Default::default()
        };
        assert!(!meta.trustworthy(Duration::from_secs(60)));
    }

    #[test]
    fn untrustworthy_with_zero_grace_and_zero_max_age() {
        // max_age=0 + grace=0 → window is 0, immediately stale
        let meta = meta_with(None, None, Some(0));
        assert!(!meta.trustworthy(Duration::ZERO));
    }

    #[test]
    fn untrustworthy_when_default() {
        assert!(!HttpCacheMeta::default().trustworthy(Duration::from_secs(60)));
    }

    // --- parse_max_age ---

    #[test]
    fn parse_max_age_simple() {
        let mut h = HeaderMap::new();
        h.insert(CACHE_CONTROL, "max-age=300".parse().unwrap());
        assert_eq!(
            HttpCacheMeta::parse_max_age(&h),
            Some(Duration::from_secs(300))
        );
    }

    #[test]
    fn parse_max_age_with_other_directives() {
        let mut h = HeaderMap::new();
        h.insert(
            CACHE_CONTROL,
            "public, max-age=600, must-revalidate".parse().unwrap(),
        );
        assert_eq!(
            HttpCacheMeta::parse_max_age(&h),
            Some(Duration::from_secs(600))
        );
    }

    #[test]
    fn parse_max_age_zero() {
        let mut h = HeaderMap::new();
        h.insert(CACHE_CONTROL, "max-age=0".parse().unwrap());
        assert_eq!(
            HttpCacheMeta::parse_max_age(&h),
            Some(Duration::from_secs(0))
        );
    }

    #[test]
    fn parse_max_age_missing_header() {
        assert_eq!(HttpCacheMeta::parse_max_age(&HeaderMap::new()), None);
    }

    #[test]
    fn parse_max_age_no_max_age_directive() {
        let mut h = HeaderMap::new();
        h.insert(CACHE_CONTROL, "no-cache, no-store".parse().unwrap());
        assert_eq!(HttpCacheMeta::parse_max_age(&h), None);
    }

    #[test]
    fn parse_max_age_garbage_value() {
        let mut h = HeaderMap::new();
        h.insert(CACHE_CONTROL, "max-age=notanumber".parse().unwrap());
        assert_eq!(HttpCacheMeta::parse_max_age(&h), None);
    }

    // --- Display ---

    #[test]
    fn display_full() {
        let meta = HttpCacheMeta {
            etag: Some("\"69ce6ab1234567890\"".into()),
            last_modified: Some("Thu, 02 Apr 2026 13:10:18 GMT".into()),
            max_age: Some(Duration::from_secs(300)),
            fetched_at: Some(Instant::now()),
            fetched_at_epoch: 1744300000, // 2025-04-10 some time
        };
        let s = meta.to_string();
        assert!(s.contains("max-age=300"));
        assert!(s.contains("etag=\"69ce6ab"), "etag truncated: {s}");
        assert!(s.contains("\u{2026}"), "etag has ellipsis: {s}");
        assert!(s.contains("lm=Thu, 02 Apr 2026 13:10:18 GMT"));
        assert!(s.starts_with('@'));
    }

    #[test]
    fn display_minimal() {
        let meta = HttpCacheMeta {
            fetched_at_epoch: 1744300000,
            ..Default::default()
        };
        let s = meta.to_string();
        assert!(s.starts_with('@'));
        assert!(!s.contains("max-age"));
        assert!(!s.contains("etag"));
        assert!(!s.contains("lm="));
    }

    #[test]
    fn display_short_etag() {
        let meta = HttpCacheMeta {
            etag: Some("\"ab\"".into()),
            fetched_at_epoch: 0,
            ..Default::default()
        };
        let s = meta.to_string();
        assert!(
            s.contains("etag=\"ab\"\u{2026}"),
            "short etag kept whole: {s}"
        );
    }
}
