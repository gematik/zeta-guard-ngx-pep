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
use reqwest::header::{CACHE_CONTROL, ETAG, HeaderMap, LAST_MODIFIED};
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
    /// Monotonic instant of the last full (non-304) response
    installed_at: Option<Instant>,
    /// Wall-clock epoch seconds for logging
    fetched_at_epoch: u64,
}

impl HttpCacheMeta {
    /// True once the content is older than `max_lifetime`, however often it
    /// was revalidated since: it must then be fetched again in full.
    fn must_reinstall(&self, max_lifetime: Duration) -> bool {
        self.installed_at
            .is_none_or(|at| at.elapsed() >= max_lifetime)
    }

    fn is_fresh(&self, max_lifetime: Duration) -> bool {
        if self.must_reinstall(max_lifetime) {
            return false;
        }
        match (self.fetched_at, self.max_age) {
            (Some(at), Some(max_age)) => at.elapsed() < max_age,
            _ => false,
        }
    }

    /// Metadata to derive the next request's validators from: none once
    /// [`Self::must_reinstall`] holds, so the server cannot answer 304.
    fn validators(&self, max_lifetime: Duration) -> Self {
        if self.must_reinstall(max_lifetime) {
            Self::default()
        } else {
            self.clone()
        }
    }

    /// True if the cache is still trustworthy enough to use even when the
    /// most recent refresh attempt failed: within `max_age + grace` of the
    /// last successful fetch. `max_age` defaults to 0 if the server didn't
    /// say (so the trust window is just `grace`). Never beyond
    /// `max_lifetime + grace` of the last full response.
    fn trustworthy(&self, grace: Duration, max_lifetime: Duration) -> bool {
        match (self.fetched_at, self.installed_at) {
            (Some(fetched), Some(installed)) => {
                fetched.elapsed() < self.max_age.unwrap_or_default().saturating_add(grace)
                    && installed.elapsed() < max_lifetime.saturating_add(grace)
            }
            _ => false,
        }
    }

    fn from_headers(h: &HeaderMap) -> Self {
        Self {
            etag: h.get(ETAG).and_then(|v| v.to_str().ok()).map(Into::into),
            last_modified: h
                .get(LAST_MODIFIED)
                .and_then(|v| v.to_str().ok())
                .map(Into::into),
            max_age: Self::parse_max_age(h),
            fetched_at: Some(Instant::now()),
            installed_at: Some(Instant::now()),
            fetched_at_epoch: jsonwebtoken::get_current_timestamp(),
        }
    }

    /// Merge metadata from a (possibly 304) response's headers, keeping existing
    /// values for headers the server didn't repeat.
    fn merge_headers(&mut self, h: &HeaderMap) {
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

/// Origin (scheme + host[:port]) of the public issuer, presented to the IdP when
/// it is reached over an internal address so its advertised URLs stay public.
#[derive(Debug, Clone, PartialEq)]
struct ForwardedOrigin {
    scheme: String,
    host: String,
}

impl ForwardedOrigin {
    /// `None` when `issuer` has no host, or is not a URL we could impersonate.
    fn from_issuer(issuer: &str) -> Option<Self> {
        let url = reqwest::Url::parse(issuer).ok()?;
        let host = match (url.host_str()?, url.port()) {
            (h, Some(p)) => format!("{h}:{p}"),
            (h, None) => h.to_string(),
        };
        Some(Self {
            scheme: url.scheme().to_string(),
            host,
        })
    }
}

/// Rewrite a discovery-advertised `jwks_uri` onto the internal base URL.
///
/// The IdP advertises its *public* frontend URL, so with `pep_pdp_url` set the
/// JWKS would otherwise still be fetched over the public path even though
/// discovery already went in-cluster.
///
/// Only the `issuer` prefix is substituted. A `jwks_uri` that does not sit under
/// the issuer returns `None` so the caller can warn and fall back to the
/// advertised URI, rather than being silently redirected somewhere internal.
fn internalize_jwks_uri(jwks_uri: &str, issuer: &str, fetch_base: &str) -> Option<String> {
    let issuer = issuer.trim_end_matches('/');
    let fetch_base = fetch_base.trim_end_matches('/');
    if issuer == fetch_base {
        return Some(jwks_uri.to_string());
    }
    let rest = jwks_uri.strip_prefix(issuer)?;
    // Guard against a prefix that matches only partially, e.g. issuer
    // `https://h/realms/zeta` vs `https://h/realms/zeta-other/...`.
    if !rest.is_empty() && !rest.starts_with('/') {
        return None;
    }
    Some(format!("{fetch_base}{rest}"))
}

#[cfg_attr(test, allow(unused))]
mod prod {
    use std::collections::HashMap;

    use anyhow::{Context, anyhow, bail};
    use base64ct::Base64;
    use bytes::Bytes;
    use http::Method;
    use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation, jwk::JwkSet};
    use reqwest::header::{HOST, HeaderMap, IF_MODIFIED_SINCE, IF_NONE_MATCH};
    use reqwest::{StatusCode, Url};
    use tokio::{sync::RwLock, time::Instant};
    use tracing::{debug, error, info, instrument, warn};

    use crate::headers::forwarded_for_value;
    use crate::otel::{traced_outbound, traced_request};
    use crate::spawn_compat;

    use {
        super::{ForwardedOrigin, HttpCacheMeta, JwkCacheOps},
        crate::{CLIENT, conf::MainConfig},
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
    /// When `forwarded_for` is set, both `Forwarded: for=…` and `X-Forwarded-For`
    /// headers are added so the IdP can attribute the request to the client that
    /// triggered a force-refresh. We send both for compatibility reasons.
    async fn conditional_get(
        client: &reqwest::Client,
        url: &str,
        meta: &HttpCacheMeta,
        forwarded_for: Option<&str>,
        origin: Option<&ForwardedOrigin>,
        max_lifetime: Duration,
    ) -> anyhow::Result<(StatusCode, HeaderMap, Bytes)> {
        let method = Method::GET;
        let url: Url = url.parse()?;
        let (mut request, span) = traced_outbound!(client, method, url, "jwk_cache_fetch");
        if let Some(etag) = &meta.etag {
            request = request.header(IF_NONE_MATCH, etag.as_str());
        }
        if let Some(lm) = &meta.last_modified {
            request = request.header(IF_MODIFIED_SINCE, lm.as_str());
        }
        if let Some(forwarded_for) = forwarded_for {
            request = request.header("Forwarded", forwarded_for_value(forwarded_for));
            request = request.header("X-Forwarded-For", forwarded_for);
        }
        // Reaching the IdP over an internal address must not change the URLs it
        // advertises: an IdP that derives them from the request (Keycloak with a
        // bare `--hostname`) would answer with the internal scheme/host, and the
        // issuer check below would reject its own metadata. Present the public
        // issuer's origin so it renders frontend URLs as if reached there.
        if let Some(o) = origin {
            request = request.header(HOST, o.host.as_str());
            request = request.header("X-Forwarded-Proto", o.scheme.as_str());
            request = request.header("X-Forwarded-Host", o.host.as_str());
        }
        let (status, headers, body) = traced_request(request, span)
            .await
            .context("request error")?;
        // traced_request relays any status; the JWKS endpoints must answer 2xx
        // (fresh) or 304 (cache hit) — anything else is a fetch failure.
        if !status.is_success() && status != StatusCode::NOT_MODIFIED {
            bail!("unexpected status {status}");
        }
        if status == StatusCode::NOT_MODIFIED && meta.etag.is_none() && meta.last_modified.is_none()
        {
            bail!("304 in response to an unconditional request");
        }
        if let Some(max_age) = HttpCacheMeta::parse_max_age(&headers)
            && max_age > max_lifetime
        {
            warn!(
                %url,
                max_age = max_age.as_secs(),
                max_lifetime = max_lifetime.as_secs(),
                "max-age exceeds pep_jwks_max_lifetime, limited to the latter"
            );
        }
        Ok((status, headers, body))
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
        /// URI the keys were fetched from
        source: String,
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
        /// Base URL actually dialed for PDP discovery/JWKS. Equals `pdp_issuer`
        /// unless `pep_pdp_url` moves the network path in-cluster.
        pdp_url: String,
        pdp_oidc: RwLock<Option<OidcCacheEntry>>,
        pdp_jwks: RwLock<Option<JwkStore>>,
        popp_issuer: Option<String>,
        popp_entity: RwLock<Option<EntityCacheEntry>>,
        popp_jwks: RwLock<Option<JwkStore>>,
        refresh_interval: Duration,
        /// Upper bound for how long any cached document is used without a
        /// full refetch, regardless of what the server's cache headers say.
        max_lifetime: Duration,
    }

    impl JwkCache {
        pub fn init(conf: &MainConfig) {
            let cache = JWK_CACHE.get_or_init(|| JwkCache {
                pdp_issuer: conf.pdp_issuer.as_ref().expect("issuer").clone(),
                pdp_url: conf
                    .pdp_url
                    .clone()
                    .unwrap_or_else(|| conf.pdp_issuer.as_ref().expect("issuer").clone()),
                pdp_oidc: Default::default(),
                pdp_jwks: Default::default(),
                popp_issuer: conf.popp_issuer.clone(),
                popp_entity: Default::default(),
                popp_jwks: Default::default(),
                refresh_interval: conf.jwks_refresh_interval,
                max_lifetime: conf.jwks_max_lifetime,
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

        /// Seconds since the last successful refresh per target, for the
        /// staleness gauges. `None` per target when nothing was fetched yet
        /// (or popp is unconfigured), or the (tokio) lock is briefly contended
        /// — observable gauges tolerate skipped samples. Called from the
        /// metrics PeriodicReader thread, hence `try_read`.
        pub fn staleness_secs(&self) -> [(&'static str, Option<u64>); 2] {
            let now = jsonwebtoken::get_current_timestamp();
            let age = |jwks: &RwLock<Option<JwkStore>>| {
                let epoch = jwks.try_read().ok()?.as_ref()?.meta.fetched_at_epoch;
                Some(now.saturating_sub(epoch))
            };
            [("pdp", age(&self.pdp_jwks)), ("popp", age(&self.popp_jwks))]
        }

        /// Wrapper around [`Self::fetch_pdp_inner`] that drops the cached data on refresh failure
        /// after a grace period (see [`HttpCacheMeta::trustworthy`]).
        #[instrument(skip(self))]
        async fn refresh_pdp(
            &self,
            force: bool,
            forwarded_for: Option<&str>,
        ) -> anyhow::Result<()> {
            let result = self.fetch_pdp_inner(force, forwarded_for).await;
            let outcome;
            if let Err(e) = &result {
                let grace = self.refresh_interval;
                // Take write locks first (in inner's lock order) and re-check
                // trustworthiness inside, so a concurrent successful refresh
                // can't be clobbered by our drop.
                let mut oidc_guard = self.pdp_oidc.write().await;
                let mut jwks_guard = self.pdp_jwks.write().await;
                let trustworthy = jwks_guard
                    .as_ref()
                    .is_some_and(|s| s.meta.trustworthy(grace, self.max_lifetime));
                if trustworthy {
                    warn!(error = %e, "refresh failed (in grace, cache kept)");
                    outcome = "err_in_grace";
                } else {
                    *jwks_guard = None;
                    *oidc_guard = None;
                    error!(error = %e, "refresh failed past grace, cache dropped");
                    outcome = "err_dropped";
                }
            } else {
                outcome = "ok";
            }
            crate::metrics::JWK_REFRESH.add(
                1,
                &[
                    opentelemetry::KeyValue::new("target", "pdp"),
                    opentelemetry::KeyValue::new("outcome", outcome),
                ],
            );
            result
        }

        /// Wrapper around [`Self::fetch_popp_inner`] that drops the cached data on refresh failure
        /// after a grace period (see [`HttpCacheMeta::trustworthy`]).
        #[instrument(skip(self))]
        async fn refresh_popp(
            &self,
            force: bool,
            forwarded_for: Option<&str>,
        ) -> anyhow::Result<()> {
            let result = self.fetch_popp_inner(force, forwarded_for).await;
            let outcome;
            if let Err(e) = &result {
                let grace = self.refresh_interval;
                let mut entity_guard = self.popp_entity.write().await;
                let mut jwks_guard = self.popp_jwks.write().await;
                let trustworthy = jwks_guard
                    .as_ref()
                    .is_some_and(|s| s.meta.trustworthy(grace, self.max_lifetime));
                if trustworthy {
                    warn!(error = %e, "refresh failed (in grace, cache kept)");
                    outcome = "err_in_grace";
                } else {
                    *jwks_guard = None;
                    *entity_guard = None;
                    error!(error = %e, "refresh failed past grace, cache dropped");
                    outcome = "err_dropped";
                }
            } else {
                outcome = "ok";
            }
            crate::metrics::JWK_REFRESH.add(
                1,
                &[
                    opentelemetry::KeyValue::new("target", "popp"),
                    opentelemetry::KeyValue::new("outcome", outcome),
                ],
            );
            result
        }

        /// Fetch PDP JWKS, respecting HTTP cache semantics.
        /// When `force` is false, cached responses that are still fresh are kept.
        /// When `force` is true (on-demand kid miss), freshness is bypassed but
        /// conditional GET is still used to save bandwidth.
        async fn fetch_pdp_inner(
            &self,
            force: bool,
            forwarded_for: Option<&str>,
        ) -> anyhow::Result<()> {
            let client = CLIENT.get().expect("client");
            let issuer = self.pdp_issuer.trim_end_matches('/');
            // Network path. Identical to `issuer` unless pep_pdp_url is set.
            let fetch_base = self.pdp_url.trim_end_matches('/');
            // Only when the two differ do we have to make the IdP answer as if it
            // had been reached at the public issuer.
            let origin = (issuer != fetch_base)
                .then(|| ForwardedOrigin::from_issuer(&self.pdp_issuer))
                .flatten();
            let origin = origin.as_ref();

            // --- Step 1: resolve JWKS URI via OIDC discovery ---
            let jwks_uri = {
                let cached = self.pdp_oidc.read().await;
                if !force
                    && cached
                        .as_ref()
                        .is_some_and(|c| c.meta.is_fresh(self.max_lifetime))
                {
                    cached.as_ref().unwrap().jwks_uri.clone()
                } else {
                    let old_meta = cached
                        .as_ref()
                        .map(|c| c.meta.validators(self.max_lifetime))
                        .unwrap_or_default();
                    drop(cached);

                    let well_known = format!("{fetch_base}/.well-known/openid-configuration");

                    let (status, headers, body) = conditional_get(
                        client,
                        &well_known,
                        &old_meta,
                        forwarded_for,
                        origin,
                        self.max_lifetime,
                    )
                    .await?;

                    let mut pdp_oidc = self.pdp_oidc.write().await;
                    if status == StatusCode::NOT_MODIFIED {
                        let entry = pdp_oidc
                            .as_mut()
                            .ok_or_else(|| anyhow!("pdp: 304 but no cached OIDC config"))?;
                        entry.meta.merge_headers(&headers);
                        debug!("OIDC discovery 304 not modified");
                        entry.jwks_uri.clone()
                    } else {
                        let meta = HttpCacheMeta::from_headers(&headers);
                        let cfg: OidcConfig =
                            serde_json::from_slice(&body).context("parse OIDC config")?;
                        // Compared against the *identity*, never against the fetch
                        // base: the IdP advertises its public issuer even when we
                        // reached it over an internal address.
                        if cfg.issuer != self.pdp_issuer {
                            bail!("pdp: issuer mismatch");
                        }
                        let uri = super::internalize_jwks_uri(&cfg.jwks_uri, issuer, fetch_base)
                            .unwrap_or_else(|| {
                                warn!(
                                    jwks_uri = %cfg.jwks_uri,
                                    "pdp: jwks_uri is not under the configured issuer; \
                                     fetching it as advertised (pep_pdp_url not applied)"
                                );
                                cfg.jwks_uri.clone()
                            });
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
                let mut cached = self.pdp_jwks.write().await;
                if cached.as_ref().is_some_and(|s| s.source != jwks_uri) {
                    warn!(jwks_uri, "pdp: jwks_uri changed, cached keys dropped");
                    *cached = None;
                }
                if !force
                    && cached
                        .as_ref()
                        .is_some_and(|s| s.meta.is_fresh(self.max_lifetime))
                {
                    debug!("JWKS still fresh, skipping fetch");
                    return Ok(());
                }

                cached
                    .as_ref()
                    .map(|s| s.meta.validators(self.max_lifetime))
                    .unwrap_or_default()
            };

            let (status, headers, body) = conditional_get(
                client,
                &jwks_uri,
                &old_meta,
                forwarded_for,
                origin,
                self.max_lifetime,
            )
            .await?;

            let mut pdp_jwks = self.pdp_jwks.write().await;
            if status == StatusCode::NOT_MODIFIED {
                if let Some(store) = pdp_jwks.as_mut() {
                    store.meta.merge_headers(&headers);
                    let kids: Vec<_> = store.keys.keys().collect();
                    debug!(meta = %store.meta, ?kids, "JWKS 304 not modified");
                }
            } else {
                let meta = HttpCacheMeta::from_headers(&headers);
                let jwk_set: JwkSet = serde_json::from_slice(&body).context("parse JWKS")?;
                let mut jwks = JwkStore {
                    meta,
                    source: jwks_uri.clone(),
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
                info!(meta = %jwks.meta, ?kids, "JWKS refreshed");
                pdp_jwks.replace(jwks);
            }

            Ok(())
        }

        /// Fetch PoPP JWKS via entity statement indirection, respecting HTTP cache
        /// semantics. See [`Self::fetch_pdp_inner`] for `force` semantics.
        async fn fetch_popp_inner(
            &self,
            force: bool,
            forwarded_for: Option<&str>,
        ) -> anyhow::Result<()> {
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
                        if !force
                            && cached
                                .as_ref()
                                .is_some_and(|c| c.meta.is_fresh(self.max_lifetime))
                        {
                            let c = cached.as_ref().unwrap();
                            (c.jwks.clone(), c.signed_jwks_uri.clone())
                        } else {
                            let entity_url = format!("{issuer}/.well-known/openid-federation");
                            let old_meta = cached
                                .as_ref()
                                .map(|c| c.meta.validators(self.max_lifetime))
                                .unwrap_or_default();

                            drop(cached);

                            let (status, headers, body) = conditional_get(
                                client,
                                &entity_url,
                                &old_meta,
                                forwarded_for,
                                None,
                                self.max_lifetime,
                            )
                            .await?;

                            let mut popp_entity = self.popp_entity.write().await;
                            if status == StatusCode::NOT_MODIFIED {
                                let entry = popp_entity.as_mut().ok_or_else(|| {
                                    anyhow!("popp: 304 but no cached entity statement")
                                })?;
                                entry.meta.merge_headers(&headers);
                                debug!("entity statement 304 not modified");
                                (entry.jwks.clone(), entry.signed_jwks_uri.clone())
                            } else {
                                let meta = HttpCacheMeta::from_headers(&headers);
                                let entity_bytes = body;
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
                        let mut cached = self.popp_jwks.write().await;
                        if cached.as_ref().is_some_and(|s| s.source != signed_jwks_url) {
                            warn!(
                                signed_jwks_url,
                                "popp: signed_jwks_uri changed, cached keys dropped"
                            );
                            *cached = None;
                        }
                        if !force
                            && cached
                                .as_ref()
                                .is_some_and(|s| s.meta.is_fresh(self.max_lifetime))
                        {
                            debug!("signed JWKS still fresh, skipping fetch");
                            return Ok(());
                        }
                        cached
                            .as_ref()
                            .map(|s| s.meta.validators(self.max_lifetime))
                            .unwrap_or_default()
                    };

                    let (status, headers, body) = conditional_get(
                        client,
                        &signed_jwks_url,
                        &old_meta,
                        forwarded_for,
                        None,
                        self.max_lifetime,
                    )
                    .await?;

                    let mut popp_jwks = self.popp_jwks.write().await;

                    if status == StatusCode::NOT_MODIFIED {
                        if let Some(store) = popp_jwks.as_mut() {
                            store.meta.merge_headers(&headers);
                            let kids: Vec<_> = store.keys.keys().collect();
                            debug!(meta = %store.meta, ?kids, "signed JWKS 304 not modified");
                        }
                    } else {
                        let meta = HttpCacheMeta::from_headers(&headers);
                        let jwks_bytes = body;
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
                            source: signed_jwks_url.clone(),
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
                        info!(meta = %jwks.meta, ?kids, "JWKS refreshed");
                        popp_jwks.replace(jwks);
                    }
                }
                None => {
                    debug!("no pep_popp_issuer configured, skipping refresh");
                }
            };
            Ok(())
        }
    }

    impl JwkCacheOps for JwkCache {
        async fn fetch_pdp(&self) -> anyhow::Result<()> {
            self.refresh_pdp(false, None).await
        }

        #[instrument(skip(self))]
        async fn get_jwk_pdp(&self, kid: String, client_ip: Option<String>) -> anyhow::Result<Jwk> {
            let mut jwk = self.pdp_jwks.get_key(&kid).await;
            if jwk.is_none() {
                info!(
                    kid,
                    have = ?*self.pdp_jwks.read().await,
                    "kid not found, refresh and retry"
                );
                self.refresh_pdp(true, client_ip.as_deref()).await?;
                jwk = self.pdp_jwks.get_key(&kid).await;
            }
            jwk.ok_or_else(|| anyhow!("pdp: {kid} not found"))
        }

        async fn fetch_popp(&self) -> anyhow::Result<()> {
            self.refresh_popp(false, None).await
        }

        #[instrument(skip(self))]
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
                info!(
                    kid,
                    have = ?*self.popp_jwks.read().await,
                    "kid not found, refresh and retry"
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

    #[cfg(test)]
    mod tests {
        use std::convert::Infallible;
        use std::sync::{Arc, Mutex};

        use http_body_util::Full;
        use hyper::body::Incoming;
        use hyper::header::{CACHE_CONTROL, ETAG, IF_NONE_MATCH};
        use hyper::service::service_fn;
        use hyper::{Request, Response};
        use hyper_util::rt::TokioIo;
        use tokio::net::TcpListener;

        use super::*;

        const MAX_LIFETIME: Duration = Duration::from_secs(60);
        const TEN_YEARS: u64 = 315_360_000;

        struct Pdp {
            issuer: String,
            jwks_path: &'static str,
            kids: Vec<&'static str>,
            etag: &'static str,
            max_age: u64,
            /// answer 200 even to a matching `If-None-Match`
            ignore_validators: bool,
            jwks_200: usize,
            jwks_304: usize,
        }

        impl Pdp {
            fn handle(&mut self, req: &Request<Incoming>) -> Response<Full<Bytes>> {
                let path = req.uri().path();
                if path == "/.well-known/openid-configuration" {
                    let body = serde_json::json!({
                        "issuer": self.issuer,
                        "jwks_uri": format!("{}{}", self.issuer, self.jwks_path),
                    });
                    return Response::new(Full::new(body.to_string().into()));
                }
                if path != self.jwks_path {
                    return Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Full::default())
                        .unwrap();
                }
                let response = Response::builder()
                    .header(ETAG, self.etag)
                    .header(CACHE_CONTROL, format!("max-age={}", self.max_age));
                let matches = req
                    .headers()
                    .get(IF_NONE_MATCH)
                    .is_some_and(|v| v.as_bytes() == self.etag.as_bytes());
                if matches && !self.ignore_validators {
                    self.jwks_304 += 1;
                    return response
                        .status(StatusCode::NOT_MODIFIED)
                        .body(Full::default())
                        .unwrap();
                }
                self.jwks_200 += 1;
                let keys: Vec<_> = self
                    .kids
                    .iter()
                    .map(|kid| {
                        serde_json::json!({
                            "kty": "EC", "crv": "P-256", "kid": kid, "x": "AA", "y": "AA",
                        })
                    })
                    .collect();
                let body = serde_json::json!({ "keys": keys });
                response.body(Full::new(body.to_string().into())).unwrap()
            }
        }

        async fn start_pdp() -> (Arc<Mutex<Pdp>>, JwkCache) {
            CLIENT.get_or_init(reqwest::Client::new);
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let issuer = format!("http://{}", listener.local_addr().unwrap());
            let pdp = Arc::new(Mutex::new(Pdp {
                issuer: issuer.clone(),
                jwks_path: "/certs",
                kids: vec!["pdp"],
                etag: "\"v1\"",
                max_age: 60,
                ignore_validators: false,
                jwks_200: 0,
                jwks_304: 0,
            }));
            let state = pdp.clone();
            tokio::spawn(async move {
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let state = state.clone();
                    let service = service_fn(move |req| {
                        let response = state.lock().unwrap().handle(&req);
                        async move { Ok::<_, Infallible>(response) }
                    });
                    tokio::spawn(
                        hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service),
                    );
                }
            });
            let cache = JwkCache {
                pdp_issuer: issuer.clone(),
                pdp_url: issuer,
                pdp_oidc: Default::default(),
                pdp_jwks: Default::default(),
                popp_issuer: None,
                popp_entity: Default::default(),
                popp_jwks: Default::default(),
                refresh_interval: Duration::from_secs(300),
                max_lifetime: MAX_LIFETIME,
            };
            (pdp, cache)
        }

        async fn inject(pdp: &Mutex<Pdp>, cache: &JwkCache) {
            {
                let mut pdp = pdp.lock().unwrap();
                pdp.kids = vec!["pdp", "attacker"];
                pdp.max_age = TEN_YEARS;
                pdp.ignore_validators = true;
            }
            cache
                .get_jwk_pdp("attacker".into(), None)
                .await
                .expect("injected key");
            let mut pdp = pdp.lock().unwrap();
            pdp.kids = vec!["pdp"];
            pdp.max_age = 60;
            pdp.ignore_validators = false;
        }

        /// Let `max_lifetime` pass for the cached key set.
        async fn expire(cache: &JwkCache) {
            let mut jwks = cache.pdp_jwks.write().await;
            let meta = &mut jwks.as_mut().expect("store").meta;
            meta.installed_at = Some(
                Instant::now()
                    .checked_sub(MAX_LIFETIME)
                    .expect("monotonic clock older than MAX_LIFETIME"),
            );
        }

        #[tokio::test]
        async fn injected_key_set_is_replaced_after_max_lifetime() {
            let (pdp, cache) = start_pdp().await;
            cache.fetch_pdp().await.expect("initial fetch");
            assert!(cache.get_jwk_pdp("attacker".into(), None).await.is_err());

            inject(&pdp, &cache).await;
            let (ok, not_modified) = {
                let pdp = pdp.lock().unwrap();
                (pdp.jwks_200, pdp.jwks_304)
            };

            // within the lifetime the injected response's headers still rule:
            // the periodic refresh skips the fetch, a forced one gets a 304
            cache.fetch_pdp().await.expect("periodic refresh");
            assert!(cache.get_jwk_pdp("unknown".into(), None).await.is_err());
            assert!(cache.pdp_jwks.get_key("attacker").await.is_some());
            assert_eq!(pdp.lock().unwrap().jwks_200, ok);
            assert_eq!(pdp.lock().unwrap().jwks_304, not_modified + 1);

            expire(&cache).await;
            cache.fetch_pdp().await.expect("periodic refresh");
            assert!(cache.pdp_jwks.get_key("attacker").await.is_none());
            assert!(cache.pdp_jwks.get_key("pdp").await.is_some());
            assert_eq!(pdp.lock().unwrap().jwks_200, ok + 1);
            assert_eq!(pdp.lock().unwrap().jwks_304, not_modified + 1);
        }

        #[tokio::test]
        async fn revalidation_does_not_extend_max_lifetime() {
            let (pdp, cache) = start_pdp().await;
            cache.fetch_pdp().await.expect("initial fetch");
            inject(&pdp, &cache).await;
            expire(&cache).await;

            // would be answered 304 if the stored ETag were sent
            assert!(cache.get_jwk_pdp("unknown".into(), None).await.is_err());
            assert!(cache.pdp_jwks.get_key("attacker").await.is_none());
            assert_eq!(pdp.lock().unwrap().jwks_304, 0);
        }

        #[tokio::test]
        async fn changed_jwks_uri_drops_cached_keys() {
            let (pdp, cache) = start_pdp().await;
            cache.fetch_pdp().await.expect("initial fetch");
            assert!(cache.pdp_jwks.get_key("pdp").await.is_some());

            // same ETag at the new location: a conditional request gets a 304
            {
                let mut pdp = pdp.lock().unwrap();
                pdp.jwks_path = "/elsewhere";
                pdp.kids = vec!["other"];
            }
            cache.fetch_pdp().await.expect("refresh from new jwks_uri");
            assert!(cache.pdp_jwks.get_key("pdp").await.is_none());
            assert!(cache.pdp_jwks.get_key("other").await.is_some());
            assert_eq!(pdp.lock().unwrap().jwks_304, 0);
        }
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
            installed_at: Some(Instant::now()),
            fetched_at_epoch: 1744300000,
        }
    }

    const LIFETIME: Duration = Duration::from_hours(24);
    const GRACE: Duration = Duration::from_secs(60);

    // --- is_fresh ---

    #[test]
    fn fresh_when_within_max_age() {
        let meta = meta_with(None, None, Some(300));
        assert!(meta.is_fresh(LIFETIME));
    }

    #[test]
    fn stale_when_max_age_zero() {
        let meta = meta_with(None, None, Some(0));
        assert!(!meta.is_fresh(LIFETIME));
    }

    #[test]
    fn stale_when_no_max_age() {
        let meta = meta_with(Some("\"abc\""), None, None);
        assert!(!meta.is_fresh(LIFETIME));
    }

    #[test]
    fn stale_when_no_fetched_at() {
        let meta = HttpCacheMeta {
            max_age: Some(Duration::from_secs(300)),
            ..Default::default()
        };
        assert!(!meta.is_fresh(LIFETIME));
    }

    #[test]
    fn stale_when_default() {
        assert!(!HttpCacheMeta::default().is_fresh(LIFETIME));
    }

    // --- max lifetime ---

    const TEN_YEARS: u64 = 315_360_000;

    #[test]
    fn stale_past_max_lifetime_despite_max_age() {
        let meta = meta_with(None, None, Some(TEN_YEARS));
        assert!(meta.is_fresh(LIFETIME));
        assert!(!meta.is_fresh(Duration::ZERO));
    }

    #[test]
    fn revalidation_does_not_extend_lifetime() {
        let mut meta = meta_with(Some("\"abc\""), None, Some(TEN_YEARS));
        let installed_at = meta.installed_at;
        meta.merge_headers(&HeaderMap::new());
        assert_eq!(meta.installed_at, installed_at);
    }

    #[test]
    fn validators_withheld_past_max_lifetime() {
        let meta = meta_with(Some("\"abc\""), Some("Thu, 02 Apr 2026 13:10:18 GMT"), None);
        let v = meta.validators(LIFETIME);
        assert_eq!(v.etag, meta.etag);
        assert_eq!(v.last_modified, meta.last_modified);
        let v = meta.validators(Duration::ZERO);
        assert_eq!(v.etag, None);
        assert_eq!(v.last_modified, None);
    }

    #[test]
    fn untrustworthy_past_max_lifetime_despite_max_age() {
        let meta = meta_with(None, None, Some(TEN_YEARS));
        assert!(meta.trustworthy(GRACE, LIFETIME));
        assert!(!meta.trustworthy(Duration::ZERO, Duration::ZERO));
    }

    #[test]
    fn trustworthy_survives_max_age_overflow() {
        let meta = meta_with(None, None, Some(u64::MAX));
        assert!(meta.trustworthy(GRACE, LIFETIME));
    }

    // --- trustworthy ---

    #[test]
    fn trustworthy_within_max_age() {
        let meta = meta_with(None, None, Some(300));
        assert!(meta.trustworthy(GRACE, LIFETIME));
    }

    #[test]
    fn trustworthy_within_grace_when_no_max_age() {
        // Server didn't send Cache-Control: max_age defaults to 0, but grace
        // alone keeps the cache trustworthy briefly past last fetch.
        let meta = meta_with(Some("\"abc\""), None, None);
        assert!(meta.trustworthy(GRACE, LIFETIME));
    }

    #[test]
    fn trustworthy_within_grace_when_max_age_zero() {
        let meta = meta_with(None, None, Some(0));
        assert!(meta.trustworthy(GRACE, LIFETIME));
    }

    #[test]
    fn untrustworthy_when_no_fetched_at() {
        let meta = HttpCacheMeta {
            max_age: Some(Duration::from_secs(300)),
            ..Default::default()
        };
        assert!(!meta.trustworthy(GRACE, LIFETIME));
    }

    #[test]
    fn untrustworthy_with_zero_grace_and_zero_max_age() {
        // max_age=0 + grace=0 → window is 0, immediately stale
        let meta = meta_with(None, None, Some(0));
        assert!(!meta.trustworthy(Duration::ZERO, LIFETIME));
    }

    #[test]
    fn untrustworthy_when_default() {
        assert!(!HttpCacheMeta::default().trustworthy(GRACE, LIFETIME));
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
            installed_at: Some(Instant::now()),
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

    // --- internalize_jwks_uri ---

    const PUB: &str = "https://zeta.example/auth/realms/zeta-guard";
    const INT: &str = "http://authserver/auth/realms/zeta-guard";
    const CERTS: &str = "/protocol/openid-connect/certs";

    #[test]
    fn rewrites_public_jwks_uri_onto_internal_base() {
        assert_eq!(
            internalize_jwks_uri(&format!("{PUB}{CERTS}"), PUB, INT).as_deref(),
            Some(format!("{INT}{CERTS}").as_str())
        );
    }

    #[test]
    fn unchanged_when_fetch_base_equals_issuer() {
        let uri = format!("{PUB}{CERTS}");
        assert_eq!(
            internalize_jwks_uri(&uri, PUB, PUB).as_deref(),
            Some(uri.as_str())
        );
    }

    #[test]
    fn trailing_slashes_do_not_double_up() {
        assert_eq!(
            internalize_jwks_uri(
                &format!("{PUB}{CERTS}"),
                &format!("{PUB}/"),
                &format!("{INT}/")
            )
            .as_deref(),
            Some(format!("{INT}{CERTS}").as_str())
        );
    }

    #[test]
    fn issuer_itself_maps_to_bare_fetch_base() {
        assert_eq!(internalize_jwks_uri(PUB, PUB, INT).as_deref(), Some(INT));
    }

    #[test]
    fn none_when_jwks_uri_is_on_a_foreign_host() {
        assert_eq!(
            internalize_jwks_uri("https://elsewhere.example/certs", PUB, INT),
            None
        );
    }

    // --- ForwardedOrigin ---

    #[test]
    fn origin_keeps_scheme_and_host() {
        let o = ForwardedOrigin::from_issuer(PUB).expect("origin");
        assert_eq!(o.scheme, "https");
        assert_eq!(o.host, "zeta.example");
    }

    #[test]
    fn origin_keeps_explicit_port() {
        let o = ForwardedOrigin::from_issuer("http://zeta.example:18080/auth/realms/x")
            .expect("origin");
        assert_eq!(o.scheme, "http");
        assert_eq!(o.host, "zeta.example:18080");
    }

    #[test]
    fn origin_none_for_non_url() {
        assert_eq!(ForwardedOrigin::from_issuer("not a url"), None);
    }

    #[test]
    fn none_on_partial_path_segment_match() {
        // `…/zeta-guard` must not match `…/zeta-guard-other`
        assert_eq!(
            internalize_jwks_uri(&format!("{PUB}-other{CERTS}"), PUB, INT),
            None
        );
    }
}
