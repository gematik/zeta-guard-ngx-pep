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

#[cfg_attr(test, automock, allow(unused))]
pub trait JwkCacheOps {
    async fn fetch_pdp(&self) -> anyhow::Result<()>;
    async fn get_jwk_pdp(&self, kid: String) -> anyhow::Result<Jwk>;
    async fn fetch_popp(&self) -> anyhow::Result<()>;
    async fn get_jwk_popp(&self, kid: String) -> anyhow::Result<Jwk>;
}

#[cfg_attr(test, allow(unused))]
mod prod {
    use std::collections::HashMap;

    use anyhow::{Context, anyhow, bail};
    use base64ct::Base64;
    use jsonwebtoken::{
        Algorithm, DecodingKey, TokenData, Validation, get_current_timestamp, jwk::JwkSet,
    };
    use tokio::{sync::RwLock, time::Instant};

    use crate::{format_iso8601, spawn_compat};

    use {
        super::JwkCacheOps,
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

    pub static JWK_CACHE: OnceLock<JwkCache> = OnceLock::new();

    #[derive(Debug, Default)]
    struct JwkStore {
        keys: HashMap<String, Jwk>, // put into map for faster access
        #[allow(unused)]
        seen: u64, // when was the JwkSet last seen (epoch s)
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
        pdp_jwks: RwLock<Option<JwkStore>>,
        popp_issuer: Option<String>,
        popp_jwks: RwLock<Option<JwkStore>>,
        refresh_interval: Duration,
    }

    impl JwkCache {
        pub fn init(conf: &MainConfig) {
            let cache = JWK_CACHE.get_or_init(|| JwkCache {
                pdp_issuer: conf.pdp_issuer.as_ref().expect("issuer").clone(),
                pdp_jwks: Default::default(),
                popp_issuer: conf.popp_issuer.clone(),
                popp_jwks: Default::default(),
                refresh_interval: conf.jwks_refresh_interval,
            });
            spawn_compat(cache.cache_worker()).detach();
        }

        async fn cache_worker(&'static self) {
            loop {
                let start = Instant::now();
                match self.fetch_pdp().await {
                    Ok(_) => {}
                    Err(e) => {
                        log_debug!("jwk_cache[pdp]: during refresh: {e}");
                    }
                };
                match self.fetch_popp().await {
                    Ok(_) => {}
                    Err(e) => {
                        log_debug!("jwk_cache[popp]: during refresh: {e}");
                    }
                };
                let elapsed = Instant::now().duration_since(start);
                if elapsed < self.refresh_interval {
                    sleep(self.refresh_interval - elapsed).await;
                }
            }
        }
    }

    impl JwkCacheOps for JwkCache {
        async fn fetch_pdp(&self) -> anyhow::Result<()> {
            tokio::time::sleep(Duration::from_millis(700)).await;
            let well_known = format!(
                "{}/.well-known/openid-configuration",
                self.pdp_issuer.trim_end_matches('/')
            );

            let client = CLIENT.get().expect("client");

            let cfg: OidcConfig = client.get(well_known).send().await?.json().await?;
            if cfg.issuer != self.pdp_issuer {
                bail!("pdp: issuer mismatch");
            }

            let jwk_set: JwkSet = client.get(cfg.jwks_uri).send().await?.json().await?;
            let now = get_current_timestamp();
            let mut jwks = JwkStore {
                seen: now,
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
            let now_ts = format_iso8601(Duration::from_secs(now));
            log_debug!("jwk_cache[pdp]: refresh @ {now_ts}, kids={kids:?}");
            self.pdp_jwks.write().await.replace(jwks);

            Ok(())
        }

        async fn get_jwk_pdp(&self, kid: String) -> anyhow::Result<Jwk> {
            let mut jwk = self.pdp_jwks.get_key(&kid).await;
            if jwk.is_none() {
                log_debug!(
                    "jwk_cache[pdp]: {kid} not found (have {:?}), refresh and retry…",
                    self.pdp_jwks.read().await
                );
                self.fetch_pdp().await?;
                jwk = self.pdp_jwks.get_key(&kid).await;
            }
            jwk.ok_or_else(|| anyhow!("pdp: {kid} not found"))
        }

        async fn fetch_popp(&self) -> anyhow::Result<()> {
            // config for now; once federation master provides services list, use it to discover PoPP
            let issuer = self.popp_issuer.clone();
            match issuer {
                Some(issuer) => {
                    let now = get_current_timestamp();
                    let client = CLIENT.get().expect("client");
                    let issuer = issuer.trim_end_matches('/');

                    let mut validation = Validation::new(Algorithm::ES256);
                    validation.validate_aud = false; // disabled until we know how this behaves in production
                    validation.validate_nbf = true; // validate if present
                    validation.set_required_spec_claims(&["exp"]);

                    // fetch PoPP entity statement, for now we validate self-signing and trust HTTPS
                    // otherwise; should fetch this via federation master and verify against its
                    // provisioned key
                    let entity_url = format!("{}/.well-known/openid-federation", issuer);
                    let entity_bytes = client.get(entity_url).send().await?.bytes().await?;
                    if !is_base64url_char(entity_bytes[0]) {
                        bail!(
                            "Bad PoPP entity statement: {}",
                            Base64::encode_string(&entity_bytes)
                        );
                    }
                    let entity_statement_insecure: TokenData<EntityStatement> =
                        jsonwebtoken::dangerous::insecure_decode(&entity_bytes)
                            .context("fetch PoPP entity statement")?;
                    let entity_kid = entity_statement_insecure
                        .header
                        .kid
                        .ok_or_else(|| anyhow!("missing kid header in entity statement"))?;
                    let entity_key = entity_statement_insecure
                        .claims
                        .jwks
                        .find(&entity_kid)
                        .and_then(|key| DecodingKey::from_jwk(key).ok())
                        .ok_or_else(|| anyhow!("missing or invalid key '{}'", entity_kid))?;
                    let entity_statement: EntityStatement =
                        jsonwebtoken::decode(entity_bytes, &entity_key, &validation)
                            .context("fetch PoPP signed key set")?
                            .claims;

                    // fetch PoPP signed JWKS; consider relative URLs based on issuer URL
                    let mut jwks_url = entity_statement.metadata.oauth_resource.signed_jwks_uri;
                    if !jwks_url.to_ascii_lowercase().starts_with("http") {
                        if jwks_url.starts_with('/') {
                            jwks_url = format!("{issuer}{jwks_url}");
                        } else {
                            jwks_url = format!("{issuer}/{jwks_url}");
                        }
                    }
                    let jwks_bytes = client.get(jwks_url).send().await?.bytes().await?;
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
                    let jwks_key = entity_statement
                        .jwks
                        .find(&jwks_kid)
                        .and_then(|key| DecodingKey::from_jwk(key).ok())
                        .ok_or_else(|| anyhow!("missing or invalid key '{}'", jwks_kid))?;
                    let signed_jwks: SignedJwkSet =
                        jsonwebtoken::decode(jwks_bytes, &jwks_key, &validation)
                            .context("fetch PoPP signed key set")?
                            .claims;

                    let mut jwks = JwkStore {
                        seen: now,
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

                    let now_ts = format_iso8601(Duration::from_secs(now));
                    log_debug!("jwk_cache[popp]: refresh @ {now_ts}, kids={kids:?}");
                    self.popp_jwks.write().await.replace(jwks);
                }
                None => {
                    log_debug!("jwk_cache[popp]: no pep_popp_issuer configured, skipping refresh");
                }
            };
            Ok(())
        }

        async fn get_jwk_popp(&self, kid: String) -> anyhow::Result<Jwk> {
            if self.popp_issuer.is_none() {
                bail!("popp: no pep_popp_issuer configured");
            }

            let mut jwk = self.popp_jwks.get_key(&kid).await;
            if jwk.is_none() {
                log_debug!(
                    "jwk_cache[popp]: {kid} not found (have {:?}), refresh and retry…",
                    self.popp_jwks.read().await
                );
                self.fetch_popp().await?;
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

        async fn get_jwk_pdp(&self, kid: String) -> anyhow::Result<Jwk> {
            let guard = self.read().await;
            guard.get_jwk_pdp(kid).await
        }

        async fn fetch_popp(&self) -> anyhow::Result<()> {
            let guard = self.read().await;
            guard.fetch_popp().await
        }

        async fn get_jwk_popp(&self, kid: String) -> anyhow::Result<Jwk> {
            let guard = self.read().await;
            guard.get_jwk_popp(kid).await
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
