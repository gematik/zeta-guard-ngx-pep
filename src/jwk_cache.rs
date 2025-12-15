/*-
 * #%L
 * ngx_pep
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH
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

#[cfg_attr(test, automock)]
pub trait JwkCacheOps {
    async fn fetch_pdp(&self) -> anyhow::Result<()>;
    async fn get_jwk_pdp(&self, kid: String) -> anyhow::Result<Jwk>;
    async fn fetch_popp(&self) -> anyhow::Result<()>;
    async fn get_jwk_popp(&self, kid: String) -> anyhow::Result<Jwk>;
}

#[cfg(not(test))]
mod prod {
    use anyhow::Context;
    use http::Uri;
    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::jws::{Jws, decode};
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode_header};

    use {
        super::JwkCacheOps,
        crate::{CLIENT, conf::MainConfig, log_debug},
        async_compat::Compat,
        jsonwebtoken::jwk::Jwk,
        ngx::async_::sleep,
        scc::HashMap,
        serde::Deserialize,
        std::sync::OnceLock,
        std::time::Duration,
    };

    #[derive(Deserialize)]
    pub struct OidcConfig {
        pub jwks_uri: String,
        pub issuer: String,
    }

    pub static JWK_CACHE: OnceLock<JwkCache> = OnceLock::new();

    pub struct JwkCache {
        pdp_issuer: String,
        pdp_jwks: HashMap<String, Jwk>,
        popp_issuer: Option<String>,
        popp_jwks: HashMap<String, Jwk>,
        refresh_interval: Duration,
    }

    impl JwkCache {
        pub fn init(conf: &MainConfig) {
            use ngx_tickle::spawn;

            let cache = JWK_CACHE.get_or_init(|| JwkCache {
                pdp_issuer: conf.pdp_issuer.as_ref().expect("issuer").clone(),
                pdp_jwks: HashMap::new(),
                popp_issuer: conf.popp_issuer.clone(),
                popp_jwks: HashMap::new(),
                refresh_interval: conf.jwks_refresh_interval,
            });
            spawn(Compat::new(cache.cache_worker())).detach();
        }

        async fn cache_worker(&'static self) {
            loop {
                log_debug!("pep: jwk cache refresh…");
                match self.fetch_pdp().await {
                    Ok(_) => {}
                    Err(e) => {
                        log_debug!("during jwk cache refresh (pdp): {e}");
                    }
                };
                match self.fetch_popp().await {
                    Ok(_) => {}
                    Err(e) => {
                        log_debug!("during jwk cache refresh (popp): {e}");
                    }
                };
                sleep(self.refresh_interval).await;
            }
        }
    }

    impl JwkCacheOps for JwkCache {
        async fn fetch_pdp(&self) -> anyhow::Result<()> {
            let well_known = format!(
                "{}/.well-known/openid-configuration",
                self.pdp_issuer.trim_end_matches('/')
            );

            let client = CLIENT.get().expect("client");

            let cfg: OidcConfig = client.get(well_known).send().await?.json().await?;
            if cfg.issuer != self.pdp_issuer {
                anyhow::bail!("issuer mismatch (pdp)");
            }

            let jwks: JwkSet = client.get(cfg.jwks_uri).send().await?.json().await?;
            for jwk in jwks.keys {
                let kid = jwk.common.key_id.as_ref().expect("kid").clone();
                log_debug!("pep: cache add kid {kid} (pdp)");
                self.pdp_jwks.upsert_async(kid, jwk).await;
            }

            Ok(())
        }

        async fn get_jwk_pdp(&self, kid: String) -> anyhow::Result<Jwk> {
            let mut jwk = self.pdp_jwks.get_async(&kid).await.map(|x| x.clone());
            if jwk.is_none() {
                log_debug!("pep: {kid} not found (pdp), refresh and retry…");
                self.fetch_pdp().await?;
                jwk = self.pdp_jwks.get_async(&kid).await.map(|x| x.clone());
            }
            jwk.ok_or_else(|| anyhow::anyhow!("pep: {kid} not found (pdp)"))
        }

        async fn fetch_popp(&self) -> anyhow::Result<()> {
            let issuer = self
                .popp_issuer
                .clone()
                .context("no pep_popp_issuer configured")?;

            let well_known = format!("{}/jwks.json", issuer.trim_end_matches('/'));

            let client = CLIENT.get().expect("client");

            let jwks: JwkSet = client.get(well_known).send().await?.json().await?;

            for jwk in jwks.keys {
                let kid = jwk.common.key_id.as_ref().expect("kid").clone();
                log_debug!("pep: cache add kid {kid} (popp)");
                self.popp_jwks.upsert_async(kid, jwk).await;
            }

            Ok(())
        }

        async fn get_jwk_popp(&self, kid: String) -> anyhow::Result<Jwk> {
            let mut jwk = self.popp_jwks.get_async(&kid).await.map(|x| x.clone());
            if jwk.is_none() {
                log_debug!("pep: {kid} not found (popp), refresh and retry…");
                self.fetch_popp().await?;
                jwk = self.popp_jwks.get_async(&kid).await.map(|x| x.clone());
            }
            jwk.ok_or_else(|| anyhow::anyhow!("pep: {kid} not found (popp)"))
        }
    }

    pub fn jwk_cache() -> &'static impl JwkCacheOps {
        JWK_CACHE.get().expect("JwkCache not initialized")
    }
}
#[cfg(not(test))]
pub use prod::*;

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
        f(&mut *g)
    }

    pub async fn reset_jwk_cache_mock() {
        *JWK_CACHE_MOCK.write().await = MockJwkCacheOps::new();
    }

    pub fn jwk_cache() -> &'static impl JwkCacheOps {
        &*JWK_CACHE_MOCK
    }
}
#[cfg(test)]
pub use mock::*;
