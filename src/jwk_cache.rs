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
use crate::log_debug;
use std::sync::OnceLock;
use std::time::Duration;

use crate::conf::MainConfig;
use async_compat::Compat;
use ngx::async_::{sleep, spawn};
use reqwest::{Client, ClientBuilder, redirect::Policy};
use scc::HashMap;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct OidcConfig {
    pub jwks_uri: String,
    pub issuer: String,
}

#[derive(Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

#[derive(Deserialize, Clone)]
pub struct Jwk {
    pub kid: Option<String>,
    pub kty: String,
    pub n: Option<String>,
    pub e: Option<String>,
    pub alg: Option<String>,
    pub x5c: Option<Vec<String>>,
}

pub static JWK_CACHE: OnceLock<JwkCache> = OnceLock::new();

pub struct JwkCache {
    pub issuer: String,
    jwks: HashMap<String, Jwk>,
    refresh_interval: Duration,
    client: Client,
}

impl JwkCache {
    pub fn init(conf: &MainConfig) {
        let cache = JWK_CACHE.get_or_init(|| JwkCache {
            issuer: conf.issuer.as_ref().expect("issuer").clone(),
            jwks: HashMap::new(),
            refresh_interval: conf.jwks_refresh_interval,
            client: ClientBuilder::new()
                .redirect(Policy::none())
                .http2_adaptive_window(true)
                .pool_idle_timeout(conf.http_client_idle_timeout)
                .pool_max_idle_per_host(conf.http_client_max_idle_per_host)
                .tcp_keepalive(conf.http_client_tcp_keepalive)
                .connect_timeout(conf.http_client_connect_timeout)
                .timeout(conf.http_client_timeout)
                .use_rustls_tls()
                .danger_accept_invalid_certs(conf.http_client_accept_invalid_certs)
                .build()
                .expect("reqwest client"),
        });
        spawn(Compat::new(cache.cache_worker())).detach();
    }

    async fn cache_worker(&self) {
        loop {
            log_debug!("pep: jwk cache refresh…");
            match self.fetch().await {
                Ok(_) => {}
                Err(e) => {
                    log_debug!("during jwk cache refresh: {e}");
                }
            };
            sleep(self.refresh_interval).await;
        }
    }

    async fn fetch(&self) -> anyhow::Result<()> {
        let well_known = format!(
            "{}/.well-known/openid-configuration",
            self.issuer.trim_end_matches('/')
        );

        let cfg: OidcConfig = self.client.get(well_known).send().await?.json().await?;
        if cfg.issuer != self.issuer {
            anyhow::bail!("issuer mismatch");
        }

        let jwks: JwkSet = self.client.get(cfg.jwks_uri).send().await?.json().await?;
        for jwk in jwks.keys {
            let kid = jwk.kid.as_ref().expect("kid").clone();
            log_debug!("pep: cache add kid {kid}");
            self.jwks.upsert_async(kid, jwk).await;
        }

        Ok(())
    }

    pub async fn get_jwk(&self, kid: String) -> anyhow::Result<Jwk> {
        let mut jwk = self.jwks.get_async(&kid).await.map(|x| x.clone());
        if jwk.is_none() {
            log_debug!("pep: {kid} not found, refresh and retry…");
            self.fetch().await?;
            jwk = self.jwks.get_async(&kid).await.map(|x| x.clone());
        }
        jwk.ok_or_else(|| anyhow::anyhow!("pep: {kid} not found"))
    }
}

pub fn jwk_cache() -> &'static JwkCache {
    JWK_CACHE.get().expect("JwkCache not initialized")
}
