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

use ambassador::Delegate;
use anyhow::Ok;
use rstest::fixture;

use crate::conf::{LocationConfig, MainConfig};
use crate::jwk_cache::reset_jwk_cache_mock;
use crate::request_ops::*;
use crate::request_ops::{ConfigOps, RequestOps};

#[derive(Delegate)]
#[delegate(RequestOps, target = "request")]
pub struct RequestMock {
    pub request: MockRequestOps,
    pub mcfg: MainConfig,
    pub lcfg: LocationConfig,
}

impl ConfigOps for RequestMock {
    fn main_config<'a>(&'a self) -> anyhow::Result<&'a MainConfig> {
        Ok(&self.mcfg)
    }

    fn location_config<'a>(&'a self) -> anyhow::Result<&'a LocationConfig> {
        Ok(&self.lcfg)
    }
}

impl Default for RequestMock {
    fn default() -> Self {
        let request = MockRequestOps::new();

        let mcfg = MainConfig {
            pdp_issuer: Some("issuer".to_string()),
            ..Default::default()
        };
        let lcfg = LocationConfig {
            pep: Some(true),
            ..Default::default()
        };

        Self {
            request,
            mcfg,
            lcfg,
        }
    }
}

#[fixture]
pub async fn request_mock() -> RequestMock {
    reset_jwk_cache_mock().await;
    let mut mock = RequestMock::default();

    mock.request
        .expect_ensure_header_out()
        .returning(|_name, _value| Ok(()));

    mock
}
