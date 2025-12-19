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

use anyhow::Result;
use base64ct::{Base64Url, Encoding};
use serde::Serialize;
use serde_json::Value;

use crate::request_ops::RequestOps;
use crate::typify::{ClientInstance, UserInfo};

fn to_base64_encoded_json<T: Serialize>(value: &T) -> Result<String> {
    let json = serde_json::to_string_pretty(&value)?;
    Ok(Base64Url::encode_string(json.as_bytes()))
}

pub fn ensure_api_version_header_out<R: RequestOps>(request: &mut R) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    request.ensure_header_out("ZETA-API-Version", version)
}

pub fn ensure_user_info_header_in<R: RequestOps>(
    request: &mut R,
    user_info: UserInfo,
) -> Result<()> {
    request.ensure_header_in("ZETA-User-Info", &to_base64_encoded_json(&user_info)?)
}

pub fn ensure_popp_token_header_in<R: RequestOps>(
    request: &mut R,
    popp_token_payload: Value,
) -> Result<()> {
    request.ensure_header_in(
        "ZETA-PoPP-Token-Content",
        &to_base64_encoded_json(&popp_token_payload)?,
    )
}

pub fn ensure_client_data_header_in<R: RequestOps>(
    request: &mut R,
    client_instance: ClientInstance,
) -> Result<()> {
    request.ensure_header_in(
        "ZETA-Client-Data",
        &to_base64_encoded_json(&client_instance)?,
    )
}
