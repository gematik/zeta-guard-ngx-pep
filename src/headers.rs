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

use anyhow::Result;
use base64ct::{Base64Url, Encoding};
use serde::Serialize;
use serde_json::Value;
use tracing::debug;

use crate::request_ops::RequestOps;
use crate::typify::{ClientData, ZetaUserInfo};
use crate::{ZETA_VAR_CLIENT_DATA, ZETA_VAR_FORWARDED, ZETA_VAR_POPP_TOKEN, ZETA_VAR_USER_INFO};

fn to_base64_encoded_json<T: Serialize>(value: &T) -> Result<String> {
    let json = serde_json::to_string_pretty(&value)?;
    Ok(Base64Url::encode_string(json.as_bytes()))
}

pub fn ensure_api_version_header_out<R: RequestOps>(request: &mut R) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    request.ensure_header_out("ZETA-API-Version", version)
}

pub fn ensure_user_info_upstream_header<R: RequestOps>(
    request: &mut R,
    user_info: &ZetaUserInfo,
) -> Result<()> {
    request.set_zeta_upstream_header(ZETA_VAR_USER_INFO, &to_base64_encoded_json(user_info)?);
    Ok(())
}

pub fn ensure_popp_token_upstream_header<R: RequestOps>(
    request: &mut R,
    popp_token_payload: Value,
) -> Result<()> {
    request.set_zeta_upstream_header(
        ZETA_VAR_POPP_TOKEN,
        &to_base64_encoded_json(&popp_token_payload)?,
    );
    Ok(())
}

pub fn ensure_client_data_upstream_header<R: RequestOps>(
    request: &mut R,
    client_data: ClientData,
) -> Result<()> {
    request.set_zeta_upstream_header(ZETA_VAR_CLIENT_DATA, &to_base64_encoded_json(&client_data)?);
    Ok(())
}

/// `host` and `for` are emitted as RFC 7239 quoted-strings: an authority always carries a `:port`
/// (and an IPv6 `for` literal carries `:`), and `:` is not a valid `token` character, so RFC 7239
/// §4 mandates the quoted-string form for those values. `by` (the obfuscated node identifier
/// `_zetapep`, RFC 7239 §6.3) and `proto` are plain `token`s and therefore stay unquoted.
pub fn pep_forwarded_element(scheme: &str, authority: &str, client_ip: Option<&str>) -> String {
    let mut element = String::from("by=_zetapep");
    if let Some(ip) = client_ip {
        element.push_str(&format!(";{}", forwarded_for_value(ip)));
    }
    element.push_str(&format!(";host=\"{authority}\";proto={scheme}"));
    element
}

/// RFC 7239 `for=` directive for a client IP, emitted as a quoted-string: an
/// IPv6 literal contains `:` (not a valid `token` char) and is bracketed inside
/// the quotes per RFC 7239 §4. Shared by `pep_forwarded_element` (the upstream
/// loopback) and the standalone `Forwarded` header on JWKS fetches.
pub fn forwarded_for_value(ip: &str) -> String {
    let node = if ip.contains(':') {
        format!("[{ip}]")
    } else {
        ip.to_string()
    };
    format!("for=\"{node}\"")
}

/// A_28439: update the `Forwarded` header (RFC 7239) of the upstream request by appending this
/// PEP's own forwarding element while preserving any element(s) already present.
pub fn ensure_forwarded_upstream_header<R: RequestOps>(request: &mut R) -> Result<()> {
    // Collect everything we read (immutable borrows) into owned values before mutating.
    let (scheme, host, port) = request.eigenurl_parts()?;
    let authority = match port {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let scheme = scheme.to_string();
    let client_ip = request.get_client_ip().map(str::to_string);
    let existing = request.get_header_in("forwarded").map(str::to_string);

    let element = pep_forwarded_element(&scheme, &authority, client_ip.as_deref());

    let value = match existing {
        Some(prev) if !prev.trim().is_empty() => format!("{prev}, {element}"),
        _ => element,
    };

    debug!(zeta_forwarded = value, "set $zeta_forwarded=\"{value}\"");
    // Replace any incoming Forwarded with the updated chain.
    request.set_zeta_upstream_header(ZETA_VAR_FORWARDED, &value);
    Ok(())
}
