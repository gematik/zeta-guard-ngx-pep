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
use crate::ngx_http_pep_module;
use crate::{conf::LocationConfig, jwk_cache::jwk_cache, log_debug};
use anyhow::anyhow;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use futures::FutureExt;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::decode_header;
use jsonwebtoken::{Algorithm, TokenData};
use jsonwebtoken::{Validation, decode};
use ngx::async_::spawn;
use ngx::ffi::*;
use ngx::ngx_log_debug_http;
use ngx::{async_::Task, http::HTTPStatus};
use ngx::{core::Status, http::HttpModuleLocationConf};
use ngx::{http::Request, ngx_log_error};
use serde::Deserialize;
use std::cell::RefCell;
use std::ptr::{addr_of, addr_of_mut};
use std::sync::atomic::{AtomicPtr, Ordering};

use crate::{Module, jwk_cache::Jwk};

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
struct Claims {
    iss: String,
    sub: String,
    aud: serde_json::Value,
    exp: u64,
    iat: Option<u64>,
    nbf: Option<u64>,
    scope: Option<String>,
}

fn decoding_key_from_jwk(jwk: &Jwk) -> anyhow::Result<DecodingKey> {
    // Prefer n/e; fall back to x5c[0] if present.
    if jwk.kty == "RSA" {
        if let (Some(n), Some(e)) = (&jwk.n, &jwk.e) {
            return Ok(DecodingKey::from_rsa_components(n, e)?);
        }
        if let Some(chain) = &jwk.x5c
            && let Some(pem_der_b64) = chain.first()
        {
            // x5c is base64 DER; jsonwebtoken can take PEM, so wrap as PEM.
            let der = URL_SAFE_NO_PAD.decode(pem_der_b64)?;
            let pem = pem_rsa_from_der(&der);
            return Ok(DecodingKey::from_rsa_pem(pem.as_bytes())?);
        }
    }
    anyhow::bail!("unsupported JWK")
}

fn pem_rsa_from_der(der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut s = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(chunk).unwrap());
        s.push('\n');
    }
    s.push_str("-----END CERTIFICATE-----\n");
    s
}

async fn verify_token(config: &LocationConfig, token: &str) -> anyhow::Result<TokenData<Claims>> {
    log_debug!("pep: verify_token {config:?}");
    let header = decode_header(token)?;
    let kid = header.kid.ok_or_else(|| anyhow::anyhow!("no kid"))?;
    if header.alg != Algorithm::RS256 {
        anyhow::bail!("unsupported alg");
    }

    let jwk = jwk_cache().get_jwk(kid).await?;

    if jwk.alg.as_deref() != Some("RS256") {
        anyhow::bail!("jwk alg NI: {:?}", jwk.alg);
    }
    let key = decoding_key_from_jwk(&jwk)?;

    // validate
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[jwk_cache().issuer.clone()]);
    validation.required_spec_claims.insert("iss".to_string());
    if let Some(require_aud_any) = &config.require_aud_any {
        validation.set_audience(require_aud_any);
        validation.required_spec_claims.insert("aud".to_string());
    } else {
        validation.validate_aud = false;
    }
    validation.leeway = config.leeway.as_secs();
    validation.validate_nbf = true; // if present, but don't require nbf
    log_debug!("pep: validate {validation:?}");

    let data = decode::<Claims>(token, &key, &validation)?;
    if let Some(require_scope) = &config.require_scope
        && data
            .claims
            .scope
            .as_ref()
            .is_none_or(|scope| scope != require_scope)
    {
        anyhow::bail!(
            "scope mismatch; got={:?}, want={}",
            data.claims.scope,
            require_scope
        );
    }
    log_debug!("pep: valid, {data:?}");

    Ok(data)
}

async fn verify_authorization(request: &mut Request) -> anyhow::Result<Status> {
    let config = Module::location_conf(request).expect("location config is none");

    let token = request
        .headers_in_iterator()
        .find(|(k, _)| {
            k.to_str()
                .is_ok_and(|s| s.eq_ignore_ascii_case("authorization"))
        })
        .and_then(|(_, v)| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .and_then(|(scheme, token)| match scheme {
            "Bearer" => Some(token),
            _ => None,
        })
        .ok_or_else(|| anyhow!("no token"))?;

    let _claims = verify_token(config, token).await?;

    Ok(Status::NGX_OK)
}

struct RequestCtx(RefCell<Option<Task<anyhow::Result<Status>>>>);

pub fn handler(request: &mut Request) -> Status {
    let config = Module::location_conf(request).expect("location config is none");

    match config.enable {
        true => {
            // Check if we were called *again*
            if let Some(RequestCtx(task)) =
                unsafe { request.get_module_ctx::<RequestCtx>(&*addr_of!(ngx_http_pep_module)) }
            {
                let task = task.take().expect("Task");
                // task should be finished when re-entering the handler
                if !task.is_finished() {
                    ngx_log_error!(NGX_LOG_ERR, request.log(), "Task not finished");
                    return HTTPStatus::INTERNAL_SERVER_ERROR.into();
                }
                return match task.now_or_never().expect("Task result") {
                    Ok(status) => status,
                    Err(err) => {
                        ngx_log_debug_http!(request, "pep: unauthorized — {err}");
                        HTTPStatus::UNAUTHORIZED.into()
                    }
                };
            }

            ngx_log_debug_http!(request, "pep: enter");

            // from https://github.com/nginx/ngx-rust/blob/main/examples/async.rs:
            // „Request is no longer needed and can be converted to something movable to the async block”
            let r_ptr = AtomicPtr::new(request.into());
            let task = spawn(async move {
                let r_ptr = r_ptr.load(Ordering::Relaxed);
                let request = unsafe { ngx::http::Request::from_ngx_http_request(r_ptr) };

                let result = verify_authorization(request).await;

                let c: *mut ngx_connection_t = request.connection().cast();
                // trigger „write” event so nginx calls our handler again to finalize the request
                // (as per async.rs example above)
                unsafe { ngx_post_event((*c).write, addr_of_mut!(ngx_posted_events)) };
                result
            });

            let ctx = request
                .pool()
                .allocate(RequestCtx(RefCell::new(Some(task))));
            if ctx.is_null() {
                return Status::NGX_ERROR;
            }
            request.set_module_ctx(ctx.cast(), unsafe { &*addr_of!(ngx_http_pep_module) });

            Status::NGX_AGAIN
        }
        false => Status::NGX_DECLINED,
    }
}
