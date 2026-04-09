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

use crate::error::{ZetaError, ZetaResult};
use crate::headers::{
    ensure_api_version_header_out, ensure_client_data_header_in, ensure_popp_token_header_in,
    ensure_user_info_header_in,
};
use crate::jwk_cache::JwkCacheOps;
use crate::request_ops::{ConfigOps, RequestOps, normalized_uri};
use crate::typify::{
    AccessTokenPayload, AccessTokenPayloadAud, AccessTokenPayloadPlatform, ClientData,
    ClientDataPlatform, DPoPProofJwtPayload, ZetaUserInfo,
};
use crate::{ModuleCtx, spawn_compat};
use crate::{
    conf::{LocationConfig, MainConfig},
    jwk_cache::jwk_cache,
    log_debug,
};
use anyhow::{Context, anyhow, bail};
use base64ct::{Base64UrlUnpadded, Encoding};
use futures::FutureExt;
use http::Uri;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::{KeyAlgorithm, ThumbprintHash};
use jsonwebtoken::{Algorithm, TokenData};
use jsonwebtoken::{Validation, decode};
use jsonwebtoken::{decode_header, get_current_timestamp};
use ngx::ffi::*;
use ngx::ngx_log_error;
use ngx::{
    core::Status,
    http::{HTTPStatus, HttpModuleLocationConf, Request},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::ptr::addr_of_mut;
use std::sync::atomic::{AtomicPtr, Ordering};

use crate::Module;

async fn verify_access_token(
    main_config: &MainConfig,
    location_config: &LocationConfig,
    token: &str,
    now: u64,
) -> ZetaResult<TokenData<AccessTokenPayload>> {
    let header = decode_header(token).context("while decoding authorization token header")?;
    let kid = header.kid.ok_or_else(|| anyhow!("no kid"))?;
    if header.alg != Algorithm::ES256 {
        return Err(ZetaError::AccessToken(anyhow!(
            "unsupported token alg {:?}",
            header.alg
        )));
    }

    let jwk = jwk_cache().get_jwk_pdp(kid).await?;

    if jwk.common.key_algorithm != Some(KeyAlgorithm::ES256) {
        return Err(ZetaError::AccessToken(anyhow!(
            "unsupported jwk alg: {:?}",
            jwk.common.key_algorithm
        )));
    }
    let key = DecodingKey::from_jwk(&jwk).context("while constructing DecodingKey from jwk")?;

    // validate
    let mut validation = Validation::new(Algorithm::ES256);
    // we will validate aud ourselves below
    validation.validate_aud = false;
    validation.set_issuer(&[main_config.pdp_issuer.clone().expect("issuer")]);
    validation.required_spec_claims.insert("iss".to_string());

    validation.leeway = location_config.leeway().as_secs();
    validation.validate_nbf = true; // if present, but don't require nbf
    log_debug!("at: {validation:?}");

    // NOTE: can't provide or get the timestamp used by jsonwebtoken, but we need to validate
    // iat ourselves. Technically, if both nbf and iat are provided and the validation happens
    // accross the boundary unix epoch second, iat might validate but nbf would not,
    // because jsonwebtoken produces another timestamp after this.
    let payload = decode::<AccessTokenPayload>(token, &key, &validation)
        .map_err(|e| ZetaError::AccessTokenInvalid(e.into()))?;

    let now: i64 = now.try_into().expect("now");
    let valid_since = now - payload.claims.iat;
    let leeway: i64 = location_config
        .leeway()
        .as_secs()
        .try_into()
        .context("parsing leeway")?;
    if valid_since + leeway < 0 {
        return Err(ZetaError::AccessTokenInvalid(anyhow!(
            "iat invalid; valid_since: want >= 0, got {}, iat = {}, leeway = {}",
            valid_since + leeway,
            payload.claims.iat,
            leeway
        )));
    }

    // NOTE: not using validation.set_audience, as we want to validate that *all* required
    // audiences are present on the token.
    let auds: HashSet<_> = HashSet::from_iter(match payload.claims.aud.clone() {
        AccessTokenPayloadAud::Array(items) => items,
        AccessTokenPayloadAud::String(item) => vec![item],
    });

    if let Some(required_auds) = location_config.aud.clone() {
        let missing_auds: Vec<_> = required_auds
            .difference(&auds)
            .map(|s| s.as_str())
            .collect();
        if !missing_auds.is_empty() {
            return Err(ZetaError::AccessTokenInvalid(anyhow!(
                "missing audiences: want {}, got {:#?}",
                missing_auds.join(","),
                auds,
            )));
        }
    }

    let scopes: HashSet<String> = HashSet::from_iter(
        payload
            .claims
            .scope
            .clone()
            .unwrap_or("".to_string())
            .split(" ")
            .map(|x| x.to_string()),
    );
    if let Some(required_scopes) = location_config.scope.clone() {
        let missing_scopes: Vec<_> = required_scopes
            .difference(&scopes)
            .map(|s| s.as_str())
            .collect();
        if !missing_scopes.is_empty() {
            return Err(ZetaError::AccessTokenInvalid(anyhow!(
                "missing scopes: {}",
                missing_scopes.join(",")
            )));
        }
    }

    Ok(payload)
}

async fn verify_popp(
    location_config: &LocationConfig,
    popp: &str,
    now: u64,
) -> anyhow::Result<TokenData<Value>> {
    let header = decode_header(popp)?;

    match &header.typ {
        Some(typ) => {
            if typ != "vnd.telematik.popp+jwt" {
                bail!("invalid typ {typ}");
            }
        }
        None => bail!("no typ"),
    };

    if header.alg != Algorithm::ES256 {
        anyhow::bail!("unsupported token alg {:?}", header.alg);
    }
    let kid = header.kid.ok_or_else(|| anyhow!("no kid"))?;

    let jwk = jwk_cache().get_jwk_popp(kid).await?;

    let mut validation = Validation::new(Algorithm::ES256);
    validation.required_spec_claims.remove("exp");
    let key = DecodingKey::from_jwk(&jwk)?;

    // TODO: Fix schema and use PoPpTokenPayload instead of Value
    let token_data: TokenData<Value> = decode(popp, &key, &validation)?;

    let iat: u64 = token_data.claims["iat"]
        .as_u64()
        .context("while parsing iat")?;
    let iat: i64 = iat.try_into().context("iat u64->i64 overflow")?;
    let now: i64 = now.try_into()?;
    let valid_since = now - iat;
    let leeway: i64 = location_config.leeway().as_secs().try_into()?;
    if valid_since + leeway < 0 {
        anyhow::bail!(
            "iat invalid; valid_since: want >= 0, got {}, iat = {}, leeway = {}",
            valid_since + leeway,
            iat,
            leeway
        );
    }
    let ppop_validity: i64 = location_config.ppop_validity().as_secs().try_into()?;
    let valid_until = iat + ppop_validity + leeway;
    if valid_until < now {
        anyhow::bail!(
            "not longer valid: want {} + {} + {} = {} < {}",
            iat,
            ppop_validity,
            leeway,
            valid_until,
            now
        );
    }

    Ok(token_data)
}

async fn verify_dpop(
    location_config: &LocationConfig,
    access_token_claims: &AccessTokenPayload,
    ath: &Vec<u8>,
    dpop: &str,
    now: u64,
    http_method: &str,
    request_uri: Uri,
) -> anyhow::Result<()> {
    let header = decode_header(dpop)?;

    match &header.typ {
        Some(typ) => {
            if typ != "dpop+jwt" {
                bail!("invalid typ {typ}");
            }
        }
        None => bail!("no typ"),
    };

    if header.alg != Algorithm::ES256 {
        anyhow::bail!("unsupported token alg {:?}", header.alg);
    }
    let jwk = header.jwk.ok_or_else(|| anyhow!("no jwk"))?;

    if jwk.common.key_algorithm != Some(KeyAlgorithm::ES256) {
        anyhow::bail!("unsupported jwk alg: {:?}", jwk.common.key_algorithm);
    }

    let thumbprint = jwk.thumbprint(ThumbprintHash::SHA256);
    let cnf = access_token_claims.cnf.clone();

    if cnf.jkt != thumbprint {
        bail!(
            "invalid thumbprint; cnf.jkt={}, dpop={}",
            cnf.jkt,
            thumbprint,
        );
    }
    let key = DecodingKey::from_jwk(&jwk)?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.required_spec_claims.remove("exp");
    let payload = decode::<DPoPProofJwtPayload>(&dpop, &key, &validation)?;

    let claimed_ath = Base64UrlUnpadded::decode_vec(
        payload
            .claims
            .ath
            .as_ref()
            .ok_or_else(|| anyhow!("missing ath claim"))?,
    )?;

    if ath != &claimed_ath {
        bail!(
            "invalid ath; access_token={}, ath={}",
            hex::encode(ath),
            hex::encode(claimed_ath)
        );
    }

    let now: i64 = now.try_into()?;
    let valid_since = now - payload.claims.iat;
    let leeway: i64 = location_config.leeway().as_secs().try_into()?;
    if valid_since + leeway < 0 {
        anyhow::bail!(
            "iat invalid; valid_since: want >= 0, got {}, iat = {}, leeway = {}",
            valid_since + leeway,
            payload.claims.iat,
            leeway
        );
    }
    let dpop_validity: i64 = location_config.dpop_validity().as_secs().try_into()?;
    let valid_until = payload.claims.iat + dpop_validity + leeway;
    if valid_until < now {
        anyhow::bail!(
            "no longer valid: want {} + {} + {} = {} < {}",
            payload.claims.iat,
            dpop_validity,
            leeway,
            valid_until,
            now
        );
    }

    if http_method != payload.claims.htm {
        anyhow::bail!(
            "htm invalid: want {}; got {}",
            http_method,
            payload.claims.htm,
        );
    }

    // https://datatracker.ietf.org/doc/html/rfc9449#name-checking-dpop-proofs, Nr. 9:
    // „The htu claim matches the HTTP URI value for the HTTP request in which the JWT was received,
    // ignoring any query and fragment parts.”
    let htu: Uri = payload.claims.htu.try_into()?;
    if htu.query().is_some() {
        bail!("htu contains query: {htu}");
    }
    // request_uri is normalized as well
    let htu = normalized_uri(
        htu.scheme()
            .map(|scheme| scheme.as_str())
            .unwrap_or("https"),
        htu.host().context("no host in htu")?,
        htu.port().map(|port| port.as_u16()),
        htu.path(),
    )?;
    if request_uri != htu {
        anyhow::bail!("htu invalid: want {}; got {}", request_uri, htu);
    }

    Ok(())
}

fn verify_client_ip(
    main_config: &MainConfig,
    access_token_claims: &AccessTokenPayload,
    request_ip: Option<&str>,
) -> ZetaResult<()> {
    if main_config.no_travel {
        let access_ip = &access_token_claims.ip_address;
        let client_ip = request_ip.ok_or_else(|| {
            ZetaError::Internal(anyhow!(
                "client IP address unavailable; ingress must set HTTP Forwarded header"
            ))
        })?;
        if client_ip != access_ip {
            return Err(ZetaError::ImpossibleTravel(anyhow!(
                "access token IP does not match client IP address"
            )));
        }
    }
    Ok(())
}

async fn pep_handler<R: RequestOps + ConfigOps>(request: &mut R) -> ZetaResult<()> {
    let now = get_current_timestamp();

    ensure_api_version_header_out(request)?;
    let main_config = request.main_config()?;
    let location_config = request.location_config()?;

    let access_token = request
        .get_authorization_token()
        .map_err(ZetaError::AccessToken)?;
    let ath = Sha256::digest(&access_token).to_vec();
    let access_token =
        verify_access_token(main_config, location_config, &access_token, now).await?;

    let dpop = request
        .get_header_in("dpop")
        .context("missing DPoP header")
        .map_err(ZetaError::DPoP)?;
    let http_method = request.method();
    let uri: Uri = request.eigenurl_normalized()?;

    verify_dpop(
        location_config,
        &access_token.claims,
        &ath,
        dpop,
        now,
        &http_method,
        uri,
    )
    .await
    .map_err(ZetaError::DPoP)?;

    verify_client_ip(main_config, &access_token.claims, request.get_client_ip())?;

    if location_config.require_popp.unwrap_or(false) {
        if main_config.popp_issuer.is_none() {
            return Err(ZetaError::PoPP(anyhow!("No `pep_popp_issuer` configured")));
        }

        let popp = request
            .get_header_in("popp")
            .ok_or(ZetaError::PoPP(anyhow!("missing PoPP header")))?;
        let token_data = verify_popp(location_config, popp, now)
            .await
            .map_err(ZetaError::PoPP)?;
        ensure_popp_token_header_in(request, token_data.claims)?;
    }

    let claims = access_token.claims;
    ensure_user_info_header_in(
        request,
        ZetaUserInfo {
            common_name: claims.common_name.context("missing common_name")?.clone(),
            identifier: claims.sub.clone(),
            profession_oid: claims.profession_oid.clone(),
            organization_name: claims.organization_name.clone(),
        },
    )?;

    let platform = claims.platform.map(|p| match p {
        AccessTokenPayloadPlatform::Android => ClientDataPlatform::Android,
        AccessTokenPayloadPlatform::Apple => ClientDataPlatform::Apple,
        AccessTokenPayloadPlatform::Windows => ClientDataPlatform::Windows,
        AccessTokenPayloadPlatform::Linux => ClientDataPlatform::Linux,
    });

    ensure_client_data_header_in(
        request,
        ClientData {
            client_id: claims.client_id.clone(),
            platform,
            product_id: claims.product_id.clone(),
            product_version: claims.product_version.clone(),
        },
    )?;

    Ok(())
}

pub fn handler(request: &mut Request) -> Status {
    let config = Module::location_conf(request).expect("location config is none");

    match config.pep {
        Some(true) => {
            // Check if we were called *again*
            if let Some(task) = ModuleCtx::take_pep_task(request) {
                // task should be finished when re-entering the handler
                if !task.is_finished() {
                    ngx_log_error!(NGX_LOG_ERR, request.log(), "pep: Task not finished");
                    return HTTPStatus::INTERNAL_SERVER_ERROR.into();
                }
                return match task.now_or_never().expect("Task result") {
                    Ok(()) => Status::NGX_OK, // OK: allow access, move to next phase
                    Err(err) => {
                        log_debug!("pep: {err}");
                        let response = request
                            .eigenurl_normalized()
                            .and_then(|base| err.response(base));

                        match response {
                            Ok(response) => {
                                response.send(request, Status::NGX_ERROR);
                                Status::NGX_ERROR
                            }
                            Err(e) => {
                                ngx_log_error!(
                                    NGX_LOG_ERR,
                                    request.log(),
                                    "error building error response — {e}"
                                );
                                // request was *not* finalized, return fast finalization status
                                HTTPStatus::INTERNAL_SERVER_ERROR.into()
                            }
                        }
                    }
                };
            }

            let r_ptr = AtomicPtr::new(request.into());
            let task = spawn_compat(async move {
                let r_ptr = r_ptr.load(Ordering::Relaxed);
                let request = unsafe { ngx::http::Request::from_ngx_http_request(r_ptr) };

                let result = pep_handler(request).await;

                let c: *mut ngx_connection_t = request.connection().cast();
                // trigger „write” event so nginx calls our handler again
                unsafe { ngx_post_event((*c).write, addr_of_mut!(ngx_posted_events)) };
                result
            });

            ModuleCtx::insert_pep_task(request, task);

            Status::NGX_AGAIN
        }
        _ => Status::NGX_DECLINED,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use jsonwebtoken::jwk::Jwk;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use mockall::predicate::eq;
    use rstest::rstest;
    use serde::Serialize;
    use serial_test::serial;

    use crate::jwk_cache::with_jwk_cache_mock;
    use crate::tests::{RequestMock, request_mock};
    use crate::typify::AccessTokenPayloadCnf;

    use super::*;

    static EC_PRIVATE_KEY: LazyLock<EncodingKey> = LazyLock::new(|| {
        EncodingKey::from_ec_pem(include_bytes!("./client/ec-private.pem")).expect("ec")
    });

    impl Default for AccessTokenPayload {
        fn default() -> Self {
            Self {
                aud: AccessTokenPayloadAud::String("aud".to_string()),
                client_id: "client_id".to_string(),
                cnf: AccessTokenPayloadCnf {
                    jkt: "".to_string(),
                },
                common_name: None,
                exp: i64::MAX,
                iat: 0,
                ip_address: "ip_address".to_string(),
                iss: "issuer".to_string(),
                jti: "jti".to_string(),
                organization_name: None,
                platform: None,
                product_id: "product_id".to_string(),
                product_version: "product_version".to_string(),
                profession_oid: "profession_oid".to_string(),
                scope: None,
                sub: "sub".to_string(),
            }
        }
    }

    fn make_jwt<T: Serialize>(mut header: Header, claims: T) -> String {
        header.kid = Some("kid".to_string());
        encode(&header, &claims, &EC_PRIVATE_KEY).expect("jwt")
    }

    #[rstest]
    #[tokio::test]
    async fn test_missing_auth_header(#[future(awt)] mut request_mock: RequestMock) {
        request_mock
            .request
            .expect_get_authorization_token()
            .times(1)
            .returning(|| Err(anyhow!("No token")));

        let result = pep_handler(&mut request_mock).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No token"));
    }

    #[rstest]
    #[tokio::test]
    #[serial] // jwk cache
    async fn verifies_tokens(#[future(awt)] mut request_mock: RequestMock) {
        let jwk = Jwk::from_encoding_key(&EC_PRIVATE_KEY, Algorithm::ES256).expect("jwk");
        with_jwk_cache_mock(|mock| {
            mock.expect_get_jwk_pdp()
                .with(eq("kid".to_string()))
                .returning(move |_| Ok(jwk.clone()));
        })
        .await;

        let now = 1;
        let token = make_jwt(Header::new(Algorithm::ES256), AccessTokenPayload::default());
        let result = verify_access_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
        assert!(result.is_ok());

        // aud
        // tolerate extra auds
        let token = make_jwt(
            Header::new(Algorithm::ES256),
            AccessTokenPayload {
                aud: AccessTokenPayloadAud::Array(vec!["aud".to_string(), "other_aud".to_string()]),
                ..Default::default()
            },
        );
        let result = verify_access_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
        assert!(result.is_ok());

        // multiple auds
        request_mock.lcfg.aud.replace(HashSet::from_iter(vec![
            "aud1".to_string(),
            "aud2".to_string(),
        ]));
        let token = make_jwt(
            Header::new(Algorithm::ES256),
            AccessTokenPayload {
                aud: AccessTokenPayloadAud::Array(vec![
                    "aud1".to_string(),
                    "aud2".to_string(),
                    "extra_aud".to_string(),
                ]),
                ..Default::default()
            },
        );
        let result = verify_access_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
        assert!(result.is_ok());

        // fail when we require more auds than present on token
        request_mock.lcfg.aud.replace(HashSet::from_iter(vec![
            "aud".to_string(),
            "missing_aud".to_string(),
        ]));

        let token = make_jwt(Header::new(Algorithm::ES256), AccessTokenPayload::default());
        let result = verify_access_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
        assert!(result.is_err_and(|err| err.to_string().contains("missing_aud")));
        request_mock
            .lcfg
            .aud
            .replace(HashSet::from_iter(vec!["aud".to_string()]));

        // scope
        request_mock.lcfg.scope.replace(HashSet::from_iter(vec![
            "required_scope1".to_string(),
            "required_scope2".to_string(),
        ]));

        // succeed when all required scopes are included
        let token = make_jwt(
            Header::new(Algorithm::ES256),
            AccessTokenPayload {
                scope: Some("required_scope2 required_scope1".to_string()), // any order
                ..Default::default()
            },
        );
        let result = verify_access_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
        assert!(result.is_ok());

        // fail when missing scope(s)
        let token = make_jwt(
            Header::new(Algorithm::ES256),
            AccessTokenPayload {
                scope: Some("required_scope1".to_string()),
                ..Default::default()
            },
        );
        let result = verify_access_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
        assert!(result.is_err_and(|err| err.to_string().contains("required_scope2")));

        let token = make_jwt(
            Header::new(Algorithm::ES256),
            AccessTokenPayload {
                scope: Some("".to_string()),
                ..Default::default()
            },
        );
        let result = verify_access_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
        assert!(
            result.is_err_and(|err| err.to_string().contains("required_scope1")
                && err.to_string().contains("required_scope2"))
        );

        let token = make_jwt(
            Header::new(Algorithm::ES256),
            AccessTokenPayload {
                scope: None,
                ..Default::default()
            },
        );
        let result = verify_access_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
        assert!(
            result.is_err_and(|err| err.to_string().contains("required_scope1")
                && err.to_string().contains("required_scope2"))
        );

        // or incorrect scope
        let token = make_jwt(
            Header::new(Algorithm::ES256),
            AccessTokenPayload {
                scope: Some("another_scope".to_string()),
                ..Default::default()
            },
        );
        let result = verify_access_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
        assert!(
            result.is_err_and(|err| err.to_string().contains("required_scope1")
                && err.to_string().contains("required_scope2"))
        );
        request_mock.lcfg.scope.take();

        // iat=nbf
        let token = make_jwt(
            Header::new(Algorithm::ES256),
            AccessTokenPayload {
                iat: i64::MAX,
                ..Default::default()
            },
        );
        let result = verify_access_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
        assert!(result.is_err_and(|err| err.to_string().contains("iat invalid")));

        // leeway
        let now = 1;
        let token = make_jwt(
            Header::new(Algorithm::ES256),
            AccessTokenPayload {
                iat: 61,
                ..Default::default()
            },
        );
        let result = verify_access_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
        assert!(result.is_ok());

        let now = 1;
        let token = make_jwt(
            Header::new(Algorithm::ES256),
            AccessTokenPayload {
                iat: 62,
                ..Default::default()
            },
        );
        let result = verify_access_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
        assert!(result.is_err_and(|err| err.to_string().contains("iat invalid")));
    }

    #[rstest]
    #[tokio::test]
    #[serial] // jwk cache
    async fn verifies_dpop(#[future(awt)] request_mock: RequestMock) {
        let jwk = Jwk::from_encoding_key(&EC_PRIVATE_KEY, Algorithm::ES256).expect("jwk");
        with_jwk_cache_mock(|mock| {
            let jwk = jwk.clone();
            mock.expect_get_jwk_pdp()
                .with(eq("kid".to_string()))
                .returning(move |_| Ok(jwk.clone()));
        })
        .await;

        let now: u64 = 1;

        let at = AccessTokenPayload {
            cnf: AccessTokenPayloadCnf {
                jkt: jwk.thumbprint(ThumbprintHash::SHA256),
            },
            ..Default::default()
        };
        let at_jwt = make_jwt(Header::new(Algorithm::ES256), &at);
        let ath = Sha256::digest(&at_jwt).to_vec();
        let mut dpop_header = Header::new(Algorithm::ES256);
        dpop_header.typ = Some("dpop+jwt".to_string());
        dpop_header.jwk = Some(jwk.clone());
        let dpop = make_jwt(
            dpop_header,
            DPoPProofJwtPayload {
                ath: Some(Base64UrlUnpadded::encode_string(&ath).to_string()),
                htm: "GET".to_string(),
                htu: "http://localhost/htu".to_string(),
                iat: now.try_into().expect("iat overflow"),
                jti: "jti".to_string(),
                nonce: None,
            },
        );

        let result = verify_dpop(
            &request_mock.lcfg,
            &at,
            &ath,
            &dpop,
            now,
            "GET",
            "http://localhost/htu".try_into().expect("uri"),
        )
        .await;
        assert!(result.is_ok());

        // method mismatch
        let result = verify_dpop(
            &request_mock.lcfg,
            &at,
            &ath,
            &dpop,
            now,
            "POST",
            "http://localhost/htu".try_into().expect("uri"),
        )
        .await;
        assert!(result.is_err_and(|err| err.to_string().contains("htm invalid")));

        // uri mismatch
        let result = verify_dpop(
            &request_mock.lcfg,
            &at,
            &ath,
            &dpop,
            now,
            "GET",
            "http://localhost/invalid".try_into().expect("uri"),
        )
        .await;
        assert!(result.is_err_and(|err| err.to_string().contains("htu invalid")));

        // access token cnf mismatch

        let invalid_at = AccessTokenPayload {
            cnf: AccessTokenPayloadCnf {
                jkt: "invalid".to_string(),
            },
            ..Default::default()
        };

        let result = verify_dpop(
            &request_mock.lcfg,
            &invalid_at,
            &ath,
            &dpop,
            now,
            "GET",
            "http://localhost/htu".try_into().expect("uri"),
        )
        .await;
        assert!(result.is_err_and(|err| err.to_string().contains("invalid thumbprint")));

        // dpop proof ath mismatch
        let invalid_ath = "wrong";
        let result = verify_dpop(
            &request_mock.lcfg,
            &at,
            &invalid_ath.as_bytes().to_vec(),
            &dpop,
            now,
            "GET",
            "http://localhost/htu".try_into().expect("uri"),
        )
        .await;
        assert!(result.is_err_and(|err| err.to_string().contains("invalid ath")));

        // dpop proof typ mismatch
        let mut invalid_dpop_header = Header::new(Algorithm::ES256);
        invalid_dpop_header.typ = Some("dpop+wrong".to_string());
        invalid_dpop_header.jwk = Some(jwk.clone());
        let invalid_dpop = make_jwt(
            invalid_dpop_header,
            DPoPProofJwtPayload {
                ath: Some(Base64UrlUnpadded::encode_string(&ath).to_string()),
                htm: "GET".to_string(),
                htu: "http://localhost/htu".to_string(),
                iat: now.try_into().expect("iat overflow"),
                jti: "jti".to_string(),
                nonce: None,
            },
        );
        let result = verify_dpop(
            &request_mock.lcfg,
            &at,
            &ath,
            &invalid_dpop,
            now,
            "GET",
            "http://localhost/htu".try_into().expect("uri"),
        )
        .await;

        assert!(result.is_err_and(|err| err.to_string().contains("invalid typ")));
    }

    #[rstest]
    #[tokio::test]
    async fn verifies_client_ip() {
        let no_travel_on = MainConfig {
            no_travel: true,
            ..Default::default()
        };

        let at = AccessTokenPayload {
            ip_address: "192.168.1.1".to_string(),
            ..Default::default()
        };

        let result = verify_client_ip(&no_travel_on, &at, Some("192.168.1.1"));
        assert!(result.is_ok());

        // mismatch
        let result = verify_client_ip(&no_travel_on, &at, Some("127.0.0.1"));
        assert!(result.is_err_and(|err| err.to_string().contains("Impossible Travel")));

        // missing client IP
        let result = verify_client_ip(&no_travel_on, &at, None);
        assert!(result.is_err_and(|err| err.to_string().contains("client IP address unavailable")));

        // disabled
        let no_travel_off = MainConfig {
            no_travel: false,
            ..Default::default()
        };
        let result = verify_client_ip(&no_travel_off, &at, None);
        assert!(result.is_ok());
    }
}
