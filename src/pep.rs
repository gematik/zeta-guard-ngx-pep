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

use crate::ModuleCtx;
use crate::headers::{
    ensure_api_version_header_out, ensure_client_data_header_in, ensure_popp_token_header_in,
    ensure_user_info_header_in,
};
use crate::jwk_cache::JwkCacheOps;
use crate::request_ops::{ConfigOps, RequestOps, normalized_uri};
use crate::typify::{
    AccessTokenPayload, AccessTokenPayloadAud, AccessTokenPayloadCdatPlatformProductId,
    ClientInstance, DPoPProofJwtPayload, UserInfo,
};
use crate::{
    conf::{LocationConfig, MainConfig},
    jwk_cache::jwk_cache,
    log_debug,
};
use anyhow::{Context, Result, anyhow, bail};
use async_compat::Compat;
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
use ngx_tickle::spawn;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::ptr::addr_of_mut;
use std::sync::atomic::{AtomicPtr, Ordering};

use crate::Module;

async fn verify_acess_token(
    main_config: &MainConfig,
    location_config: &LocationConfig,
    token: &str,
    now: u64,
) -> Result<TokenData<AccessTokenPayload>> {
    let header = decode_header(token)?;
    let kid = header.kid.ok_or_else(|| anyhow!("no kid"))?;
    if header.alg != Algorithm::ES256 {
        anyhow::bail!("at: unsupported token alg {:?}", header.alg);
    }

    let jwk = jwk_cache().get_jwk_pdp(kid).await?;

    if jwk.common.key_algorithm != Some(KeyAlgorithm::ES256) {
        anyhow::bail!("at: unsupported jwk alg: {:?}", jwk.common.key_algorithm);
    }
    let key = DecodingKey::from_jwk(&jwk)?;

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
    let payload = decode::<AccessTokenPayload>(token, &key, &validation)?;

    let now: i64 = now.try_into()?;
    let valid_since = now - payload.claims.iat;
    let leeway: i64 = location_config.leeway().as_secs().try_into()?;
    if valid_since + leeway < 0 {
        anyhow::bail!(
            "at: iat invalid; valid_since: want >= 0, got {}, iat = {}, leeway = {}",
            valid_since + leeway,
            payload.claims.iat,
            leeway
        );
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
            anyhow::bail!(
                "at: missing audiences: want {}, got {:#?}",
                missing_auds.join(","),
                auds,
            );
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
            anyhow::bail!("at: missing scopes: {}", missing_scopes.join(","));
        }
    }

    Ok(payload)
}

async fn verify_popp(
    location_config: &LocationConfig,
    popp: &str,
    now: u64,
) -> Result<TokenData<Value>> {
    let header = decode_header(popp)?;

    match &header.typ {
        Some(typ) => {
            if typ != "vnd.telematik.popp+jwt" {
                bail!("PoPP: invalid typ {typ}");
            }
        }
        None => bail!("PoPP: no typ"),
    };

    if header.alg != Algorithm::ES256 {
        anyhow::bail!("PoPP: unsupported token alg {:?}", header.alg);
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
        .context("couldn't parse iat")?;
    let iat: i64 = iat.try_into().context("iat u64->i64 overflow")?;
    let now: i64 = now.try_into()?;
    let valid_since = now - iat;
    let leeway: i64 = location_config.leeway().as_secs().try_into()?;
    if valid_since + leeway < 0 {
        anyhow::bail!(
            "PoPP: iat invalid; valid_since: want >= 0, got {}, iat = {}, leeway = {}",
            valid_since + leeway,
            iat,
            leeway
        );
    }
    let ppop_validity: i64 = location_config.ppop_validity().as_secs().try_into()?;
    let valid_until = iat + ppop_validity + leeway;
    if valid_until < now {
        anyhow::bail!(
            "PPoP: not longer valid: want {} + {} + {} = {} < {}",
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
) -> Result<()> {
    let header = decode_header(dpop)?;

    match &header.typ {
        Some(typ) => {
            if typ != "dpop+jwt" {
                bail!("DPoP: invalid typ {typ}");
            }
        }
        None => bail!("DPoP: no typ"),
    };

    if header.alg != Algorithm::ES256 {
        anyhow::bail!("DPoP: unsupported token alg {:?}", header.alg);
    }
    let jwk = header.jwk.ok_or_else(|| anyhow!("no jwk"))?;

    if jwk.common.key_algorithm != Some(KeyAlgorithm::ES256) {
        anyhow::bail!("DPoP: unsupported jwk alg: {:?}", jwk.common.key_algorithm);
    }

    let thumbprint = jwk.thumbprint(ThumbprintHash::SHA256);
    let cnf = access_token_claims
        .cnf
        .clone()
        .ok_or_else(|| anyhow!("DPoP: missing cnf"))?;

    if cnf.jkt != thumbprint {
        bail!(
            "DPoP: invalid thumbprint; jkt={}, dpop={}",
            hex::encode(ath),
            hex::encode(thumbprint)
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
            .ok_or_else(|| anyhow!("DPoP: missing ath claim"))?,
    )?;

    if ath != &claimed_ath {
        bail!(
            "DPoP: invalid ath; access_token={}, ath={}",
            hex::encode(ath),
            hex::encode(claimed_ath)
        );
    }

    let now: i64 = now.try_into()?;
    let valid_since = now - payload.claims.iat;
    let leeway: i64 = location_config.leeway().as_secs().try_into()?;
    if valid_since + leeway < 0 {
        anyhow::bail!(
            "DPoP: iat invalid; valid_since: want >= 0, got {}, iat = {}, leeway = {}",
            valid_since + leeway,
            payload.claims.iat,
            leeway
        );
    }
    let dpop_validity: i64 = location_config.dpop_validity().as_secs().try_into()?;
    let valid_until = payload.claims.iat + dpop_validity + leeway;
    if valid_until < now {
        anyhow::bail!(
            "DPoP: no longer valid: want {} + {} + {} = {} < {}",
            payload.claims.iat,
            dpop_validity,
            leeway,
            valid_until,
            now
        );
    }

    if http_method != payload.claims.htm {
        anyhow::bail!(
            "DPoP: htm invalid: want {}; got {}",
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
        anyhow::bail!("DPoP: htu invalid: want {}; got {}", request_uri, htu);
    }

    Ok(())
}

async fn pep_handler<R: RequestOps + ConfigOps>(request: &mut R) -> Result<Status> {
    let now = get_current_timestamp();
    let main_config = request.main_config()?;
    let location_config = request.location_config()?.clone();

    let access_token = request.get_authorization_token()?;
    let ath = Sha256::digest(&access_token).to_vec();
    let access_token =
        verify_acess_token(main_config, &location_config, &access_token, now).await?;

    let dpop = request
        .get_header_in("dpop")
        .context("missing DPoP header")?;
    let http_method = request.method();
    let uri: Uri = request.self_uri()?;

    verify_dpop(
        &location_config,
        &access_token.claims,
        &ath,
        dpop,
        now,
        &http_method,
        uri,
    )
    .await?;

    if location_config.require_popp.unwrap_or(true) {
        match request.get_header_in("popp") {
            Some(popp) => {
                let token_data = verify_popp(&location_config, popp, now).await?;
                ensure_popp_token_header_in(request, token_data.claims)?;
            }
            None => bail!("PoPP header missing"),
        }
    }

    ensure_api_version_header_out(request)?;

    let udat = access_token.claims.udat.context("missing udat")?;
    ensure_user_info_header_in(
        request,
        UserInfo {
            identifier: udat.telid.clone(),
            mail: None,
            profession_oid: udat.prof.clone(),
        },
    )?;

    let cdat = access_token.claims.cdat.context("cdat missing")?;
    let platform_product_id = cdat.platform_product_id;
    let client_instance = match platform_product_id {
        AccessTokenPayloadCdatPlatformProductId::AndroidProductId {
            namespace,
            package_name,
            platform,
            sha256_cert_fingerprints,
        } => ClientInstance::Variant0 {
            client_id: cdat.client_id.clone(),
            manufacturer_id: cdat
                .manufacturer_id
                .context("manufacturer_id missing")?
                .clone(),
            manufacturer_name: cdat
                .manufacturer_name
                .context("manufacturer_name missing")?
                .clone(),
            name: cdat.name.clone(),
            namespace: namespace.clone(),
            owner_mail: None,
            package_name: package_name.clone(),
            platform: platform.context("platform missing")?.clone(),
            platform_product_id: Map::new(),
            registration_timestamp: cdat.registration_timestamp,
            sha256_cert_fingerprints: sha256_cert_fingerprints.clone(),
        },
        AccessTokenPayloadCdatPlatformProductId::AppleProductId {
            app_bundle_ids,
            platform,
            platform_type,
        } => ClientInstance::Variant1 {
            client_id: cdat.client_id.clone(),
            manufacturer_id: cdat
                .manufacturer_id
                .context("manufacturer_id missing")?
                .clone(),
            manufacturer_name: cdat
                .manufacturer_name
                .context("manufacturer_name missing")?
                .clone(),
            name: cdat.name.clone(),
            owner_mail: None,
            platform_type: platform_type.clone(),
            platform: platform.context("platform missing")?.clone(),
            platform_product_id: Map::new(),
            registration_timestamp: cdat.registration_timestamp,
            app_bundle_ids: app_bundle_ids.clone(),
        },
        AccessTokenPayloadCdatPlatformProductId::WindowsProductId {
            package_family_name,
            platform,
            store_id,
        } => ClientInstance::Variant2 {
            client_id: cdat.client_id.clone(),
            manufacturer_id: cdat
                .manufacturer_id
                .context("manufacturer_id missing")?
                .clone(),
            manufacturer_name: cdat
                .manufacturer_name
                .context("manufacturer_name missing")?
                .clone(),
            name: cdat.name.clone(),
            owner_mail: None,
            package_family_name,
            platform: platform.context("platform missing")?.clone(),
            platform_product_id: Map::new(),
            registration_timestamp: cdat.registration_timestamp,
            store_id,
        },
        AccessTokenPayloadCdatPlatformProductId::LinuxProductId {
            application_id,
            packaging_type,
            platform,
        } => ClientInstance::Variant3 {
            client_id: cdat.client_id.clone(),
            manufacturer_id: cdat
                .manufacturer_id
                .context("manufacturer_id missing")?
                .clone(),
            manufacturer_name: cdat
                .manufacturer_name
                .context("manufacturer_name missing")?
                .clone(),
            name: cdat.name.clone(),
            owner_mail: None,
            application_id,
            platform: platform.context("platform missing")?.clone(),
            platform_product_id: Map::new(),
            registration_timestamp: cdat.registration_timestamp,
            packaging_type,
        },
    };
    ensure_client_data_header_in(request, client_instance)?;

    Ok(Status::NGX_OK)
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
                    Ok(status) => status,
                    Err(err) => {
                        log_debug!("pep: unauthorized — {err}");
                        HTTPStatus::UNAUTHORIZED.into()
                    }
                };
            }

            log_debug!("pep: enter");

            let r_ptr = AtomicPtr::new(request.into());
            let task = spawn(Compat::new(async move {
                let r_ptr = r_ptr.load(Ordering::Relaxed);
                let request = unsafe { ngx::http::Request::from_ngx_http_request(r_ptr) };

                let result = pep_handler(request).await;

                let c: *mut ngx_connection_t = request.connection().cast();
                // trigger „write” event so nginx calls our handler again
                unsafe { ngx_post_event((*c).write, addr_of_mut!(ngx_posted_events)) };
                result
            }));

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
        EncodingKey::from_ec_pem(include_bytes!("./tests/ec-private.pem")).expect("ec")
    });

    impl Default for AccessTokenPayload {
        fn default() -> Self {
            Self {
                aud: AccessTokenPayloadAud::String("aud".to_string()),
                client_id: None,
                cnf: None,
                exp: i64::MAX,
                iat: 0,
                iss: "issuer".to_string(),
                jti: "jti".to_string(),
                scope: None,
                sub: "sub".to_string(),
                udat: None,
                cdat: None,
            }
        }
    }

    fn make_jwt<T: Serialize>(mut header: Header, claims: T) -> String {
        header.kid = Some("kid".to_string());
        return encode(&header, &claims, &EC_PRIVATE_KEY).expect("jwt");
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
        let result = verify_acess_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
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
        let result = verify_acess_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
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
        let result = verify_acess_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
        assert!(result.is_ok());

        // fail when we require more auds than present on token
        request_mock.lcfg.aud.replace(HashSet::from_iter(vec![
            "aud".to_string(),
            "missing_aud".to_string(),
        ]));

        let token = make_jwt(Header::new(Algorithm::ES256), AccessTokenPayload::default());
        let result = verify_acess_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
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
        let result = verify_acess_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
        assert!(result.is_ok());

        // fail when missing scope(s)
        let token = make_jwt(
            Header::new(Algorithm::ES256),
            AccessTokenPayload {
                scope: Some("required_scope1".to_string()),
                ..Default::default()
            },
        );
        let result = verify_acess_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
        assert!(result.is_err_and(|err| err.to_string().contains("required_scope2")));

        let token = make_jwt(
            Header::new(Algorithm::ES256),
            AccessTokenPayload {
                scope: Some("".to_string()),
                ..Default::default()
            },
        );
        let result = verify_acess_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
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
        let result = verify_acess_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
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
        let result = verify_acess_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
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
        let result = verify_acess_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
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
        let result = verify_acess_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
        assert!(result.is_ok());

        let now = 1;
        let token = make_jwt(
            Header::new(Algorithm::ES256),
            AccessTokenPayload {
                iat: 62,
                ..Default::default()
            },
        );
        let result = verify_acess_token(&request_mock.mcfg, &request_mock.lcfg, &token, now).await;
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

        let mut at = AccessTokenPayload::default();
        at.cnf = Some(AccessTokenPayloadCnf {
            jkt: jwk.thumbprint(ThumbprintHash::SHA256),
        });
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
        let mut invalid_at = AccessTokenPayload::default();
        invalid_at.cnf = Some(AccessTokenPayloadCnf {
            jkt: "invalid".to_string(),
        });

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
}
