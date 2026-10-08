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

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use http::header::ACCEPT;
use http::{HeaderMap, HeaderValue, Method, Uri};
use jsonwebtoken::dangerous::insecure_decode;
use jsonwebtoken::{TokenData, get_current_timestamp};
use ngx_pep::client::asl::{
    AslResponse, asl_handshake, asl_handshake_with_ocsp, asl_request, encode_http_request,
    encode_valid_http_request, valid_asl_request,
};
use reqwest::Url;
use reqwest::cookie::Jar;
use rstest::rstest;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use ngx_pep::client::token_dispenser::{Tokens, create_dpop_proof, create_popp_token};
use ngx_pep::client::{SHARED_CLIENT, admission_from_x509, client_builder};
use ngx_pep::revocation::parse_event;
mod common;
use common::{NginxLease, TestContext, context, nginx};
use tokio::sync::Mutex;
use tokio_stream::StreamExt;

use crate::common::echo::{Echo, ws_request};
use crate::common::typify::{ClientData, HttpZetaErrorResponse, ZetaUserInfo};

#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn access_tokens_and_dpop(
    #[future(awt)] context: &TestContext,
    #[future(awt)] nginx: NginxLease,
) -> Result<()> {
    nginx.wait_ready().await?;

    let target = nginx.url().await?.join("empty.json")?;

    // valid access token and dpop proof
    let tokens = context.tokens().await?;

    let resp = tokens
        .valid_get(&context.jar, target.clone())?
        .send()
        .await?;

    assert!(resp.status() == 200);

    assert!(
        resp.headers()
            .get("zeta-api-version")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == env!("CARGO_PKG_VERSION"))
    );

    let result: Value = resp.json().await?;
    // empty.json is {}
    assert!(result == json!({}));

    // missing dpop and access token
    let resp = SHARED_CLIENT.get(target.clone()).send().await?;
    assert!(resp.status() == 401);
    assert!(
        resp.headers()
            .get("zeta-error-origin")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == "pep"),
        "missing credentials error must carry zeta-error-origin: pep"
    );

    // zeta-api-version also for 401s
    assert!(
        resp.headers()
            .get("zeta-api-version")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == env!("CARGO_PKG_VERSION"))
    );

    // missing access token
    let dpop = tokens.valid_dpop_proof("GET", target.as_str())?;
    let resp = SHARED_CLIENT
        .get(target.clone())
        .header("dpop", &dpop)
        .send()
        .await?;
    assert!(resp.status() == 401);
    assert!(
        resp.headers()
            .get("zeta-error-origin")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == "pep"),
        "missing access token error must carry zeta-error-origin: pep"
    );

    // missing dpop proof
    let resp = SHARED_CLIENT
        .get(target.clone())
        .bearer_auth(&tokens.access_token)
        .send()
        .await?;
    assert!(resp.status() == 401);
    assert!(
        resp.headers()
            .get("zeta-error-origin")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == "pep"),
        "missing DPoP error must carry zeta-error-origin: pep"
    );

    // incorrect dpop proof
    let incorrect_dpop = create_dpop_proof(
        &context.registration,
        "POST",
        target.as_str(),
        Some(&Base64UrlUnpadded::encode_string(&Sha256::digest(
            &tokens.access_token,
        ))),
        None,
    )?;
    let resp = SHARED_CLIENT
        .get(target.clone())
        .bearer_auth(&tokens.access_token)
        .header("dpop", &incorrect_dpop)
        .send()
        .await?;
    assert!(resp.status() == 401);
    assert!(
        resp.headers()
            .get("zeta-error-origin")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == "pep"),
        "incorrect DPoP error must carry zeta-error-origin: pep"
    );

    let incorrect_dpop_ath = create_dpop_proof(
        &context.registration,
        "GET",
        target.as_str(),
        Some(&Base64UrlUnpadded::encode_string(&Sha256::digest(
            "invalid_ath",
        ))),
        None,
    )?;
    let resp = SHARED_CLIENT
        .get(target.clone())
        .bearer_auth(&tokens.access_token)
        .header("dpop", &incorrect_dpop_ath)
        .send()
        .await?;
    assert!(resp.status() == 401);
    assert!(
        resp.headers()
            .get("zeta-error-origin")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == "pep"),
        "incorrect DPoP ath error must carry zeta-error-origin: pep"
    );

    Ok(())
}

#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn popp_and_upstream_headers(
    #[future(awt)] context: &TestContext,
    #[future(awt)] nginx: NginxLease,
) -> Result<()> {
    nginx.wait_ready().await?;

    // start a server that responds with Echo objects containing request method, uri, headers.
    // It's configured as upstream (see nginx.conf.tpl and build.rs) and allows the test to assert
    // that the pep module sets upstream headers correctly.

    let echo_sever = nginx.start_echo_server().await;
    let target = nginx.url().await?.join("echo-with-popp/")?;

    let tokens = context.tokens().await?;

    // missing popp header
    let resp = tokens
        .valid_get(&context.jar, target.clone())?
        .send()
        .await?;

    assert!(resp.status() == 400);
    assert!(
        resp.headers()
            .get("zeta-error-origin")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == "pep"),
        "PoPPMissing error must carry zeta-error-origin: pep"
    );

    let error: HttpZetaErrorResponse = resp.json().await?;
    assert!(error.error == "PoPPMissing");

    // invalid popp header
    let resp = tokens
        .valid_get(&context.jar, target.clone())?
        .header("popp", "garbage")
        .send()
        .await?;

    assert!(resp.status() == 403);
    assert!(
        resp.headers()
            .get("zeta-error-origin")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == "pep"),
        "invalid PoPP error must carry zeta-error-origin: pep"
    );

    // valid

    let resp = tokens
        .valid_get(&context.jar, target.clone())?
        .header("popp", &tokens.popp)
        // A_25669-01 (ZETAP-992): client-supplied ZETA-* headers must be overwritten by the PEP, not
        // cause a 500 (conflict) nor leak upstream. The decode/parse + cert/client_id assertions below
        // would fail if any FAKE value survived.
        .header("zeta-user-info", "FAKE_USER_INFO")
        .header("zeta-client-data", "FAKE_CLIENT_DATA")
        .header("zeta-popp-token-content", "FAKE_POPP_CONTENT")
        .send()
        .await?;

    assert!(resp.status() == 200);

    let echo: Echo = resp.json().await?;

    // A_28439: the PEP updates the Forwarded header (RFC 7239) — the client's element is kept and
    // the PEP appends its own (by=_zetapep …).
    let forwarded = &echo.headers["forwarded"];
    assert!(
        // A_28439: an existing Forwarded element must be preserved and the PEP's own element appended.
        // NOTE: the test setup always prepends an element now: for="{token_ip}", so it is not
        // blocked due to no-travel restriction, assert that this element is preserved
        forwarded.starts_with(&format!(
            "for=\"{}\"",
            tokens.access_token_data.claims.ip_address
        )),
        "existing Forwarded element not preserved: {forwarded}"
    );
    assert!(
        forwarded.contains("by=_zetapep"),
        "PEP did not append its own Forwarded element: {forwarded}"
    );

    // test headers passed to upstream
    let user_info: String = Base64::decode_vec(&echo.headers["zeta-user-info"])?.try_into()?;
    let user_info: ZetaUserInfo = serde_json::from_str(&user_info)?;

    let admission = admission_from_x509(&context.smcb_key.cert)?;
    let profession_info = admission.single_profession_info()?;
    assert!(Some(user_info.identifier.clone()) == profession_info.registration_number()?);

    // HOTFIX ANFTI2-922 / A_27558: the fixed `birthdate` is emitted for insurant tokens
    // (professionOID 1.2.276.0.76.4.49) only. This test authenticates via SMC-B token
    // exchange, i.e. an institution OID — the field must be absent here.
    assert_eq!(
        user_info.birthdate, None,
        "zeta-user-info must not carry a birthdate for SMC-B/LEI tokens"
    );

    let cert_profession_oids: Option<Vec<String>> = profession_info
        .profession_oids
        .as_ref()
        .map(|oids| oids.iter().map(|oid| oid.to_string()).collect());
    assert!(Some(vec![user_info.profession_oid.clone()]) == cert_profession_oids);

    let client_data: String = Base64::decode_vec(&echo.headers["zeta-client-data"])?.try_into()?;
    let client_data: ClientData = serde_json::from_str(&client_data)?;

    // fields are mostly just copied from our client data, just check that the client_id matches
    // for now
    assert!(client_data.client_id == context.registration.client_id);

    let popp_token: String =
        Base64::decode_vec(&echo.headers["zeta-popp-token-content"])?.try_into()?;
    let popp_token_content: Value = serde_json::from_str(&popp_token)?;
    let expected_popp_token: TokenData<Value> = insecure_decode(&tokens.popp)?;
    assert!(popp_token_content == expected_popp_token.claims);

    // don't pass on zeta-client-data unless configured, A_26492-02
    let target_without_client_data = nginx.url().await?.join("echo/")?;

    let resp = tokens
        .valid_get(&context.jar, target_without_client_data.clone())?
        .send()
        .await?;

    assert!(resp.status() == 200);

    let echo: Echo = resp.json().await?;
    assert!(
        !echo.headers.contains_key("zeta-client-data"),
        "zeta-client-data present when it shouldn't"
    );

    // A_25669-01 (ZETAP-992): client-supplied ZETA-* headers must never reach the upstream
    // unmodified, even on a location that does not set them itself: here PoPP is not required and
    // client-data forwarding is off, so the PEP adds neither — both fake headers must be stripped,
    // and the always-set zeta-user-info must be overwritten (not the fake value).
    let resp = tokens
        .valid_get(&context.jar, target_without_client_data.clone())?
        .header("zeta-user-info", "FAKE_USER_INFO")
        .header("zeta-client-data", "FAKE_CLIENT_DATA")
        .header("zeta-popp-token-content", "FAKE_POPP_CONTENT")
        .send()
        .await?;

    assert!(resp.status() == 200);

    let echo: Echo = resp.json().await?;
    assert!(
        !echo.headers.contains_key("zeta-popp-token-content"),
        "client-supplied zeta-popp-token-content leaked to upstream"
    );
    assert!(
        !echo.headers.contains_key("zeta-client-data"),
        "client-supplied zeta-client-data leaked to upstream (forwarding is off)"
    );
    assert!(
        echo.headers
            .get("zeta-user-info")
            .is_some_and(|v| v != "FAKE_USER_INFO"),
        "zeta-user-info not overwritten by PEP"
    );

    // invalid actorId
    let now = get_current_timestamp();
    let iat = now;
    let proof_time = now - 10;
    let popp = create_popp_token(&context.popp_key, "invalid", iat, proof_time).await?;

    let resp = tokens
        .valid_get(&context.jar, target.clone())?
        .header("popp", &popp)
        .send()
        .await?;

    assert!(resp.status() == 403);
    assert!(
        resp.headers()
            .get("zeta-error-origin")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == "pep"),
        "PoPPInvalidActor error must carry zeta-error-origin: pep"
    );
    let error: HttpZetaErrorResponse = resp.json().await?;
    assert!(error.error == "PoPPInvalidActor");

    echo_sever.abort();
    let _ = echo_sever.await;

    Ok(())
}

#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn zeta_cause_proxy_intercepted(
    #[future(awt)] context: &TestContext,
    #[future(awt)] nginx: NginxLease,
) -> Result<()> {
    nginx.wait_ready().await?;
    let echo_server = nginx.start_echo_server().await;

    let target = nginx.url().await?.join("echo/proxy_error")?;
    let tokens = context.tokens().await?;

    let resp = tokens
        .valid_get(&context.jar, target.clone())?
        .send()
        .await?;

    // Upstream returned 200; pep must have replaced it with a 500 ZetaError::Proxy.
    assert!(resp.status() == 500, "got status {}", resp.status());

    // The upstream header itself must not be propagated.
    assert!(resp.headers().get("zeta-cause").is_none());

    // Proxy errors also originate in the PEP — the header must be present.
    assert!(
        resp.headers()
            .get("zeta-error-origin")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == "pep"),
        "pep-originated proxy error must carry zeta-error-origin: pep"
    );

    // Read the body once, verify it does not leak the upstream body and is the Proxy JSON error.
    let body = resp.bytes().await?;
    assert!(
        !body.windows(20).any(|w| w == b"SECRET_UPSTREAM_BODY"),
        "upstream body leaked: {:?}",
        String::from_utf8_lossy(&body)
    );

    let error: HttpZetaErrorResponse = serde_json::from_slice(&body)?;
    assert!(error.error == "Proxy", "got {:?}", error.error);
    assert!(
        error
            .error_uri
            .as_deref()
            .is_some_and(|u| u.ends_with("/doc/errors/Proxy.html")),
        "got error_uri {:?}",
        error.error_uri
    );

    echo_server.abort();
    let _ = echo_server.await;
    Ok(())
}

#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn websockets(
    #[future(awt)] context: &TestContext,
    #[future(awt)] nginx: NginxLease,
) -> Result<()> {
    // echo_server serves a websocket acceptor at /ws
    let echo_sever = nginx.start_echo_server().await;

    nginx.wait_ready().await?;
    let target = nginx.url().await?.join("echo/ws/")?;
    let target = target.as_str();

    let tokens = context.tokens().await?;

    let resp = ws_request(tokens, target.parse()?, 42u8).await?;
    // echo ws is expected to return the given u8
    assert!(resp == 42u8);

    echo_sever.abort();
    let _ = echo_sever.await;

    Ok(())
}

#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn asl(#[future(awt)] context: &TestContext, #[future(awt)] nginx: NginxLease) -> Result<()> {
    nginx.wait_ready().await?;

    let target = nginx.url().await?;

    let tokens = context.tokens().await?;

    let mut asl_session = asl_handshake(&tokens, target.clone()).await?;

    let inner = encode_valid_http_request(
        &tokens,
        Method::GET,
        target.join("empty.json")?.as_str().parse()?,
        None,
    )?;

    let response =
        valid_asl_request(&tokens, &mut asl_session, target.clone(), &inner, None).await?;

    match response {
        AslResponse::Body(body) => {
            let result: Value = serde_json::from_slice(&body)?;
            // empty.json is {}
            assert!(result == json!({}));
        }
        AslResponse::Error(err) => bail!("want body, got asl error {err:?}"),
        AslResponse::HttpError(err) => bail!("want body, got http error {err:?}"),
        AslResponse::Unexpected((status, body)) => {
            bail!("want body, got unexpected error {status:?} {body}")
        }
    }

    let inner_invalid = [0u8; 1];
    let response = valid_asl_request(
        &tokens,
        &mut asl_session,
        target.clone(),
        &inner_invalid,
        None,
    )
    .await?;

    match response {
        AslResponse::Body(_) => {
            bail!("want error, got body");
        }
        AslResponse::Error(err) => {
            assert!(err.message_type == "Error");
            assert!(err.error_code == 102);
            assert!(err.error_message == "internal error: unparseable inner request");
        }
        AslResponse::HttpError(err) => bail!("want asl error, got http error {err:?}"),
        AslResponse::Unexpected((status, body)) => {
            bail!("want asl error, got unexpected error {status:?} {body}")
        }
    }

    let inner_invalid = [0u8; 0];
    let response = valid_asl_request(
        &tokens,
        &mut asl_session,
        target.clone(),
        &inner_invalid,
        None,
    )
    .await?;

    match response {
        AslResponse::Body(_) => {
            bail!("want error, got body");
        }
        AslResponse::Error(err) => {
            // sic, A_26928
            assert!(err.message_type == "Error");
            assert!(err.error_code == 6);
            assert!(err.error_message == "bad format: extended ciphertext");
        }
        AslResponse::HttpError(err) => bail!("want asl error, got http error {err:?}"),
        AslResponse::Unexpected((status, body)) => {
            bail!("want asl error, got unexpected error {status:?} {body}")
        }
    };

    // access phase errors on /ASL/<cid> lead to application/json errors, not application/cbor

    let inner = encode_valid_http_request(
        &tokens,
        Method::GET,
        target.join("empty.json")?.as_str().parse()?,
        None,
    )?;

    let response = asl_request(
        "invalid",
        &mut asl_session,
        target.clone(),
        &tokens.valid_dpop_proof("POST", target.as_str())?,
        &inner,
        None,
    )
    .await?;

    match response {
        AslResponse::Body(_) => bail!("want http error, got body"),
        AslResponse::Error(err) => bail!("want body, got asl error {err:?}"),
        AslResponse::HttpError(err) => {
            assert!(err.error == "AccessToken");
            assert!(
                err.error_description
                    == Some("access token error: while decoding authorization token header".into())
            );
        }
        AslResponse::Unexpected((status, body)) => {
            bail!("want http error, got unexpected error {status:?} {body}")
        }
    }

    // access phase errors in the inner request lead to error in asl_request helper

    let uri: Uri = target.join("empty.json")?.as_str().parse()?;
    let inner = encode_http_request(
        "invalid",
        &tokens.valid_dpop_proof("GET", &uri.to_string())?,
        Method::GET,
        uri,
        None,
    )?;

    let response = valid_asl_request(&tokens, &mut asl_session, target.clone(), &inner, None).await;

    assert!(response.is_err_and(|e| e.to_string() == "inner status: 401 Unauthorized"));

    Ok(())
}

#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn asl_forward_header(
    #[future(awt)] context: &TestContext,
    #[future(awt)] nginx: NginxLease,
) -> Result<()> {
    nginx.wait_ready().await?;

    let target = nginx.url().await?;

    let tokens = context.tokens().await?;

    let mut asl_session = asl_handshake(&tokens, target.clone()).await?;

    fn encoded_inner(tokens: &Tokens, target_uri: Uri) -> Result<Vec<u8>> {
        let mut inner_headers = HashMap::new();
        // any inner {x-,}forwarded{,-*} header should still be tolerated, but ignored
        inner_headers.insert("X-Forwarded-For", "something".to_string());
        inner_headers.insert("X-Forwarded-Host", "anotherthing".to_string());
        inner_headers.insert("X-Forwarded-Proto", "https".to_string());
        inner_headers.insert("X-Forwarded-Port", "123".to_string());
        inner_headers.insert("Forwarded", "host=somehost;proto=https".to_string());
        encode_valid_http_request(tokens, Method::GET, target_uri, Some(inner_headers))
    }

    let url = target.join("empty.json")?;
    let url = url.as_str();

    // No outer {x-,}forwarded{,-*}
    let inner = encoded_inner(&tokens, url.parse()?)?;

    let response =
        valid_asl_request(&tokens, &mut asl_session, target.clone(), &inner, None).await?;

    match response {
        AslResponse::Body(body) => {
            let result: Value = serde_json::from_slice(&body)?;
            // empty.json is {}
            assert!(result == json!({}));
        }
        AslResponse::Error(err) => bail!("want body, got asl error {err:?}"),
        AslResponse::HttpError(err) => bail!("want body, got http error {err:?}"),
        AslResponse::Unexpected((status, body)) => {
            bail!("want body, got unexpected error {status:?} {body}")
        }
    };

    // outer x-forwarded-*
    let url = "https://forwarded.invalid:4444/empty.json";
    let inner = encoded_inner(&tokens, url.parse()?)?;

    let mut outer_headers = HeaderMap::new();
    outer_headers.insert(
        "x-forwarded-for",
        tokens
            .access_token_data
            .claims
            .ip_address
            .clone()
            .try_into()?,
    );
    outer_headers.insert("x-forwarded-proto", HeaderValue::from_str("https")?);
    outer_headers.insert(
        "x-forwarded-host",
        HeaderValue::from_str("forwarded.invalid")?,
    );
    // header names case insensitive
    outer_headers.insert("X-Forwarded-Port", HeaderValue::from_str("4444")?);
    let outer_dpop = tokens.valid_dpop_proof(
        "POST",
        &format!("https://forwarded.invalid:4444{}", asl_session.cid),
    )?;

    let response = asl_request(
        &tokens.access_token,
        &mut asl_session,
        target.clone(),
        &outer_dpop,
        &inner,
        Some(outer_headers),
    )
    .await?;

    match response {
        AslResponse::Body(body) => {
            let result: Value = serde_json::from_slice(&body)?;
            // empty.json is {}
            assert!(result == json!({}));
        }
        AslResponse::Error(err) => bail!("want body, got asl error {err:?}"),
        AslResponse::HttpError(err) => bail!("want body, got http error {err:?}"),
        AslResponse::Unexpected((status, body)) => {
            bail!("want body, got unexpected error {status:?} {body}")
        }
    };

    // outer with both forwarded and x-forwarded-* — forwarded takes precedence (see
    // `RequestOps::eigenurl_parts`)
    let url = "https://forwarded.invalid:4444/empty.json";
    let inner = encoded_inner(&tokens, url.parse()?)?;

    let mut outer_headers = HeaderMap::new();

    outer_headers.insert(
        "forwarded",
        format!(
            "by=forwarder;for={};host=forwarded.invalid:4444;proto=https",
            tokens.access_token_data.claims.ip_address
        )
        .try_into()?,
    );
    // these should be ignored due to the presence of forwarded:
    outer_headers.insert("x-forwarded-for", HeaderValue::from_str("x-client")?);
    outer_headers.insert("x-forwarded-proto", HeaderValue::from_str("x-https")?);
    outer_headers.insert(
        "x-forwarded-host",
        HeaderValue::from_str("x-forwarded.invalid")?,
    );
    outer_headers.insert("x-forwarded-port", HeaderValue::from_str("5555")?);

    let response = asl_request(
        &tokens.access_token,
        &mut asl_session,
        target.clone(),
        &outer_dpop,
        &inner,
        Some(outer_headers),
    )
    .await?;

    match response {
        AslResponse::Body(body) => {
            let result: Value = serde_json::from_slice(&body)?;
            // empty.json is {}
            assert!(result == json!({}));
        }
        AslResponse::Error(err) => bail!("want body, asl error {err:?}"),
        AslResponse::HttpError(err) => bail!("want body, got http error {err:?}"),
        AslResponse::Unexpected((status, body)) => {
            bail!("want body, got unexpected error {status:?} {body}")
        }
    };

    Ok(())
}

#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn asl_forward_client_ip(
    #[future(awt)] context: &TestContext,
    #[future(awt)] nginx: NginxLease,
) -> Result<()> {
    let echo_server = nginx.start_echo_server().await;
    nginx.wait_ready().await?;

    let target = nginx.url().await?;
    let token_dispenser = context.token_dispenser().await?;
    let tokens = token_dispenser.tokens().await?;

    let mut asl_session = asl_handshake(&tokens, target.clone()).await?;

    let echo_url = target.join("echo/")?;
    let inner = encode_http_request(
        &tokens.access_token,
        &tokens.valid_dpop_proof("GET", echo_url.as_str())?,
        Method::GET,
        echo_url.as_str().parse()?,
        None,
    )?;

    let token_ip = tokens.access_token_data.claims.ip_address.clone();
    let expected = format!("for=\"{}\"", token_ip.clone());
    // X-Real-IP (typical F5 NIC / nginx real_ip_header setting)
    let mut outer_headers = HeaderMap::new();
    outer_headers.insert("x-real-ip", token_ip.clone().try_into()?);

    let response = valid_asl_request(
        &tokens,
        &mut asl_session,
        target.clone(),
        &inner,
        Some(outer_headers),
    )
    .await?;

    match response {
        AslResponse::Body(body) => {
            let echo: Echo = serde_json::from_slice(&body)?;
            let forwarded = echo
                .headers
                .get("forwarded")
                .context("forwarded header missing from echo response")?;
            assert!(
                forwarded.contains(&expected),
                "expected {expected} in forwarded header, got: {forwarded}"
            );
        }
        AslResponse::Error(err) => bail!("want body, got asl error {err:?}"),
        AslResponse::HttpError(err) => bail!("want body, got http error {err:?}"),
        AslResponse::Unexpected((status, body)) => {
            bail!("want body, got unexpected error {status:?} {body}")
        }
    };

    // X-Forwarded-For (typical reverse proxy setting)
    let mut outer_headers = HeaderMap::new();
    outer_headers.insert("x-forwarded-for", token_ip.clone().try_into()?);

    let response = valid_asl_request(
        &tokens,
        &mut asl_session,
        target.clone(),
        &inner,
        Some(outer_headers),
    )
    .await?;

    match response {
        AslResponse::Body(body) => {
            let echo: Echo = serde_json::from_slice(&body)?;
            let forwarded = echo
                .headers
                .get("forwarded")
                .context("forwarded header missing from echo response")?;
            assert!(
                forwarded.contains(&expected),
                "expected {expected} in forwarded header, got: {forwarded}"
            );
        }
        AslResponse::Error(err) => bail!("want body, got asl error {err:?}"),
        AslResponse::HttpError(err) => bail!("want body, got http error {err:?}"),
        AslResponse::Unexpected((status, body)) => {
            bail!("want body, got unexpected error {status:?} {body}")
        }
    };

    // RFC 7239 Forwarded header with for=, host= matching the loopback so eigenurl stays the same
    let host_port = format!(
        "{}:{}",
        target.host_str().context("target host")?,
        target.port().context("target port")?
    );
    let mut outer_headers = HeaderMap::new();
    outer_headers.insert(
        "forwarded",
        HeaderValue::from_str(&format!("for={token_ip};host={host_port};proto=http"))?,
    );

    let response = valid_asl_request(
        &tokens,
        &mut asl_session,
        target.clone(),
        &inner,
        Some(outer_headers),
    )
    .await?;

    match response {
        AslResponse::Body(body) => {
            let echo: Echo = serde_json::from_slice(&body)?;
            let forwarded = echo
                .headers
                .get("forwarded")
                .context("forwarded header missing from echo response")?;
            assert!(
                forwarded.contains(&expected),
                "expected {expected} in forwarded header, got: {forwarded}"
            );
        }
        AslResponse::Error(err) => bail!("want body, got asl error {err:?}"),
        AslResponse::HttpError(err) => bail!("want body, got http error {err:?}"),
        AslResponse::Unexpected((status, body)) => {
            bail!("want body, got unexpected error {status:?} {body}")
        }
    };

    echo_server.abort();
    let _ = echo_server.await;
    Ok(())
}

#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn cid_expiry(
    #[future(awt)] context: &TestContext,
    #[future(awt)] nginx: NginxLease,
) -> Result<()> {
    nginx.wait_ready().await?;

    let target = nginx.url().await?;

    let tokens = context.tokens().await?;

    let mut asl_session = asl_handshake(&tokens, target.clone()).await?;

    let inner = encode_valid_http_request(
        &tokens,
        Method::GET,
        target.join("empty.json")?.as_str().parse()?,
        None,
    )?;

    let control_client = nginx.control_client().await?;

    // NOTE:
    // The removal of expired sessions is immediate, on access.
    //
    // In production, we also probabilistically clean up stale sessions that are not accessed (in 1%
    // of {start,continue}_session calls). This is done in a non-blocking way.
    //
    // During integration tests this auto-cleanup is *not* random — it is either never or always,
    // defaulting to never on startup, and blocking.
    //
    // The observable difference is subtle — the error message mentions "expired" in the on access
    // case, and "missing" in the auto-cleanup case, but it is enough to test both cases here.

    // expire cid and try otherwise valid request
    control_client
        .expire_cid(tarpc::context::current(), asl_session.cid.clone())
        .await??;

    let response =
        valid_asl_request(&tokens, &mut asl_session, target.clone(), &inner, None).await?;
    match response {
        AslResponse::Body(_) => {
            bail!("want Error, got Body");
        }
        AslResponse::Error(err) => {
            assert!(err.message_type == "Error");
            assert!(err.error_code == 102);
            // removal on access — clue "expired" in the message
            assert!(err.error_message == format!("internal error: expired — {}", asl_session.cid));
        }
        AslResponse::HttpError(err) => bail!("want asl error, got http error {err:?}"),
        AslResponse::Unexpected((status, body)) => {
            bail!("want asl error, got unexpected error {status:?} {body}")
        }
    };

    // expired cid should be removed now
    let response =
        valid_asl_request(&tokens, &mut asl_session, target.clone(), &inner, None).await?;

    match response {
        AslResponse::Body(_) => {
            bail!("want error, got body");
        }
        AslResponse::Error(err) => {
            assert!(err.message_type == "Error");
            assert!(err.error_code == 102);
            assert!(err.error_message == format!("internal error: missing — {}", asl_session.cid));
        }
        AslResponse::HttpError(err) => bail!("want asl error, got http error {err:?}"),
        AslResponse::Unexpected((status, body)) => {
            bail!("want asl error, got unexpected error {status:?} {body}")
        }
    };

    // now toggle always_expire…
    control_client
        .set_always_expire_cid(tarpc::context::current(), true)
        .await??;

    // …and acquire a new cid…
    let mut asl_session = asl_handshake(&tokens, target.clone()).await?;

    // …that expired.
    control_client
        .expire_cid(tarpc::context::current(), asl_session.cid.clone())
        .await??;

    let response =
        valid_asl_request(&tokens, &mut asl_session, target.clone(), &inner, None).await?;

    match response {
        AslResponse::Body(_) => {
            bail!("want error, got body");
        }
        AslResponse::Error(err) => {
            assert!(err.message_type == "Error");
            assert!(err.error_code == 102);
            // should be removed by cleanup_expired, not on access cleanup → we skip the "expired",
            // see above.
            assert!(err.error_message == format!("internal error: missing — {}", asl_session.cid));
        }
        AslResponse::HttpError(err) => bail!("want asl error, got http error {err:?}"),
        AslResponse::Unexpected((status, body)) => {
            bail!("want asl error, got unexpected error {status:?} {body}")
        }
    };

    Ok(())
}

#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn sid_expiry(
    #[future(awt)] context: &TestContext,
    #[future(awt)] nginx: NginxLease,
) -> Result<()> {
    nginx.wait_ready().await?;

    let target = nginx.url().await?.join("empty.json")?;
    let tokens = context.tokens().await?;

    let control_client = nginx.control_client().await?;

    // with a blocked session, request must be rejected

    control_client
        .block_sid(
            tarpc::context::current(),
            tokens.access_token_data.claims.sid.clone(),
            999,
        )
        .await??;

    let resp = tokens
        .valid_get(&context.jar, target.clone())?
        .send()
        .await?;

    assert!(resp.status() == 401);

    control_client
        .unblock_sid(
            tarpc::context::current(),
            tokens.access_token_data.claims.sid.clone(),
        )
        .await??;

    let resp = tokens
        .valid_get(&context.jar, target.clone())?
        .send()
        .await?;

    assert!(resp.status() == 200);

    // Test cleaning up expired blocks: first, block for 0s…
    control_client
        .block_sid(
            tarpc::context::current(),
            tokens.access_token_data.claims.sid.clone(),
            0,
        )
        .await??;

    // …and set always expire
    control_client
        .set_always_expire_sid(tarpc::context::current(), true)
        .await??;

    // This request will always go through (0s block duration)…
    let resp = tokens
        .valid_get(&context.jar, target.clone())?
        .send()
        .await?;
    assert!(resp.status() == 200);

    // …but the map entry should have been cleaned up as well
    let has_sid = control_client
        .has_sid(
            tarpc::context::current(),
            tokens.access_token_data.claims.sid.clone(),
        )
        .await??;
    assert!(!has_sid);

    Ok(())
}

#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn sending_and_receiving_blocks(
    #[future(awt)] context: &TestContext,
    #[future(awt)] nginx: NginxLease,
) -> Result<()> {
    nginx.wait_ready().await?;

    let target = nginx.url().await?.join("empty.json")?;
    let tokens = context.tokens().await?;

    let blocks = Arc::new(Mutex::new(vec![]));
    let subscriber = {
        let blocks = blocks.clone();
        tokio::spawn(async move {
            let resp = SHARED_CLIENT
                .get(nginx.revocation_url().await.expect("revocation_url"))
                .header(ACCEPT, "text/event-stream")
                .send()
                .await
                .expect("SSE response")
                .error_for_status()
                .expect("SSE stream");

            let mut stream = resp.bytes_stream();
            let mut buf: Vec<u8> = Vec::new();
            while let Some(chunk) = stream.next().await {
                buf.extend_from_slice(&chunk.expect("chunk"));
                while let Some(end) = buf.windows(2).position(|w| w == b"\n\n") {
                    let event: Vec<u8> = buf.drain(..end).collect();
                    buf.drain(..2); // the \n\n event delimiter
                    if let Some(block) = parse_event(&event).expect("block") {
                        blocks.lock().await.push(block);
                    }
                }
            }
        })
    };
    let blocks = blocks.clone();

    // request with expected ip (via forwarded, see valid_get)
    let resp = tokens
        .valid_get(&context.jar, target.clone())?
        .send()
        .await?;
    assert!(resp.status() == 200);
    // there should be no blocks
    assert!(blocks.lock().await.is_empty());

    // request with unexpected ip…
    let resp = tokens
        .request_builder(
            Method::GET,
            &context.jar,
            target.clone(),
            &tokens.valid_dpop_proof("GET", target.as_str())?,
            Some("1.2.3.4"),
        )?
        .send()
        .await?;
    // …triggering no-travel error…
    assert!(resp.status() == 401);
    let error: HttpZetaErrorResponse = resp.json().await?;
    assert!(error.error == "ImpossibleTravel");
    // …and broadcasting a new block, which our subscriber should (also) see.
    let sid = tokens.access_token_data.claims.sid.clone();
    tokio::time::timeout(Duration::from_secs(1), async move {
        loop {
            let seen = {
                let blocks = blocks.lock().await;
                (blocks.len() == 1).then(|| blocks.first().is_some_and(|b| b.what == sid))
            };
            match seen {
                Some(matches) => {
                    assert!(matches);
                    break;
                }
                None => tokio::time::sleep(Duration::from_millis(1)).await,
            }
        }
    })
    .await
    .context("timed out waiting for Block")?;

    // Now try to request again with the correct ip, this should trigger a 401,
    // eventually, because the sid has been blocked.

    let last_err = Rc::new(RefCell::new(None));
    let result = {
        let last_err = last_err.clone();

        tokio::time::timeout(Duration::from_secs(1), async move {
            loop {
                let last_err = last_err.clone();
                let tokens = tokens.clone();
                let target = target.clone();
                let assert = async move {
                    let resp = tokens
                        .valid_get(&context.jar, target.clone())?
                        .send()
                        .await?;
                    if resp.status() != 401 {
                        bail!("wrong status; want 401, got {}", resp.status());
                    }
                    let error: HttpZetaErrorResponse = resp.json().await?;
                    if error.error != "RevokedSession" {
                        bail!("wrong error; want RevokedSession, got {}", error.error);
                    }
                    anyhow::Ok(())
                };
                match assert.await {
                    Ok(()) => break,
                    Err(err) => {
                        last_err.borrow_mut().replace(err);
                    }
                }
            }
        })
        .await
    };
    if result.is_err() {
        bail!(
            "timed out waiting for blocked response, last_err={:#?}",
            last_err.borrow()
        );
    }

    subscriber.abort();
    Ok(())
}

#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn error_responses(
    #[future(awt)] context: &TestContext,
    #[future(awt)] nginx: NginxLease,
) -> Result<()> {
    nginx.wait_ready().await?;

    let echo_sever = nginx.start_echo_server().await;
    let target = nginx.url().await?.join("echo-with-popp/")?;

    let tokens = context.tokens().await?;

    // missing popp header, to get 400
    let resp = tokens
        .valid_get(&context.jar, target.clone())?
        .send()
        .await?;

    assert!(resp.status() == 400);
    assert!(
        resp.headers()
            .get("zeta-error-origin")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == "pep"),
        "pep-originated error must carry zeta-error-origin: pep"
    );
    assert!(
        resp.headers()
            .iter()
            .any(|(name, value)| *name == "content-type" && *value == "application/json")
    );
    let response_json: HttpZetaErrorResponse = resp.json().await?;
    assert!(response_json.error == "PoPPMissing");
    assert!(response_json.error_description == Some("PoPP header missing".to_string()));
    assert!(
        response_json.error_uri
            == Some(
                nginx
                    .url()
                    .await?
                    .join("/doc/errors/PoPPMissing.html")?
                    .into()
            )
    );

    // forwarded header must include "for": no-travel enforcement
    let forwarded = format!(
        "for=\"{}\";host=example.invalid",
        tokens.access_token_data.claims.ip_address
    );

    // uses Forwarded, X-Forwarded, or Host for error base uri
    for (header, value) in [
        ("forwarded", forwarded.as_str()),
        ("x-forwarded-host", "example.invalid"),
        ("host", "example.invalid"),
    ] {
        // need to crate dpop manually because of overriden host
        let dpop = create_dpop_proof(
            &context.registration,
            "GET",
            "http://example.invalid/echo-with-popp/",
            Some(&Base64UrlUnpadded::encode_string(&Sha256::digest(
                &tokens.access_token,
            ))),
            None,
        )?;
        let mut req = SHARED_CLIENT
            .get(target.clone())
            .bearer_auth(&tokens.access_token)
            .header("dpop", &dpop)
            .header(header, value);
        if header != "forwarded" {
            req = req.header(
                "forwarded",
                format!(
                    "for=\"{}\"",
                    tokens.access_token_data.claims.ip_address.clone()
                ),
            );
        }
        let resp = req.send().await?;

        let response_json: HttpZetaErrorResponse = resp.json().await?;
        assert!(
            response_json.error_uri
                == Some("http://example.invalid/doc/errors/PoPPMissing.html".parse()?)
        );
    }

    echo_sever.abort();
    let _ = echo_sever.await;

    Ok(())
}

/// Verify that nginx serves a TLS certificate obtained via the HSM proxy provider.
/// Connects to nginx over TLS, extracts the peer certificate, then fetches the same
/// key_id's certificate directly from hsm_sim and compares SPKI.
#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn hsm_proxy_tls(#[future(awt)] nginx: NginxLease) -> Result<()> {
    nginx.wait_ready().await?;

    // Build a client with tls_info enabled so we can extract the peer certificate
    let client = client_builder(true).tls_info(true).build()?;

    let tls_url = nginx.tls_url().await?.join("ready/")?;
    let resp = client.get(tls_url).send().await?;
    assert!(resp.status() == 200);

    let tls_info = resp
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .expect("tls_info missing — was .tls_info(true) set on the client?");

    let peer_cert_der = tls_info
        .peer_certificate()
        .expect("no peer certificate from TLS connection");
    let peer_cert = openssl::x509::X509::from_der(peer_cert_der)?;

    // Compare the SPKI (public key) from the TLS cert against what hsm_sim derives.
    // We can't compare full certs because ECDSA signatures are non-deterministic.
    let hsm_url = nginx.hsm_sim_url().await?;
    let mut hsm_client =
        hsm_sim::proto::hsm_proxy_service_client::HsmProxyServiceClient::connect(hsm_url).await?;

    let pub_resp = hsm_client
        .get_public_key(hsm_sim::proto::GetPublicKeyRequest {
            key_id: "tls.p256".to_string(),
        })
        .await?
        .into_inner();

    let peer_pubkey_der = peer_cert.public_key()?.public_key_to_der()?;
    assert!(
        peer_pubkey_der == pub_resp.public_key_der,
        "TLS peer cert SPKI does not match hsm_sim key for tls.p256"
    );

    Ok(())
}

/// Verify that the ASL handshake includes a valid OCSP response when the OCSP responder is running.
/// Starts the OCSP responder, performs an ASL handshake, and checks that M2's
/// SignedAslKeys contains a non-empty ocsp_response that decodes as a valid OCSP response.
#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn asl_ocsp_stapling(
    #[future(awt)] context: &TestContext,
    #[future(awt)] nginx: NginxLease,
) -> Result<()> {
    nginx.wait_ready().await?;

    let target = nginx.url().await?;
    let tokens = context.tokens().await?;

    // Handshake with OCSP capture — the verify callback extracts the OCSP response from M2
    let jar = Jar::default();
    let (_cid, _state, ocsp_response) = asl_handshake_with_ocsp(&tokens, jar, target).await?;

    assert!(
        ocsp_response.is_some(),
        "M2 SignedAslKeys did not contain an OCSP response — is the OCSP responder running?"
    );

    // Verify the OCSP response is well-formed
    let ocsp_bytes = ocsp_response.unwrap();
    let ocsp: x509_ocsp::OcspResponse =
        der::Decode::from_der(&ocsp_bytes).context("decode OCSP response from M2")?;
    assert!(
        ocsp.response_status == x509_ocsp::OcspResponseStatus::Successful,
        "OCSP response status: {:?}",
        ocsp.response_status
    );

    Ok(())
}

/// Verify that nginx does not expose its version in the Server header on error responses.
/// `server_tokens off` must be set in the http block.
#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn server_tokens_hidden(#[future(awt)] nginx: NginxLease) -> Result<()> {
    nginx.wait_ready().await?;

    // /doc/ has pep off and serves static files — requesting a non-existent path triggers a
    // native nginx 404 response whose Server header we can inspect.
    let target = nginx.url().await?.join("doc/nonexistent")?;
    let resp = SHARED_CLIENT.get(target).send().await?;
    assert!(resp.status() == 404);

    assert!(
        resp.headers()
            .get("server")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == "nginx"),
        "Server header must be 'nginx' without version (server_tokens off), got: {:?}",
        resp.headers().get("server")
    );

    Ok(())
}

/// A pep-protected proxy_pass location that omits `include proxy_headers.conf;` must be rejected
/// with 500 (ProxyHeadersMissing) instead of forwarding the client's credentials unstripped.
#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn proxy_headers_enforcement(
    #[future(awt)] context: &TestContext,
    #[future(awt)] nginx: NginxLease,
) -> Result<()> {
    nginx.wait_ready().await?;
    let _echo_server = nginx.start_echo_server().await;
    let target = nginx.url().await?.join("echo-no-headers/")?;

    let tokens = context.tokens().await?;
    let resp = tokens.valid_get(&context.jar, target)?.send().await?;

    assert!(resp.status() == 500, "want 500, got {}", resp.status());
    assert!(
        resp.headers()
            .get("zeta-error-origin")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == "pep"),
        "ProxyHeadersMissing error must carry zeta-error-origin: pep"
    );
    let error: HttpZetaErrorResponse = resp.json().await?;
    assert!(
        error.error == "ProxyHeadersMissing",
        "want ProxyHeadersMissing, got {}",
        error.error
    );

    Ok(())
}

/// ASL handler must not forward absolute inner requests (e.g. https://example.com or //example.com)
#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn asl_no_absolute_inner(
    #[future(awt)] context: &TestContext,
    #[future(awt)] nginx: NginxLease,
) -> Result<()> {
    nginx.wait_ready().await?;

    let target = nginx.url().await?;

    let tokens = context.tokens().await?;

    let mut asl_session = asl_handshake(&tokens, target.clone()).await?;

    for inner_url in [
        "https://example.com/",
        "https://example.com/path",
        "https://example.com/path/",
        "//example.com",
        "unix:/tmp",
        &target.as_str().replacen("http:", "file:/", 1),
        "http://127.0.0.1:1/",
        "http://localhost:1/",
    ] {
        let inner_dpop = tokens.valid_dpop_proof("GET", inner_url)?;

        // locally parse the test url to construct the host header
        let inner_url = Url::options().base_url(Some(&target)).parse(inner_url)?;
        let host_port = format!(
            "{}:{}",
            target.host_str().context("host_str")?,
            target
                .port_or_known_default()
                .context("port_or_known_default")?
        );
        let inner =
            format!("GET {inner_url} HTTP/1.1\r\nhost: {host_port}\r\ndpop: {inner_dpop}\r\n\r\n")
                .into_bytes();

        let response =
            valid_asl_request(&tokens, &mut asl_session, target.clone(), &inner, None).await?;

        match response {
            AslResponse::Body(_) => {
                bail!("want asl error, got body")
            }
            AslResponse::Error(err) => {
                assert!(err.error_code == 101);
                assert!(err.error_message.starts_with(&format!(
                    "bad request: error resolving request target: {inner_url} is not relative to"
                )));
            }
            AslResponse::HttpError(err) => bail!("want asl error, got http error {err:?}"),
            AslResponse::Unexpected((status, body)) => {
                bail!("want asl error, got unexpected error {status:?} {body}")
            }
        }
    }

    Ok(())
}
