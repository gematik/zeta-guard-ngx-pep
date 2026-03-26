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

use std::collections::HashMap;

use anyhow::{Result, bail};
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use http::{HeaderMap, HeaderValue, Method, Uri};
use jsonwebtoken::get_current_timestamp;
use ngx_pep::client::asl::{
    AslResponse, asl_handshake, asl_request, asl_request_with_dpop, encode_http_request,
    encode_http_request_with_dpop,
};
use rstest::rstest;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use ngx_pep::client::{
    admission_from_x509, create_dpop_proof, create_popp_token, get_with_dpop, read_smcb_p12,
    test_popp_token_payload,
};
mod common;
use common::{NginxLease, TestContext, context, nginx};

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
    let access_token = context.access_token().await?;

    let resp = get_with_dpop(
        &context.registration,
        context.client.clone(),
        &access_token,
        target.clone(),
    )?
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
    let resp = context.client.get(target.clone()).send().await?;
    assert!(resp.status() == 401);

    // zeta-api-version also for 401s
    assert!(
        resp.headers()
            .get("zeta-api-version")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == env!("CARGO_PKG_VERSION"))
    );

    // missing access token
    let dpop = create_dpop_proof(
        &context.registration,
        "GET",
        target.as_str(),
        Some(&Base64UrlUnpadded::encode_string(&Sha256::digest(
            &access_token,
        ))),
        None,
    )?;
    let resp = context
        .client
        .get(target.clone())
        .header("dpop", &dpop)
        .send()
        .await?;
    assert!(resp.status() == 401);

    // missing dpop proof
    let resp = context
        .client
        .get(target.clone())
        .bearer_auth(&access_token)
        .send()
        .await?;
    assert!(resp.status() == 401);

    // incorrect dpop proof
    let incorrect_dpop = create_dpop_proof(
        &context.registration,
        "POST",
        target.as_str(),
        Some(&Base64UrlUnpadded::encode_string(&Sha256::digest(
            &access_token,
        ))),
        None,
    )?;
    let resp = context
        .client
        .get(target.clone())
        .bearer_auth(&access_token)
        .header("dpop", &incorrect_dpop)
        .send()
        .await?;
    assert!(resp.status() == 401);

    let incorrect_dpop_ath = create_dpop_proof(
        &context.registration,
        "GET",
        target.as_str(),
        Some(&Base64UrlUnpadded::encode_string(&Sha256::digest(
            "invalid_ath",
        ))),
        None,
    )?;
    let resp = context
        .client
        .get(target.clone())
        .bearer_auth(&access_token)
        .header("dpop", &incorrect_dpop_ath)
        .send()
        .await?;
    assert!(resp.status() == 401);

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

    let access_token = context.access_token().await?;

    // missing popp header
    let resp = get_with_dpop(
        &context.registration,
        context.client.clone(),
        &access_token,
        target.clone(),
    )?
    .send()
    .await?;

    assert!(resp.status() == 403);

    // invalid popp header
    let resp = get_with_dpop(
        &context.registration,
        context.client.clone(),
        &access_token,
        target.clone(),
    )?
    .header("popp", "garbage")
    .send()
    .await?;

    assert!(resp.status() == 403);

    // valid

    let popp_p12 = context.popp_p12()?;
    let popp_p12_pass = context.popp_p12_pass()?;
    let popp_p12_alias = context.popp_p12_alias()?;
    let now = get_current_timestamp();
    let iat = now;
    let proof_time = now - 10;
    let popp =
        create_popp_token(&popp_p12, &popp_p12_pass, &popp_p12_alias, iat, proof_time).await?;

    let resp = get_with_dpop(
        &context.registration,
        context.client.clone(),
        &access_token,
        target.clone(),
    )?
    .header("popp", &popp)
    .send()
    .await?;

    assert!(resp.status() == 200);

    let echo: Echo = resp.json().await?;

    // test headers passed to upstream
    let user_info: String = Base64::decode_vec(&echo.headers["zeta-user-info"])?.try_into()?;
    let user_info: ZetaUserInfo = serde_json::from_str(&user_info)?;

    let (cert, _key) = read_smcb_p12(&context.it_p12(), &context.it_p12_pass()).await?;
    let admission = admission_from_x509(&cert)?;
    let profession_info = admission.single_profession_info()?;
    assert!(Some(user_info.identifier.clone()) == profession_info.registration_number()?);

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
    let popp_token: Value = serde_json::from_str(&popp_token)?;
    let expected_popp_token = test_popp_token_payload(iat, proof_time);
    assert!(popp_token == expected_popp_token);

    echo_sever.abort();
    let _ = echo_sever.await;

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

    let access_token = context.access_token().await?;
    let dpop = create_dpop_proof(
        &context.registration,
        "GET",
        target,
        Some(&Base64UrlUnpadded::encode_string(&Sha256::digest(
            &access_token,
        ))),
        None,
    )?;

    let resp = ws_request(target.parse()?, &access_token, &dpop, 42u8).await?;
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

    let access_token = context.access_token().await?;

    let (cid, mut state) = asl_handshake(
        context.client.clone(),
        &context.registration,
        target.clone(),
        &access_token,
    )
    .await?;

    let inner = encode_http_request(
        &context.registration,
        Method::GET,
        target.join("empty.json")?.as_str().parse()?,
        &access_token,
        None,
    )?;

    let response = asl_request(
        &context.registration,
        context.client.clone(),
        &access_token,
        target.clone(),
        &cid,
        &mut state,
        0,
        &inner,
        None,
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
    }

    let inner_invalid = [0u8; 1];
    let response = asl_request(
        &context.registration,
        context.client.clone(),
        &access_token,
        target.clone(),
        &cid,
        &mut state,
        1,
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
    }

    let inner_invalid = [0u8; 0];
    let response = asl_request(
        &context.registration,
        context.client.clone(),
        &access_token,
        target.clone(),
        &cid,
        &mut state,
        1,
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
    };

    // access phase errors on /ASL/<cid> lead to application/json errors, not application/cbor

    let inner = encode_http_request(
        &context.registration,
        Method::GET,
        target.join("empty.json")?.as_str().parse()?,
        &access_token,
        None,
    )?;

    let response = asl_request(
        &context.registration,
        context.client.clone(),
        &"invalid",
        target.clone(),
        &cid,
        &mut state,
        0,
        &inner,
        None,
    )
    .await?;

    match response {
        AslResponse::Body(_) => bail!("want error, got body"),
        AslResponse::Error(err) => bail!("want body, got asl error {err:?}"),
        AslResponse::HttpError(err) => {
            assert!(err.error == "Internal");
            assert!(
                err.error_description
                    == Some("internal error: while decoding authorization token header".into())
            );
        }
    }

    // access phase errors in the inner request lead to error in asl_request helper

    let inner = encode_http_request(
        &context.registration,
        Method::GET,
        target.join("empty.json")?.as_str().parse()?,
        "invalid",
        None,
    )?;

    let response = asl_request(
        &context.registration,
        context.client.clone(),
        &access_token,
        target.clone(),
        &cid,
        &mut state,
        0,
        &inner,
        None,
    )
    .await;
    assert!(response.is_err_and(|e| e.to_string() == "inner status: 500 Internal Server Error"));

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

    let access_token = context.access_token().await?;

    let (cid, mut state) = asl_handshake(
        context.client.clone(),
        &context.registration,
        target.clone(),
        &access_token,
    )
    .await?;

    fn encoded_inner(target_uri: Uri, access_token: &str, dpop: String) -> Result<Vec<u8>> {
        let mut inner_headers = HashMap::new();
        // any inner {x-,}forwarded{,-*} header should still be tolerated, but ignored
        inner_headers.insert("X-Forwarded-For", "something");
        inner_headers.insert("X-Forwarded-Host", "anotherthing");
        inner_headers.insert("X-Forwarded-Proto", "https");
        inner_headers.insert("X-Forwarded-Port", "123");
        inner_headers.insert("Forwarded", "host=somehost;proto=https");
        encode_http_request_with_dpop(target_uri, access_token, dpop, Some(inner_headers))
    }

    let url = target.join("empty.json")?;
    let url = url.as_str();
    let ath = Base64UrlUnpadded::encode_string(&Sha256::digest(&access_token));

    // No outer {x-,}forwarded{,-*}
    let dpop = create_dpop_proof(&context.registration, "GET", url, Some(&ath), None)?;
    let inner = encoded_inner(url.parse()?, &access_token, dpop)?;

    let response = asl_request(
        &context.registration,
        context.client.clone(),
        &access_token,
        target.clone(),
        &cid,
        &mut state,
        0,
        &inner,
        None,
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
    };

    // outer x-forwarded-*
    let url = "https://forwarded.invalid:4444/empty.json";
    let inner_dpop = create_dpop_proof(&context.registration, "GET", url, Some(&ath), None)?;
    let inner = encoded_inner(url.parse()?, &access_token, inner_dpop)?;

    let mut outer_headers = HeaderMap::new();
    // ignored for the purposes of eigenuri, but is commonly set by proxies
    outer_headers.insert("x-forwarded-for", HeaderValue::from_str("client")?);
    outer_headers.insert("x-forwarded-proto", HeaderValue::from_str("https")?);
    outer_headers.insert(
        "x-forwarded-host",
        HeaderValue::from_str("forwarded.invalid")?,
    );
    // header names case insensitive
    outer_headers.insert("X-Forwarded-Port", HeaderValue::from_str("4444")?);
    let outer_dpop = create_dpop_proof(
        &context.registration,
        "POST",
        &format!("https://forwarded.invalid:4444{cid}"),
        Some(&ath),
        None,
    )?;

    let response = asl_request_with_dpop(
        &outer_dpop,
        context.client.clone(),
        &access_token,
        target.clone(),
        &cid,
        &mut state,
        0,
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
    };

    // outer with both forwarded and x-forwarded-* — forwarded takes precedence (see
    // `RequestOps::eigenuri_parts`)
    let url = "https://forwarded.invalid:4444/empty.json";
    let inner_dpop = create_dpop_proof(&context.registration, "GET", url, Some(&ath), None)?;
    let inner = encoded_inner(url.parse()?, &access_token, inner_dpop)?;

    let mut outer_headers = HeaderMap::new();

    outer_headers.insert(
        "forwarded",
        HeaderValue::from_str("by=forwarder;for=client;host=forwarded.invalid:4444;proto=https")?,
    );
    // these should be ignored due to the presence of forwarded:
    outer_headers.insert("x-forwarded-for", HeaderValue::from_str("x-client")?);
    outer_headers.insert("x-forwarded-proto", HeaderValue::from_str("x-https")?);
    outer_headers.insert(
        "x-forwarded-host",
        HeaderValue::from_str("x-forwarded.invalid")?,
    );
    outer_headers.insert("x-forwarded-port", HeaderValue::from_str("5555")?);

    let outer_dpop = create_dpop_proof(
        &context.registration,
        "POST",
        &format!("https://forwarded.invalid:4444{cid}"),
        Some(&ath),
        None,
    )?;

    let response = asl_request_with_dpop(
        &outer_dpop,
        context.client.clone(),
        &access_token,
        target.clone(),
        &cid,
        &mut state,
        0,
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
    };

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

    let access_token = context.access_token().await?;

    let (cid, mut state) = asl_handshake(
        context.client.clone(),
        &context.registration,
        target.clone(),
        &access_token,
    )
    .await?;

    let inner = encode_http_request(
        &context.registration,
        Method::GET,
        target.join("empty.json")?.as_str().parse()?,
        &access_token,
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
        .expire_cid(tarpc::context::current(), cid.clone())
        .await??;

    let response = asl_request(
        &context.registration,
        context.client.clone(),
        &access_token,
        target.clone(),
        &cid,
        &mut state,
        0,
        &inner,
        None,
    )
    .await?;
    match response {
        AslResponse::Body(_) => {
            bail!("want Error, got Body");
        }
        AslResponse::Error(err) => {
            assert!(err.message_type == "Error");
            assert!(err.error_code == 102);
            // removal on access — clue "expired" in the message
            assert!(err.error_message == format!("internal error: expired — {cid}"));
        }
        AslResponse::HttpError(err) => bail!("want asl error, got http error {err:?}"),
    };

    // expired cid should be removed now
    let response = asl_request(
        &context.registration,
        context.client.clone(),
        &access_token,
        target.clone(),
        &cid,
        &mut state,
        0,
        &inner,
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
            assert!(err.error_message == format!("internal error: missing — {cid}"));
        }
        AslResponse::HttpError(err) => bail!("want asl error, got http error {err:?}"),
    };

    // now toggle always_expire…
    control_client
        .set_always_expire(tarpc::context::current(), true)
        .await??;

    // …and acquire a new cid…
    let (cid, mut state) = asl_handshake(
        context.client.clone(),
        &context.registration,
        target.clone(),
        &access_token,
    )
    .await?;

    // …that expired.
    control_client
        .expire_cid(tarpc::context::current(), cid.clone())
        .await??;

    let response = asl_request(
        &context.registration,
        context.client.clone(),
        &access_token,
        target.clone(),
        &cid,
        &mut state,
        0,
        &inner,
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
            // should be removed by cleanup_expired, not on access cleanup → we skip the "expired",
            // see above.
            assert!(err.error_message == format!("internal error: missing — {cid}"));
        }
        AslResponse::HttpError(err) => bail!("want asl error, got http error {err:?}"),
    };

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

    let access_token = context.access_token().await?;

    // missing popp header, to get 403
    let resp = get_with_dpop(
        &context.registration,
        context.client.clone(),
        &access_token,
        target.clone(),
    )?
    .send()
    .await?;

    assert!(resp.status() == 403);
    assert!(
        resp.headers()
            .iter()
            .any(|(name, value)| *name == "content-type" && *value == "application/json")
    );
    let response_json: HttpZetaErrorResponse = resp.json().await?;
    assert!(response_json.error == "PoPP");
    assert!(response_json.error_description == Some("PoPP error: missing PoPP header".to_string()));
    assert!(
        response_json.error_uri == Some(nginx.url().await?.join("/doc/errors/PoPP.html")?.into())
    );

    // uses Forwarded, X-Forwarded, or Host for error base uri
    for (header, value) in [
        ("forwarded", "host=example.invalid"),
        ("x-forwarded-host", "example.invalid"),
        ("host", "example.invalid"),
    ] {
        // need to crate dpop manually because of overriden host
        let dpop = create_dpop_proof(
            &context.registration,
            "GET",
            "http://example.invalid/echo-with-popp/",
            Some(&Base64UrlUnpadded::encode_string(&Sha256::digest(
                &access_token,
            ))),
            None,
        )?;
        let resp = context
            .client
            .clone()
            .get(target.clone())
            .bearer_auth(&access_token)
            .header("dpop", &dpop)
            .header(header, value)
            .send()
            .await?;

        let response_json: HttpZetaErrorResponse = resp.json().await?;
        assert!(
            response_json.error_uri == Some("http://example.invalid/doc/errors/PoPP.html".parse()?)
        );
    }

    echo_sever.abort();
    let _ = echo_sever.await;

    Ok(())
}
