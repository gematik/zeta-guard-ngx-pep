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
use base64ct::{Base64Unpadded, Base64UrlUnpadded, Encoding};
use http::Method;
use jsonwebtoken::get_current_timestamp;
use ngx_pep::client::asl::{asl_handshake, asl_request, encode_http_request};
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
use crate::common::typify::{ClientInstance, UserInfo};

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
        Some(Base64UrlUnpadded::encode_string(&Sha256::digest(
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
        Some(Base64UrlUnpadded::encode_string(&Sha256::digest(
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
        Some(Base64UrlUnpadded::encode_string(&Sha256::digest(
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

    assert!(resp.status() == 401);

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

    assert!(resp.status() == 401);

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
    let user_info: String =
        Base64Unpadded::decode_vec(&echo.headers["zeta-user-info"])?.try_into()?;
    let user_info: UserInfo = serde_json::from_str(&user_info)?;

    let (cert, _key) = read_smcb_p12(&context.it_p12(), &context.it_p12_pass()).await?;
    let admission = admission_from_x509(&cert)?;
    let profession_info = admission.single_profession_info()?;
    assert!(Some(user_info.identifier.clone()) == profession_info.registration_number()?);

    let cert_profession_oids: Option<Vec<String>> = profession_info
        .profession_oids
        .as_ref()
        .map(|oids| oids.iter().map(|oid| oid.to_string()).collect());
    assert!(Some(vec![user_info.profession_oid.clone()]) == cert_profession_oids);

    assert!(user_info.mail.is_none()); // TODO

    let client_data: String =
        Base64Unpadded::decode_vec(&echo.headers["zeta-client-data"])?.try_into()?;
    let client_data: ClientInstance = serde_json::from_str(&client_data)?;

    // fields are mostly just copied from our client data, just check that the client_id matches
    // for now
    match client_data {
        ClientInstance::Variant0 { client_id, .. }
        | ClientInstance::Variant1 { client_id, .. }
        | ClientInstance::Variant2 { client_id, .. }
        | ClientInstance::Variant3 { client_id, .. } => {
            assert!(client_id == context.registration.client_id)
        }
    };

    let popp_token: String =
        Base64Unpadded::decode_vec(&echo.headers["zeta-popp-token-content"])?.try_into()?;
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
        Some(Base64UrlUnpadded::encode_string(&Sha256::digest(
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
    )?;

    let body = asl_request(
        &context.registration,
        context.client.clone(),
        &access_token,
        target.clone(),
        &cid,
        &mut state,
        0,
        &inner,
    )
    .await?;

    let result: Value = serde_json::from_slice(&body)?;
    // empty.json is {}
    assert!(result == json!({}));

    Ok(())
}
