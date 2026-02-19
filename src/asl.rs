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

use std::sync::LazyLock;
use std::sync::atomic::{AtomicPtr, Ordering};

use anyhow::{Result, anyhow, bail};
use asl::{Environment, decrypt_request, encrypt_response, finish_handshake, initiate_handshake};
use async_compat::Compat;
use http::Method;
use nginx_sys::{NGX_LOG_ERR, ngx_cycle};
use ngx::async_::spawn;
use ngx::core::Status;
use ngx::http::{HTTPStatus, HttpModuleLocationConf, HttpModuleMainConf, Request};
use ngx::{ngx_log_debug_http, ngx_log_error};
use reqwest::Url;

use crate::conf::MainConfig;
use crate::request_body::read_request_body;
use crate::request_ops::RequestOps;
use crate::response::{Body, Response, finalize_request};
use crate::session_cache::ShmSessionCache;
use crate::{CLIENT, Module, ModuleCtx, SELF_URL_CV};

/// see also: https://github.com/http-rs/async-h1/blob/main/src/lib.rs#L100
static MAX_HEADERS: usize = 128;

static SESSION_CACHE: LazyLock<ShmSessionCache> = LazyLock::new(|| {
    let main_conf: &mut MainConfig =
        unsafe { Module::main_conf_mut(&*ngx_cycle).expect("main_conf") };
    ShmSessionCache::new(unsafe { main_conf.shm_zone.as_mut().expect("as_mut") })
        .expect("ShmSessionCache")
});

static ERROR_RESPONSE: Response = Response {
    status: HTTPStatus::INTERNAL_SERVER_ERROR,
    content_type: None,
    body: Body(vec![]),
};

async fn handle_m1(request: &mut Request, body: &[u8]) -> Result<Response> {
    ngx_log_debug_http!(request, "asl: M1 read, {}b", body.len());

    if !request.acceptable("application/cbor")? {
        return Ok(Response::new(HTTPStatus(406)));
    }

    let (handshake_state, m2) = initiate_handshake(SESSION_CACHE.server_config(), body, &[])
        .map_err(|e| anyhow!("{e:?}"))?;
    let cid: String = SESSION_CACHE.init_handshake(handshake_state).await?;

    ngx_log_debug_http!(request, "asl: new cid {}, M2 {}b", cid, m2.len());
    request.ensure_header_out("ZETA-ASL-CID", &cid)?;

    Ok(Response::new_with_body(
        HTTPStatus::OK,
        "application/cbor",
        m2,
    ))
}

async fn handle_m3(request: &mut Request, cid: String, body: &[u8]) -> Result<Response> {
    ngx_log_debug_http!(request, "asl: M3 read, {}b", body.len());

    if !request.acceptable("application/cbor")? {
        return Ok(Response::new(HTTPStatus(406)));
    }

    let handshake_state = SESSION_CACHE.finish_handshake(&cid).await?;

    let (session, m4) = finish_handshake(SESSION_CACHE.server_config(), handshake_state, body)
        .map_err(|e| anyhow!("libasl — {e:?}"))?;

    SESSION_CACHE.start_session(&cid, session).await?;

    Ok(Response {
        status: HTTPStatus::OK,
        content_type: Some("application/cbor".to_string()),
        body: Body(m4),
    })
}

async fn handle_subrequest(request: &mut Request, cid: String, body: &[u8]) -> Result<Response> {
    ngx_log_debug_http!(request, "asl: data read, {}b", body.len());

    if !request.acceptable("application/octet-stream")? {
        return Ok(Response::new(HTTPStatus(406)));
    }

    let asl_config = SESSION_CACHE.server_config();

    if asl_config.env == Environment::Production
        && request.get_header_in("ZETA-ASL-nonPU-Tracing").is_some()
    {
        bail!("ZETA-ASL-nonPU-Tracing in Production");
    }

    let session = SESSION_CACHE.continue_session(&cid).await?;
    // TODO: validate ctr — how?
    let (ctr, inner) = decrypt_request(asl_config, &session, body)?;

    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut inner_request = httparse::Request::new(&mut headers);
    let status = inner_request.parse(&inner)?;
    if status.is_partial() {
        anyhow::bail!("partial request");
    }
    let header_len = status.unwrap();
    let body: Vec<u8> = inner[header_len..].into();

    let method = inner_request
        .method
        .ok_or_else(|| anyhow::anyhow!("missing method"))?;
    let path = inner_request
        .path
        .ok_or_else(|| anyhow::anyhow!("missing path"))?;

    let mut parsed_headers = Vec::new();
    for h in &mut *inner_request.headers {
        parsed_headers.push((
            String::from_utf8_lossy(h.name.as_bytes()).into_owned(),
            String::from_utf8_lossy(h.value).into_owned(),
        ));
    }

    let method = Method::from_bytes(method.as_bytes())?;
    let client = CLIENT.get().expect("reqwest client");

    let url = request
        .get_complex_value(unsafe { (&raw const SELF_URL_CV).as_ref().expect("SELF_URL_CV") })
        .expect("get_complex_value")
        .to_str()?;
    let url = Url::parse(url)?.join(path)?;
    let mut subrequest = client.request(method, url);

    for header in inner_request.headers.iter() {
        subrequest = subrequest.header(header.name, header.value);
    }

    let subresponse = subrequest.body(body).send().await?;
    let status = subresponse.status();

    let mut response_bytes = Vec::new();
    let status_code = status.as_u16();
    let reason = status.canonical_reason().unwrap_or("Unknown");

    // status
    response_bytes.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", status_code, reason).as_bytes());
    // headers
    for (name, value) in subresponse.headers().iter() {
        // bytes; not necessarily utf-8
        response_bytes.extend_from_slice(name.as_str().as_bytes());
        response_bytes.extend_from_slice(b": ");
        response_bytes.extend_from_slice(value.as_bytes());
        response_bytes.extend_from_slice(b"\r\n");
    }
    // end of headers
    response_bytes.extend_from_slice(b"\r\n");

    // body
    response_bytes.extend_from_slice(&subresponse.bytes().await?);

    let response = encrypt_response(
        SESSION_CACHE.server_config(),
        &session,
        ctr,
        &response_bytes,
    )?;

    // TODO: errors become application/cbor with a structure given in A_26924, and map http reponse
    // codes
    Ok(Response {
        status: HTTPStatus::OK,
        content_type: Some("application/octet-stream".to_string()),
        body: Body(response),
    })
}

async fn asl_handler(request: &mut Request) -> Result<Response> {
    if request.method() != "POST" {
        return Ok(Response::new(HTTPStatus::NOT_ALLOWED));
    }

    let path = request.path().to_string();
    let path = path.strip_suffix("/").unwrap_or(&path);

    let body = match read_request_body(request).await? {
        Ok(body) => body,
        Err(status) => {
            ngx_log_debug_http!(
                request,
                "asl: passing ngx_http_read_client_request_body status: {}",
                status.0
            );
            return Ok(Response::new(status));
        }
    };
    if body.is_empty() {
        bail!("empty body");
    }

    if path == "/ASL" {
        if request
            .get_header_in("content-type")
            .filter(|ct| *ct == "application/cbor")
            .is_none()
        {
            Ok(Response::new(HTTPStatus::UNSUPPORTED_MEDIA_TYPE))
        } else {
            handle_m1(request, &body).await
        }
    } else {
        match request.get_header_in("content-type") {
            Some("application/cbor") => handle_m3(request, path.to_string(), &body).await,
            Some("application/octet-stream") => {
                handle_subrequest(request, path.to_string(), &body).await
            }
            _ => Ok(Response::new(HTTPStatus::UNSUPPORTED_MEDIA_TYPE)),
        }
    }
}

pub fn handler(request: &mut Request) -> Status {
    let config = Module::location_conf(request).expect("location_config");

    match config.asl {
        Some(true) => {
            ngx_log_debug_http!(request, "asl: enter");

            let r_ptr = AtomicPtr::new(request.into());
            let task = spawn(Compat::new(async move {
                let r_ptr = r_ptr.load(Ordering::Relaxed);
                let request = unsafe { ngx::http::Request::from_ngx_http_request(r_ptr) };

                let response = asl_handler(request).await.unwrap_or_else(|e| {
                    ngx_log_error!(NGX_LOG_ERR, request.log(), "asl: error — {e:?}");
                    ERROR_RESPONSE.clone()
                });

                if let Err(e) = response.send(request) {
                    ngx_log_error!(NGX_LOG_ERR, request.log(), "error sending response — {e}");
                };
                finalize_request(request, Status::NGX_DONE.0);
            }));

            ModuleCtx::insert_asl_task(request, task);

            Status::NGX_AGAIN
        }
        _ => Status::NGX_DECLINED,
    }
}
