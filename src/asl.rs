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
use std::sync::{LazyLock, OnceLock};

use anyhow::{Context, Result, anyhow, bail};
use asl::{
    AslError, Environment, SESSION_OVERHEAD, decrypt_request, encrypt_response, finish_handshake,
    initiate_handshake,
};
use async_compat::CompatExt;
use http::Method;
use nginx_sys::ngx_cycle;
use ngx::core::Status;
use ngx::http::{HTTPStatus, HttpModuleLocationConf, HttpModuleMainConf, Request};
use ngx_tickle::RequestSpawn;
use reqwest::{Client, Url};
use tracing::{Instrument, debug, error, instrument};

use crate::capec::asl_capec;
use crate::conf::MainConfig;
use crate::error::{ToHttpResponse, ZetaAslResult};
use crate::headers::pep_forwarded_element;
use crate::ocsp_cache::ocsp_cache;
use crate::otel::{request_span, traced_outbound, traced_request};
use crate::request_body::read_request_body;
use crate::request_ops::RequestOps;
use crate::response::{Body, Response};
use crate::session_cache::ShmSessionCache;
use crate::{Module, ModuleCtx, SELF_URL_CV};

/// see also: https://github.com/http-rs/async-h1/blob/main/src/lib.rs#L100
static MAX_HEADERS: usize = 128;

pub(crate) static SESSION_CACHE: LazyLock<ShmSessionCache> = LazyLock::new(|| {
    let main_conf: &mut MainConfig =
        unsafe { Module::main_conf_mut(&*ngx_cycle).expect("main_conf") };
    ShmSessionCache::new(unsafe { main_conf.session_cache_zone.as_mut().expect("as_mut") })
        .expect("ShmSessionCache")
});

// we can't format the error as application/cbor when that is not acceptable → text/plain
static UNACCEPTABLE: LazyLock<Response> = LazyLock::new(|| {
    Response::new_with_body(
        HTTPStatus(406),
        "text/plain",
        "Not Acceptable: application/cbor".as_bytes().to_vec(),
    )
});

#[instrument(skip(request), fields(body=body.len()), err)]
async fn handle_m1(request: &mut Request, body: &[u8]) -> ZetaAslResult<Response> {
    ModuleCtx::set_is_asl(request, "handle_m1");

    if !request.acceptable("application/cbor")? {
        return Ok(UNACCEPTABLE.clone());
    }

    let ocsp_response = ocsp_cache().get_ocsp().await;

    let (handshake_state, m2) = initiate_handshake(
        SESSION_CACHE.server_config(),
        body,
        ocsp_response.as_deref(),
    )?;
    let cid: String = SESSION_CACHE.init_handshake(handshake_state).await?;

    request.ensure_header_out("ZETA-ASL-CID", &cid)?;
    debug!(cid, "new cid=\"{cid}\"");

    Ok(Response::new_with_body(
        HTTPStatus::OK,
        "application/cbor",
        m2,
    ))
}

#[instrument(skip(request), fields(body=body.len()), err)]
async fn handle_m3(request: &mut Request, cid: String, body: &[u8]) -> ZetaAslResult<Response> {
    ModuleCtx::set_is_asl(request, "handle_m3");

    if !request.acceptable("application/cbor")? {
        return Ok(UNACCEPTABLE.clone());
    }

    let handshake_state = SESSION_CACHE.finish_handshake(&cid).await?;

    let (session, m4) = finish_handshake(SESSION_CACHE.server_config(), handshake_state, body)?;

    SESSION_CACHE.start_session(&cid, session).await?;

    Ok(Response::new_with_body(
        HTTPStatus::OK,
        "application/cbor",
        m4,
    ))
}

// Resolve an inner request target against this PEP's own listener (base).
// Only origin-form (RFC 9112 §3.2.1: absolute-path [ "?" query ]) is accepted, and the resolved
// URL must keep the base's scheme, userinfo, host and port. The resolved URL is used as-is: it is
// never turned back into a relative reference and re-parsed — that round trip let a target like
// "/http://internal:9090/secret" resolve to http://internal:9090/secret.
fn join_path(base: Url, target: &str) -> Result<Url> {
    if !target.starts_with('/') || target.starts_with("//") {
        bail!("{target} is not in origin-form");
    }
    let url = base.join(target).context("parse error")?;
    // WHATWG parsing treats e.g. "/\host" or "/\t/host" as scheme-relative for http(s), which the
    // prefix check above can't see; the resolved authority must still be the base's.
    if url.scheme() != base.scheme()
        || url.username() != base.username()
        || url.password() != base.password()
        || url.host() != base.host()
        || url.port_or_known_default() != base.port_or_known_default()
    {
        bail!("{url} is not relative to {base}");
    }
    Ok(url)
}

// initialized in ngx_http_pep_init_worker, after fork
pub static ASL_CLIENT: OnceLock<Client> = OnceLock::new();

#[instrument(skip(request), fields(body=body.len()), err)]
async fn handle_subrequest(
    request: &mut Request,
    cid: String,
    body: &[u8],
) -> ZetaAslResult<Response> {
    ModuleCtx::set_is_asl(request, "handle_subrequest");

    if !request.acceptable("application/octet-stream")? {
        return Ok(UNACCEPTABLE.clone());
    }

    let asl_config = SESSION_CACHE.server_config();

    if asl_config.env == Environment::Production
        && request.get_header_in("ZETA-ASL-nonPU-Tracing").is_some()
    {
        return Err(AslError::IllegalTracing);
    }

    let session = SESSION_CACHE.continue_session(&cid).await?;
    // Check before sizing the buffer: a body shorter than the overhead would underflow here,
    // long before decrypt_request gets to reject it.
    let inner_len = body
        .len()
        .checked_sub(SESSION_OVERHEAD)
        .ok_or(AslError::BadFormat)?;
    let mut inner = ngx::collections::Vec::with_capacity_in(inner_len, request.pool());
    inner.resize(inner_len, 0u8);
    let ctr = decrypt_request(asl_config, &session, body, &mut inner)?;

    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut inner_request = httparse::Request::new(&mut headers);
    let status = inner_request
        .parse(&inner)
        .context("unparseable inner request")?;
    if status.is_partial() {
        return Err(AslError::BadRequest(anyhow!("partial request")));
    }
    let header_len = status.unwrap();
    let body: Vec<u8> = inner[header_len..].into();

    let method = inner_request
        .method
        .ok_or_else(|| AslError::BadRequest(anyhow!("missing method")))?;
    let path = inner_request
        .path
        .ok_or_else(|| AslError::BadRequest(anyhow!("missing path")))?;

    let method = Method::from_bytes(method.as_bytes())
        .context("unparseable method")
        .map_err(AslError::BadRequest)?;
    let client = ASL_CLIENT
        .get()
        .ok_or_else(|| anyhow!("ASL_CLIENT not initialized"))?;

    let url = request
        .get_complex_value(unsafe { (&raw const SELF_URL_CV).as_ref().unwrap() })
        .context("SELF_URL_CV as_ref")?
        .to_str()
        .context("SELF_URL_CV: invalid utf-8")?;
    let url = join_path(Url::parse(url).context("unparseable base url")?, path)
        .map_err(|err| AslError::BadRequest(anyhow!("error resolving request target: {err}")))?;

    let (mut subrequest, span) = traced_outbound!(client, method, url, "inner_request");

    for header in inner_request.headers.iter() {
        match header.name.to_lowercase().as_str() {
            "forwarded" | "x-forwarded-for" | "x-forwarded-proto" | "x-forwarded-host"
            | "x-forwarded-port" => {}
            // A_25669-01: never forward client-supplied ZETA-* headers that the PEP controls; the
            // PEP is their sole source.
            "zeta-user-info"
            | "zeta-client-data"
            | "zeta-popp-token-content"
            | "zeta-access-token-content"
            | "zeta-api-version" => {}
            // Strip any traceparent/tracestate the client baked into the
            // encrypted inner request — we want our handle_subrequest span to
            // be the parent on the loopback hop, not whatever the client set.
            "traceparent" | "tracestate" => {}
            // The client-chosen inner Host must not steer the loopback hop (e.g. nginx builds a
            // directory redirect's Location from it); it is pinned to the outer Host below.
            "host" => {}
            _ => subrequest = subrequest.header(header.name, header.value),
        };
    }

    // The outer Host already selected this server block, so the inner request lands on the same
    // one. Without an outer Host, reqwest derives it from the loopback URL.
    if let Some(host) = request.get_header_in("host") {
        subrequest = subrequest.header("host", host);
    }

    // A_28439: emit this PEP's RFC 7239 Forwarded element.
    let forwarded = {
        let (scheme, host, port) = request.eigenurl_parts()?;
        let authority = match port {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        let client_ip = request.get_client_ip().map(str::to_string);
        pep_forwarded_element(scheme, &authority, client_ip.as_deref())
    };

    subrequest = subrequest.header("forwarded", forwarded);
    subrequest = subrequest.body(body);

    let (status, headers, bytes) = traced_request(subrequest, span)
        .await
        .context("inner request failed")?;

    let mut response_bytes = ngx::collections::Vec::new_in(request.pool());
    let status_code = status.as_u16();
    let reason = status.canonical_reason().unwrap_or("Unknown");

    // status
    response_bytes.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", status_code, reason).as_bytes());
    // headers
    for (name, value) in headers.iter() {
        // bytes; not necessarily utf-8
        response_bytes.extend_from_slice(name.as_str().as_bytes());
        response_bytes.extend_from_slice(b": ");
        response_bytes.extend_from_slice(value.as_bytes());
        response_bytes.extend_from_slice(b"\r\n");
    }
    // end of headers
    response_bytes.extend_from_slice(b"\r\n");

    // body
    response_bytes.extend_from_slice(&bytes);

    let enc_len = response_bytes.len() + SESSION_OVERHEAD;
    let enc_ptr = request.pool().calloc(enc_len) as *mut u8;
    if enc_ptr.is_null() {
        return Err(AslError::InternalError(anyhow!("pool alloc failed")));
    }
    let enc_buf = unsafe { std::slice::from_raw_parts_mut(enc_ptr, enc_len) };
    encrypt_response(
        SESSION_CACHE.server_config(),
        &session,
        ctr,
        &response_bytes,
        enc_buf,
    )?;

    Ok(Response {
        status: HTTPStatus::OK,
        content_type: Some("application/octet-stream".to_string()),
        body: unsafe { Body::from_pool(enc_ptr, enc_len) },
        extra_headers: HashMap::new(),
    })
}

#[instrument(skip(request), err)]
fn handle_cert_data(request: &mut Request, path: String) -> ZetaAslResult<Response> {
    if request.method() != "GET" {
        return Ok(Response::new(HTTPStatus::NOT_ALLOWED));
    }

    let config = SESSION_CACHE.server_config();
    if !path.ends_with(&config.signed_keys.version()) {
        return Ok(Response::new(HTTPStatus::NOT_FOUND));
    }

    let cert_data = config.cert_data.to_vec()?;

    Ok(Response {
        status: HTTPStatus::OK,
        content_type: Some("application/cbor".to_string()),
        body: Body::Heap(cert_data),
        extra_headers: HashMap::new(),
    })
}

#[instrument(skip(request), err)]
async fn asl_handler(request: &mut Request) -> ZetaAslResult<Response> {
    let path = request.path().to_string();
    let path = path.strip_suffix("/").unwrap_or(&path);

    if path.starts_with("/CertData.") {
        return handle_cert_data(request, path.to_string());
    }
    if request.method() != "POST" {
        return Ok(Response::new(HTTPStatus::NOT_ALLOWED));
    }

    let body = match read_request_body(request).await? {
        Ok(body) => body,
        Err(status) => {
            error!(status=%status.0, "client body read failed");
            return Ok(Response::new(status));
        }
    };
    if body.is_empty() {
        return Err(AslError::BadRequest(anyhow!("empty body")));
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

    if config.asl != Some(true) {
        return Status::NGX_DECLINED;
    }

    // Content phase: when the access phase opened an upstream span for this
    // request, nest under it — that unifies pep- and asl-side spans into one
    // trace even without nginx-otel or an inbound traceparent. Otherwise
    // resolve the inbound parent as usual (request_span! also picks kind).
    let span = match ModuleCtx::upstream_otel_context(request) {
        Some(parent) => {
            let _attached = opentelemetry::Context::attach(parent);
            tracing::info_span!("asl::request", otel.kind = "internal",)
        }
        None => request_span!("asl::request", request),
    };

    if let Err(err) = request.spawn(async move |request| {
        async move {
            let response = asl_handler(request).await.inspect_err(|err| {
                if let Some(capec) = asl_capec(err) {
                    let capec_id = capec.id();
                    let capec_name = capec.name();
                    let detail = tracing::field::display(&err);
                    let origin = "pep";
                    let client_ip = request.get_client_ip();
                    // Set by the access phase when `pep on` validated a token for this request.
                    let user_roles = ModuleCtx::user_role(request).as_str();
                    error!(
                        attackDetection.capecId=%capec_id,
                        attackDetection.capecName=%capec_name,
                        attackDetection.detail=detail,
                        attackDetection.origin=origin,
                        attackDetection.clientIP=client_ip,
                        user.roles=user_roles,
                        "possible attack detected: {err}"
                    );
                }
            });

            match response {
                Ok(response) => {
                    response.finalize(request, Status::NGX_OK);
                    Status::NGX_OK
                }
                Err(err) => {
                    match request
                        .eigenurl_normalized()
                        .and_then(|base| Ok(err.to_http_response(base)?))
                    {
                        Ok(error_response) => {
                            error_response.finalize(request, Status::NGX_ERROR);
                            Status::NGX_ERROR
                        }
                        Err(err) => {
                            error!(%err, "error building error response");
                            HTTPStatus::INTERNAL_SERVER_ERROR.into()
                        }
                    }
                }
            }
        }
        .compat()
        .instrument(span)
        .await;
    }) {
        error!(%err, "spawn error");
        return Status::NGX_ERROR;
    }

    Status::NGX_AGAIN
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use reqwest::Url;

    use crate::asl::join_path;

    // same shape as SELF_URL_CV
    fn base() -> Url {
        Url::parse("http://127.0.0.1:8003").expect("base url")
    }

    #[test]
    fn join_path_accepts_origin_form() -> Result<()> {
        for (target, want) in [
            ("/", "http://127.0.0.1:8003/"),
            ("/abs", "http://127.0.0.1:8003/abs"),
            ("/abs?q=1&r=/x", "http://127.0.0.1:8003/abs?q=1&r=/x"),
            ("/a/../b", "http://127.0.0.1:8003/b"),
        ] {
            assert_eq!(join_path(base(), target)?.as_str(), want, "{target}");
        }
        Ok(())
    }

    /// A target whose path looks like an absolute URL must stay on the base: it used to be
    /// resolved, made relative again ("http://internal:9090/secret") and re-joined into an
    /// absolute URL pointing at the host named in the path.
    #[test]
    fn join_path_absolute_url_in_path_stays_local() -> Result<()> {
        for (target, want) in [
            (
                "/http://internal:9090/secret",
                "http://127.0.0.1:8003/http://internal:9090/secret",
            ),
            (
                "/https://internal:9090/secret",
                "http://127.0.0.1:8003/https://internal:9090/secret",
            ),
            (
                "/https:evil.example/",
                "http://127.0.0.1:8003/https:evil.example/",
            ),
            (
                "/http:/internal/x",
                "http://127.0.0.1:8003/http:/internal/x",
            ),
            (
                "/file:///etc/passwd",
                "http://127.0.0.1:8003/file:///etc/passwd",
            ),
        ] {
            let url = join_path(base(), target)?;
            assert_eq!(url.as_str(), want, "{target}");
            assert_eq!(url.host_str(), Some("127.0.0.1"), "{target}");
            assert_eq!(url.port(), Some(8003), "{target}");
        }
        Ok(())
    }

    #[test]
    fn join_path_rejects_non_origin_form() {
        for target in [
            "",
            "rel",
            "*",
            "https://example.com",
            "http://127.0.0.1:8003/",
            "//example.com",
            "//127.0.0.1:8003/",
            "\\\\unc\\le",
            "file://localhost:8003/file",
            "unix:/tmp",
            // WHATWG: a backslash counts as a slash for http(s), tab/newline are stripped
            "/\\evil.example/",
            "/\t/evil.example/",
            "/\n/evil.example/",
            // same host and port, but userinfo
            "/\\user:pass@127.0.0.1:8003/",
        ] {
            assert!(
                join_path(base(), target).is_err(),
                "{target:?} → {:?}",
                join_path(base(), target)
            );
        }
    }
}
