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
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use http::header::{AUTHORIZATION, HOST, UPGRADE};
use http::{HeaderValue, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, lookup_host};
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Echo {
    pub method: String,
    pub uri: String,
    pub headers: HashMap<String, String>,
}

fn echo_response(req: &Request<hyper::body::Incoming>) -> Result<Echo> {
    let mut headers = HashMap::new();
    for (h, v) in req.headers() {
        headers.insert(h.to_string(), v.to_str()?.to_string());
    }
    Ok(Echo {
        method: req.method().to_string(),
        uri: req.uri().to_string(),
        headers,
    })
}

// echo protocol (server-side): rx 1 u8 → tx 1 u8 → close
async fn echo_ws_io(upgraded: Upgraded) -> Result<()> {
    let mut upgraded = TokioIo::new(upgraded);
    let mut buf = vec![0; 1];
    upgraded.read_exact(&mut buf).await?;

    upgraded.write_all(&buf).await?;
    Ok(())
}

// echo protocol (client-side): tx 1 u8 → rx 1 u8 → close
async fn echo_ws_client_io(upgraded: Upgraded, msg: u8) -> Result<u8> {
    let buf = msg.to_le_bytes();
    let mut upgraded = TokioIo::new(upgraded);
    upgraded.write_all(&buf).await?;

    let mut buf = Vec::new();
    upgraded.read_to_end(&mut buf).await?;
    assert!(buf.len() == 1);
    let response: u8 = u8::from_le(buf[0]);

    Ok(response)
}

// handshake → exchange msg → close
pub async fn ws_request(uri: Uri, auth: &str, dpop: &str, msg: u8) -> Result<u8> {
    let host = uri.host().context("host")?;
    let port = uri.port_u16().context("port")?;
    let hostport = format!("{host}:{port}");
    let paq = uri.path_and_query().map(|paq| paq.as_str()).unwrap_or("/");

    let req = Request::builder()
        .header(HOST, &hostport)
        .uri(paq)
        .header(UPGRADE, "echo")
        .header(AUTHORIZATION, format!("Bearer {auth}"))
        .header("dpop", dpop)
        .body(Empty::<Bytes>::new())?;

    let addr = lookup_host(&hostport)
        .await?
        .take(1)
        .last()
        .context("lookup_host addr")?;

    let stream = TcpStream::connect(addr).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;

    tokio::task::spawn(async move {
        if let Err(err) = conn.with_upgrades().await {
            eprintln!("with_upgrades: {:?}", err);
        }
    });

    let res = sender.send_request(req).await?;

    if res.status() != StatusCode::SWITCHING_PROTOCOLS {
        panic!("server didn't upgrade: {}", res.status());
    }

    timeout(Duration::from_secs(1), async move {
        match hyper::upgrade::on(res).await {
            Ok(upgraded) => echo_ws_client_io(upgraded, msg).await,
            Err(e) => bail!("client: {e:?}"),
        }
    })
    .await?
}

async fn echo_service(
    mut req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/ready/") => {
            let mut response = Response::new(empty());
            *response.status_mut() = StatusCode::OK;
            Ok(response)
        }
        (&Method::GET, "/") => {
            let response = echo_response(&req)?;
            let response = serde_json::to_string_pretty(&response)?;
            Ok(Response::new(full(response)))
        }
        (&Method::GET, "/ws/") => {
            tokio::task::spawn(async move {
                match hyper::upgrade::on(&mut req).await {
                    Ok(upgraded) => {
                        if let Err(e) = echo_ws_io(upgraded).await {
                            eprintln!("echo_ws_io error: {e:?}")
                        };
                    }
                    Err(e) => eprintln!("upgrade error: {e:?}"),
                }
            });
            let mut response = Response::new(empty());
            *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
            response
                .headers_mut()
                // willing to upgrade to the "echo" protocol, defined above
                .insert(UPGRADE, HeaderValue::from_static("echo"));
            Ok(response)
        }
        _ => {
            let mut not_found = Response::new(empty());
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

pub async fn echo_server(port: u16) -> Result<()> {
    let addr = SocketAddr::from(([127, 1, 33, 7], port));

    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;

        let io = TokioIo::new(stream);

        tokio::task::spawn(async move {
            let conn = http1::Builder::new()
                .serve_connection(io, service_fn(echo_service))
                .with_upgrades();

            if let Err(err) = conn.await {
                eprintln!("serve_connection: {err:?}");
            }
        });
    }
}
