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

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::LazyLock;

use anyhow::Result;
use bytes::Bytes;
use futures::StreamExt;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, header};
use hyper_util::rt::TokioIo;
use jsonwebtoken::dangerous::insecure_decode;
use jsonwebtoken::{TokenData, get_current_timestamp};
use serde::Serialize;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::sync::broadcast::{self, Sender};
use tokio_stream::wrappers::BroadcastStream;

use ngx_pep::block_list::Block;

type Body = UnsyncBoxBody<Bytes, Infallible>;
static LIST: LazyLock<RwLock<BTreeSet<ServerBlock>>> = LazyLock::new(Default::default);

#[derive(Clone, Serialize)]
struct ServerBlock(Block);

impl ServerBlock {
    fn key(&self) -> (u64, &str) {
        (self.0.until, self.0.what.as_str())
    }
}

impl PartialEq for ServerBlock {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key()
    }
}
impl Eq for ServerBlock {}

impl Ord for ServerBlock {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key().cmp(&other.key())
    }
}
impl PartialOrd for ServerBlock {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

fn sse(data: &ServerBlock) -> Frame<Bytes> {
    let data = serde_json::to_string(data).unwrap();
    Frame::data(Bytes::from(format!("data: {data}\n\n")))
}

async fn subscribe(tx: Sender<ServerBlock>) -> Response<Body> {
    let rx = tx.subscribe();
    let snapshot: Vec<_> = LIST.read().await.iter().cloned().collect();

    let head = futures::stream::iter(snapshot.into_iter().map(|s| Ok::<_, Infallible>(sse(&s))));
    let tail = BroadcastStream::new(rx)
        .filter_map(|r| async move { r.ok() })
        .map(|s| Ok::<_, Infallible>(sse(&s)));
    let body = StreamBody::new(head.chain(tail)).boxed_unsync();

    Response::builder()
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(body)
        .unwrap()
}

async fn publish(req: Request<Incoming>, tx: Sender<ServerBlock>) -> Response<Body> {
    let is_text = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/plain"));
    if !is_text {
        return text(StatusCode::UNSUPPORTED_MEDIA_TYPE, "expected text/plain\n");
    }

    let bytes = req.into_body().collect().await.unwrap().to_bytes();

    let token: TokenData<Value> = insecure_decode(&bytes).unwrap();
    let when = get_current_timestamp();
    let until = token.claims.get("exp").unwrap().as_u64().unwrap();
    let what = token
        .claims
        .get("sid")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let block = ServerBlock(Block { when, until, what });

    let inserted = LIST.write().await.insert(block.clone());
    if inserted {
        let _ = tx.send(block);
    }

    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Full::new(Bytes::new()).boxed_unsync())
        .unwrap()
}

fn text(status: StatusCode, body: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Full::new(Bytes::from_static(body.as_bytes())).boxed_unsync())
        .unwrap()
}

async fn handle(
    req: Request<Incoming>,
    tx: Sender<ServerBlock>,
) -> Result<Response<Body>, Infallible> {
    Ok(match *req.method() {
        Method::GET => subscribe(tx).await,
        Method::POST => publish(req, tx).await,
        _ => text(
            StatusCode::METHOD_NOT_ALLOWED,
            "GET to subscribe, POST to publish\n",
        ),
    })
}

pub async fn revocation_server(port: u16) -> Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let (tx, _keepalive) = broadcast::channel(256);
    let listener = TcpListener::bind(&addr).await?;
    eprintln!(
        "[revocation_server] listening on {}",
        listener.local_addr()?
    );

    loop {
        let (sock, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[revocation_server] accept error: {e}");
                continue;
            }
        };
        let tx = tx.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| handle(req, tx.clone()));
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(sock), svc)
                .await
            {
                eprintln!("[revocation_server] connection error: {e}");
            }
        });
    }
}
