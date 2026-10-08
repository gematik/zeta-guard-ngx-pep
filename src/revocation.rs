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

use std::str;
use std::time::Duration;

use anyhow::Result;
use futures::StreamExt;
use nginx_sys::ngx_worker;
use reqwest::Url;
use reqwest::header::ACCEPT;
use tokio::time::error::Elapsed;
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};

use crate::block_list::Block;
use crate::conf::MainConfig;
use crate::pep::BLOCK_LIST;
use crate::spawn_compat;

const RECONNECT_MIN: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(30);

/// Bounds request-sent → response-headers-received. The client's
/// `connect_timeout` only covers TCP and TLS, and the stream deliberately has no
/// overall timeout, so a peer that accepts the connection and then withholds the
/// headers would park this task forever with nothing logged. A buffering reverse
/// proxy does exactly that (nginx `postpone_output` holds the head of the output
/// chain until 1460 bytes accumulate, which a trickle of SSE events never reaches).
const HEADERS_TIMEOUT: Duration = Duration::from_secs(15);

pub fn init(conf: &MainConfig) {
    // One subscription per process, not per worker: the block list lives in the
    // shared zone, so every worker reads what this one writes. Subscribing in each
    // worker multiplies snapshots, heartbeats and Keycloak-side sinks/listeners by
    // the worker count. A respawned worker 0 re-subscribes, and the snapshot it
    // gets on connect re-syncs anything the zone missed while it was gone.
    // `ngx_worker` is 0 both for the first worker and in single-process mode.
    if unsafe { ngx_worker } != 0 {
        return;
    }

    let Some(url) = conf.revocation_url.clone() else {
        warn!("pep_revocation_url not set; revocation stream disabled");
        return;
    };

    // Dedicated client: NO overall `.timeout()` (that would abort the long-lived
    // stream); connect timeout + keepalive only.
    let client = match reqwest::ClientBuilder::new()
        .user_agent(concat!("ZETA Guard PEP/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(conf.http_client_connect_timeout)
        .tcp_keepalive(Duration::from_secs(30))
        .use_rustls_tls()
        .danger_accept_invalid_certs(conf.http_client_accept_invalid_certs)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "failed to build revocation stream client");
            return;
        }
    };

    spawn_compat(worker(client, url)).detach();
}

async fn worker(client: reqwest::Client, url: Url) {
    let mut backoff = RECONNECT_MIN;
    loop {
        match stream_once(&client, url.clone()).await {
            Ok(()) => {
                debug!("revocation stream closed; reconnecting");
                backoff = RECONNECT_MIN;
            }
            Err(e) if e.downcast_ref::<Elapsed>().is_some() => {
                error!(url = %url, timeout = ?HEADERS_TIMEOUT, "no response headers from revocation stream; reconnecting");
                backoff = (backoff * 2).min(RECONNECT_MAX);
            }
            Err(e) => {
                warn!(error = %e, "revocation stream error; reconnecting");
                backoff = (backoff * 2).min(RECONNECT_MAX);
            }
        }
        sleep(backoff).await;
    }
}

async fn stream_once(client: &reqwest::Client, url: Url) -> Result<()> {
    let request = client
        .get(url.clone())
        .header(ACCEPT, "text/event-stream")
        .send();
    let resp = timeout(HEADERS_TIMEOUT, request)
        .await??
        .error_for_status()?;

    info!(url = %url, status = %resp.status(), "revocation stream connected");

    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        buf.extend_from_slice(&chunk?);
        while let Some(end) = buf.windows(2).position(|w| w == b"\n\n") {
            let event: Vec<u8> = buf.drain(..end).collect();
            buf.drain(..2); // the \n\n event delimiter
            apply_event(&event);
        }
    }
    Ok(())
}

pub fn parse_event(event: &[u8]) -> Result<Option<Block>> {
    let text = str::from_utf8(event)?;
    let mut data = String::new();
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(rest) = line.strip_prefix("data:") {
            let rest = rest.strip_prefix(' ').unwrap_or(rest);
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(rest);
        }
    }
    if data.is_empty() {
        return Ok(None);
    }
    let block = serde_json::from_str(&data)?;
    Ok(Some(block))
}

fn apply_event(event: &[u8]) {
    match parse_event(event) {
        Err(err) => warn!(error = %err, "malformed revocation event"),
        Ok(Some(block)) => {
            if let Err(err) = BLOCK_LIST.apply(&block) {
                warn!(error = %err, "failed to apply revocation");
            }
        }
        Ok(None) => {}
    }
}
