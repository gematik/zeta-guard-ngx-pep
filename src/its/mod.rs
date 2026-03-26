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

use std::path::Path;
use std::process;

use futures::StreamExt;
use tarpc::ServerError;
use tarpc::context::Context;
use tarpc::server::{self, Channel};
use tokio_serde::formats::Json;

use crate::asl::SESSION_CACHE;
use crate::{log_debug, spawn_compat};

#[tarpc::service]
pub trait TestControl {
    async fn set_always_expire(value: bool) -> std::result::Result<(), ServerError>;
    async fn expire_cid(cid: String) -> std::result::Result<(), ServerError>;
}

#[derive(Clone)]
struct TestControlServer;

impl TestControl for TestControlServer {
    async fn set_always_expire(
        self,
        _: Context,
        value: bool,
    ) -> std::result::Result<(), ServerError> {
        SESSION_CACHE.set_always_expire(value);
        Ok(())
    }

    async fn expire_cid(self, _: Context, cid: String) -> std::result::Result<(), ServerError> {
        SESSION_CACHE
            .expire_cid(&cid)
            .await
            .map_err(|e| ServerError::new(std::io::ErrorKind::Other, e.to_string()))
    }
}

pub fn start(control_path: &Path) {
    let sock = control_path.join(format!("{}.sock", process::id()));

    spawn_compat(async move {
        log_debug!("its: binding {}", sock.display());

        // Try to bind — if another worker already owns the socket, silently skip.
        let listener = std::os::unix::net::UnixListener::bind(&sock)
            .unwrap_or_else(|_| panic!("bind {}", sock.display()));
        listener.set_nonblocking(true).expect("set_nonblocking");
        let listener = tokio::net::UnixListener::from_std(listener).expect("from_std");
        let incoming = tarpc::serde_transport::unix::listen_on(listener, Json::default)
            .await
            .expect("listen_on");
        incoming
            .filter_map(|r| async { r.ok() })
            .map(server::BaseChannel::with_defaults)
            .for_each(|channel| async move {
                let server = TestControlServer;
                spawn_compat(channel.execute(server.serve()).for_each(spawn_compat)).detach();
            })
            .await;
    })
    .detach();
}
