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

use std::ptr::{self, copy_nonoverlapping};

use anyhow::{Result, bail};
use nginx_sys::{NGX_LOG_ERR, ngx_buf_t, ngx_chain_t, ngx_http_output_filter};
use ngx::core::Status;
use ngx::http::{HTTPStatus, Request};
use ngx::ngx_log_error;
use ngx_tickle::finalize_request;

use crate::request_ops::RequestOps;

#[derive(Debug, Default, Clone)]
pub struct Body(pub Vec<u8>);

impl Body {
    fn send(&self, request: &mut Request) -> Result<()> {
        unsafe {
            let content_length = self.len();
            if content_length > 0 {
                let buf: *mut ngx_buf_t = request.pool().calloc_type();
                if buf.is_null() {
                    bail!("null buffer");
                }
                (*buf).set_memory(1);
                (*buf).set_last_buf(if request.is_main() { 1 } else { 0 });
                (*buf).set_last_in_chain(1);

                // TODO: make libasl allocator-aware, or take a buf to write to (form request pool),
                // so we don't have to copy here
                let data_ptr = request.pool().calloc(content_length) as *mut u8;
                if data_ptr.is_null() {
                    bail!("null body buffer");
                }
                copy_nonoverlapping(self.0.as_ptr(), data_ptr, content_length);
                (*buf).start = data_ptr;
                (*buf).end = (*buf).start.add(content_length);
                (*buf).pos = (*buf).start;
                (*buf).last = (*buf).end;

                let mut chain = ngx_chain_t {
                    buf,
                    next: ptr::null_mut(),
                };

                let rc = ngx_http_output_filter(request.into(), &mut chain);

                if rc != 0 {
                    bail!("ngx_http_output_filter rc={rc}");
                }
            } else {
                let buf: *mut ngx_buf_t = request.pool().calloc_type();

                // sync-only
                (*buf).set_sync(1);
                (*buf).set_last_buf(if request.is_main() { 1 } else { 0 });
                (*buf).set_last_in_chain(1);

                let mut chain = ngx_chain_t {
                    buf,
                    next: ptr::null_mut(),
                };

                let rc = ngx_http_output_filter(request.into(), &mut chain);

                if rc != 0 {
                    bail!("ngx_http_output_filter rc={rc}");
                }
            };
            Ok(())
        }
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Clone)]
pub struct Response {
    pub status: HTTPStatus,
    pub content_type: Option<String>,
    pub body: Body,
}
impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("body", &format!("({} bytes)", self.body.0.len()))
            .finish()
    }
}

impl Response {
    pub fn new(status: HTTPStatus) -> Self {
        Response {
            status,
            content_type: None,
            body: Body::default(),
        }
    }

    pub fn new_with_body(status: HTTPStatus, content_type: &str, body: Vec<u8>) -> Self {
        Response {
            status,
            content_type: Some(content_type.to_string()),
            body: Body(body),
        }
    }

    pub fn send(&self, request: &mut Request, finalization_status: Status) {
        request.set_status(self.status);

        let content_length = self.body.len();
        request.set_content_length_n(content_length);
        if content_length > 0
            && let Some(content_type) = &self.content_type
            && let Err(e) = request.ensure_header_out("content-type", content_type)
        {
            ngx_log_error!(
                NGX_LOG_ERR,
                request.log(),
                "error setting content-type: {content_type} — {e}"
            );
            finalize_request(request, Status::NGX_ERROR);
        };

        let rc = request.send_header();
        if !rc.is_ok() {
            ngx_log_error!(NGX_LOG_ERR, request.log(), "error sending header — {rc:?}");
            finalize_request(request, rc);
        }
        let rc = self.body.send(request);

        finalize_request(
            request,
            match rc {
                Ok(()) => finalization_status,
                Err(e) => {
                    ngx_log_error!(NGX_LOG_ERR, request.log(), "error sending response — {e}");
                    Status::NGX_ERROR
                }
            },
        );
    }
}
