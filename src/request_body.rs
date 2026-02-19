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
use std::task::{Poll, Waker};

use anyhow::Result;
use futures::future::try_join_all;
use nginx_sys::{
    NGX_HTTP_SPECIAL_RESPONSE, ngx_http_finalize_request,
    ngx_http_read_client_request_body, ngx_http_request_t,
};
use ngx::core::Status;
use ngx::http::{HTTPStatus, Request};

use crate::ModuleCtx;
use crate::buffer::Buffer;

pub async fn read_request_body(
    request: &mut Request,
) -> Result<std::result::Result<Vec<u8>, HTTPStatus>> {
    let bufs = match read_client_request_body(request) {
        Ok(bufs) => bufs,
        Err(status) => return Ok(Err(status)),
    }
    .await;

    let body = try_join_all(bufs.iter().map(|buf| buf.read()))
        .await
        .map(|chunks| {
            let total: usize = chunks.iter().map(|c| c.len()).sum();
            let mut out = Vec::with_capacity(total);
            for c in chunks {
                out.extend_from_slice(&c);
            }
            out
        })?;

    Ok(Ok(body))
}

fn read_client_request_body<'a>(
    request: &'a mut Request,
) -> std::result::Result<RequestBodyRead<'a>, HTTPStatus> {
    let rc = unsafe {
        ngx_http_read_client_request_body(request.into(), Some(client_request_body_handler))
    };

    if rc >= NGX_HTTP_SPECIAL_RESPONSE.try_into().unwrap() {
        Err(HTTPStatus(rc.try_into().unwrap()))
    } else {
        Ok(RequestBodyRead { request })
    }
}

#[derive(Default, Debug)]
pub struct RequestBody {
    bufs: RefCell<Option<Vec<Buffer>>>,
    waker: RefCell<Option<Waker>>,
}

#[derive(Debug)]
pub struct RequestBodyRead<'a> {
    request: &'a Request,
}

impl Future for RequestBodyRead<'_> {
    type Output = Vec<Buffer>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let ctx = ModuleCtx::get(this.request);
        match ctx.body.bufs.borrow_mut().take() {
            Some(bufs) => Poll::Ready(bufs),
            None => {
                let mut waker = ctx.body.waker.borrow_mut();

                match &mut *waker {
                    Some(w) => w.clone_from(cx.waker()),
                    none @ None => *none = Some(cx.waker().clone()),
                }
                Poll::Pending
            }
        }
    }
}

extern "C" fn client_request_body_handler(request: *mut ngx_http_request_t) {
    let request_body = unsafe { *(*request).request_body };

    let ctx = ModuleCtx::get(unsafe { Request::from_ngx_http_request(request) });

    let mut bufs: Vec<Buffer> = Vec::new();
    if !request_body.bufs.is_null() {
        let mut chain = unsafe { *request_body.bufs };

        loop {
            let buf = unsafe { *chain.buf };
            bufs.push(Buffer(buf));
            if chain.next.is_null() {
                break;
            }
            chain = unsafe { *chain.next };
        }
    }

    *ctx.body.bufs.borrow_mut() = Some(bufs);

    if let Some(waker) = ctx.body.waker.borrow_mut().take() {
        waker.wake();
    }
    unsafe {
        // dec request count bumped by ngx_http_read_client_request_body
        ngx_http_finalize_request(request, Status::NGX_OK.0);
    }
}
