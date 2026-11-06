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

//! Response interception: when an upstream response carries the header `zeta-cause: proxy`, strip
//! everything and replace with an anonymous `ZetaError::Proxy` response

use anyhow::anyhow;
use nginx_sys::{
    NGX_LOG_ERR, ngx_http_clean_header, ngx_http_request_t, ngx_http_top_header_filter, ngx_int_t,
};
use ngx::core::Status;
use ngx::http::Request;

use crate::error::ZetaError;
use crate::request_ops::RequestOps;
use crate::{ModuleCtx, ngx_log_error};

const ZETA_CAUSE: &str = "zeta-cause";
const PROXY: &str = "proxy";

static mut NEXT_HEADER_FILTER: nginx_sys::ngx_http_output_header_filter_pt = None;

/// Install the header filter. Must be called from `postconfiguration`, after the standard filter
/// modules.
pub unsafe fn install() {
    unsafe {
        NEXT_HEADER_FILTER = ngx_http_top_header_filter;
        ngx_http_top_header_filter = Some(header_filter);
    }
}

fn matches(name: &str, value: &str) -> bool {
    name.eq_ignore_ascii_case(ZETA_CAUSE) && value.trim().eq_ignore_ascii_case(PROXY)
}

fn has_zeta_cause_proxy(request: &Request) -> bool {
    request.headers_out_iterator().any(|(k, v)| {
        let (Ok(k), Ok(v)) = (k.to_str(), v.to_str()) else {
            return false;
        };
        matches(k, v)
    })
}

#[inline]
unsafe fn call_next(r: *mut ngx_http_request_t) -> ngx_int_t {
    unsafe {
        match NEXT_HEADER_FILTER {
            Some(next) => next(r),
            None => Status::NGX_ERROR.into(),
        }
    }
}

unsafe extern "C" fn header_filter(r: *mut ngx_http_request_t) -> ngx_int_t {
    let request = unsafe { Request::from_ngx_http_request(r) };
    let ctx = ModuleCtx::get(request);

    // Re-entrance: the send_header below re-enters this filter.
    // Pass through to the next filter to avoid looping.
    if ctx.zeta_cause_intercepted.get() {
        return unsafe { call_next(r) };
    }

    if !has_zeta_cause_proxy(request) {
        return unsafe { call_next(r) };
    }

    let status = unsafe { (*r).headers_out.status };
    ngx_log_error!(
        NGX_LOG_ERR,
        request.log(),
        "upstream signaled zeta-cause: proxy (upstream status: {status})"
    );

    let response = request
        .eigenurl_normalized()
        .and_then(|base| ZetaError::Proxy(anyhow!("zeta-cause: proxy")).response(base));

    let response = match response {
        Ok(r) => r,
        Err(e) => {
            ngx_log_error!(
                NGX_LOG_ERR,
                request.log(),
                "failed to build zeta-cause error response — {e:?}"
            );
            return Status::NGX_ERROR.into();
        }
    };

    ctx.zeta_cause_intercepted.set(true);

    // Wipe all upstream headers
    unsafe { ngx_http_clean_header(r) };

    // Send anonymous ZetaError::Proxy, don't finalize (this is not async, so finalize_request's
    // event indirection is not appropriate)
    response.send(request);

    // returning NGX_ERROR here leads to automatic finalization via:
    // ngx_http_upstream_send_response (https://github.com/nginx/nginx/blob/release-1.29.8/src/http/ngx_http_upstream.c#L3249)
    // → ngx_http_send_header
    // → ngx_http_top_header_filter
    // → this function
    // → ngx_http_upstream_finalize_request
    // → ngx_http_finalize_request
    Status::NGX_ERROR.into()
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn matches_canonical() {
        assert!(matches("zeta-cause", "proxy"));
    }

    #[test]
    fn matches_case_insensitive() {
        assert!(matches("Zeta-Cause", "Proxy"));
        assert!(matches("ZETA-CAUSE", "PROXY"));
    }

    #[test]
    fn matches_trims_whitespace_in_value() {
        assert!(matches("zeta-cause", "  proxy  "));
    }

    #[test]
    fn no_match_on_other_name() {
        assert!(!matches("x-cause", "proxy"));
    }

    #[test]
    fn no_match_on_other_value() {
        assert!(!matches("zeta-cause", "upstream"));
        assert!(!matches("zeta-cause", "proxy-something"));
    }
}
