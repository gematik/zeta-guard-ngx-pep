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

//! Read-only peek at the built-in `ngx_http_proxy_module`'s per-location config, so the PEP can
//! verify at request time that a proxied location actually pulled in `proxy_headers.conf` (the
//! file that strips client credentials before `proxy_pass`). See [`pep_headers_applied`] and
//! [`crate::error::ZetaError::ProxyHeadersMissing`].
//!
//! We chose config (`proxy_set_header`) over in-module list surgery for the credential strip
//! because the strip must run at upstream-request-build time — after the access phase and after
//! any internal-redirect re-runs — which only `proxy_pass`'s own header phase satisfies. The
//! cost is `proxy_set_header`'s non-additive inheritance: a location-level `proxy_set_header`
//! silently drops the inherited strips. This check turns that silent leak into a hard 500 by
//! looking for a sentinel header in the location's *compiled* proxy header set — so it tracks
//! the strips exactly (same inheritance domain), unlike a rewrite-phase `set $var` flag.
//!
//! The struct layout comes from bindgen over `ngx_http_proxy_module.h` (see `build.rs`); every
//! field type is reused from `nginx_sys`, so the embedded `ngx_http_upstream_conf_t` (which
//! fixes the offset of `headers`) has whatever layout nginx-sys derived from the same source
//! tree. A field/layout change on an nginx bump fails this file's compile, not at runtime.

mod bindings {
    #![allow(non_camel_case_types, non_upper_case_globals, dead_code)]
    use nginx_sys::*;
    include!(concat!(env!("OUT_DIR"), "/proxy_bindings.rs"));
}

use nginx_sys::{ngx_hash_find, ngx_http_request_t, ngx_uint_t};

use bindings::{ngx_http_proxy_loc_conf_t, ngx_http_proxy_module};

/// The empty-valued `proxy_set_header` sentinel defined in `proxy_headers.conf`. Lowercase: the
/// proxy header hash is keyed case-folded (see how `ngx_http_proxy_create_request` looks up with
/// `lowcase_key`), and a lowercase literal lets us match byte-for-byte regardless of stored case.
const SENTINEL: &[u8] = b"x-zeta-headers-applied";

/// nginx's `ngx_hash_key_lc`: the case-folded rolling hash (`key = key * 31 + tolower(c)`) used
/// to index header hashes. Must match nginx exactly or the bucket lookup misses.
fn hash_key_lc(name: &[u8]) -> ngx_uint_t {
    name.iter().fold(0_usize, |key, &c| {
        key.wrapping_mul(31)
            .wrapping_add(c.to_ascii_lowercase() as usize)
    })
}

/// Whether the request's matched location pulled in `proxy_headers.conf`.
///
/// * `None` — not a `proxy_pass` location, so the check does not apply.
/// * `Some(true)` — the sentinel is present in the compiled proxy header set: the strips are live.
/// * `Some(false)` — a proxied location whose proxy headers were never set or were clobbered by a
///   location-level `proxy_set_header`; forwarding here would leak the credentials the PEP strips.
///
/// # Safety
/// `r` must point to a valid request for the current request cycle.
pub unsafe fn pep_headers_applied(r: *const ngx_http_request_t) -> Option<bool> {
    unsafe {
        // proxy module's per-location config for this request (allocated for every location)
        let plcf =
            *(*r).loc_conf.add(ngx_http_proxy_module.ctx_index) as *const ngx_http_proxy_loc_conf_t;
        if plcf.is_null() {
            return None;
        }

        // Only enforce where the proxy module actually forwards: a static `proxy_pass <url>` sets
        // `url`; a variable one (`proxy_pass http://$x`) compiles into `proxy_lengths`.
        let proxies = (*plcf).url.len != 0 || !(*plcf).proxy_lengths.is_null();
        if !proxies {
            return None;
        }

        let found = ngx_hash_find(
            &(*plcf).headers.hash as *const _ as *mut _,
            hash_key_lc(SENTINEL),
            SENTINEL.as_ptr() as *mut _,
            SENTINEL.len(),
        );
        Some(!found.is_null())
    }
}
