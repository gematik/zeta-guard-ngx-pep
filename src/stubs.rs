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

#![allow(non_upper_case_globals)]
#![allow(unused_variables)]

use std::ffi::{c_char, c_int, c_uint, c_ulong, c_void};
use std::ptr;

use nginx_sys::{
    ngx_chain_t, ngx_conf_t, ngx_http_client_body_handler_pt, ngx_http_compile_complex_value_t,
    ngx_http_complex_value_t, ngx_http_request_t, ngx_int_t, ngx_pool_t, ngx_rbtree_node_t,
    ngx_rbtree_t, ngx_shm_zone_t, ngx_shmtx_t, ngx_slab_pool_t, ngx_str_t,
};

#[unsafe(no_mangle)]
pub static mut ngx_cycle: *mut c_void = std::ptr::null_mut();

#[unsafe(no_mangle)]
pub static mut ngx_http_module: *mut c_void = std::ptr::null_mut();

#[unsafe(no_mangle)]
pub static mut ngx_http_core_module: *mut c_void = std::ptr::null_mut();

#[unsafe(no_mangle)]
pub static mut ngx_posted_events: *mut c_void = std::ptr::null_mut();

#[unsafe(no_mangle)]
pub static mut ngx_event_timer_rbtree: *mut c_void = std::ptr::null_mut();

#[unsafe(no_mangle)]
pub static mut ngx_event_actions: *mut c_void = std::ptr::null_mut();

#[unsafe(no_mangle)]
pub static mut ngx_process: c_int = 0;

#[unsafe(no_mangle)]
pub static mut ngx_thread_tid: c_int = 0;

#[unsafe(no_mangle)]
pub static mut ngx_current_msec: c_ulong = 0;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_log_error_core(
    _level: c_int,
    _log: *mut c_void,
    _err: c_int,
    _fmt: *const c_char,
    // _args: ..., — c_variadic is an unstable feature — we just need the symbol anyway
) {
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_conf_log_error(
    _level: c_int,
    _cf: *mut c_void,
    _err: c_int,
    _fmt: *const c_char,
    // _args: ..., — c_variadic is an unstable feature — we just need the symbol anyway
) {
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_array_push(_a: *mut c_void) -> *mut c_void {
    std::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_pool_cleanup_add(_p: *mut c_void, _size: usize) -> *mut c_void {
    std::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_palloc(_pool: *mut c_void, _size: usize) -> *mut c_void {
    std::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_pnalloc(_pool: *mut c_void, _size: usize) -> *mut c_void {
    std::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_list_push(_l: *mut c_void) -> *mut c_void {
    std::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_hash_strlow(_dst: *mut u8, _src: *mut u8, _n: usize) -> c_uint {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_post_event(_ev: *mut c_void, _queue: *mut c_void) {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_rbtree_insert(_tree: *mut c_void, _node: *mut c_void) {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_rbtree_delete(_tree: *mut c_void, _node: *mut c_void) {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_http_output_filter(
    r: *mut ngx_http_request_t,
    chain: *mut ngx_chain_t,
) -> ngx_int_t {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_http_read_client_request_body(
    r: *mut ngx_http_request_t,
    post_handler: ngx_http_client_body_handler_pt,
) -> ngx_int_t {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_http_finalize_request(r: *mut ngx_http_request_t, rc: ngx_int_t) {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_pcalloc(
    pool: *mut ngx_pool_t,
    size: usize,
) -> *mut ::core::ffi::c_void {
    ptr::null_mut()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_http_send_header(r: *mut ngx_http_request_t) -> ngx_int_t {
    0
}

#[unsafe(no_mangle)]
pub static mut ngx_posted_next_events: *mut c_void = std::ptr::null_mut();

#[unsafe(no_mangle)]
pub static mut ngx_ncpu: ngx_int_t = 0;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_http_core_run_phases(r: *mut ngx_http_request_t) {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_shmtx_lock(mtx: *mut ngx_shmtx_t) {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_shmtx_unlock(mtx: *mut ngx_shmtx_t) {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_slab_alloc_locked(
    pool: *mut ngx_slab_pool_t,
    size: usize,
) -> *mut ::core::ffi::c_void {
    std::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_shared_memory_add(
    cf: *mut ngx_conf_t,
    name: *mut ngx_str_t,
    size: usize,
    tag: *mut ::core::ffi::c_void,
) -> *mut ngx_shm_zone_t {
    std::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_rbtree_next(
    tree: *mut ngx_rbtree_t,
    node: *mut ngx_rbtree_node_t,
) -> *mut ngx_rbtree_node_t {
    std::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_slab_free_locked(
    pool: *mut ngx_slab_pool_t,
    p: *mut ::core::ffi::c_void,
) {
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_http_compile_complex_value(
    ccv: *mut ngx_http_compile_complex_value_t,
) -> ngx_int_t {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_http_complex_value(
    r: *mut ngx_http_request_t,
    val: *mut ngx_http_complex_value_t,
    value: *mut ngx_str_t,
) -> ngx_int_t {
    0
}
