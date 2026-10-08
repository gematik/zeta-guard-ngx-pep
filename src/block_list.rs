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

use std::ffi::c_void;
#[cfg(feature = "its")]
use std::sync::atomic::Ordering;
use std::{ptr, str};

use crate::Module;
use crate::conf::MainConfig;
use crate::ngx_http_pep_module;
use anyhow::{Context, Result};
use asl::utc_now;
use nginx_sys::{ngx_conf_t, ngx_int_t, ngx_shared_memory_add, ngx_shm_zone_t};
use ngx::collections::{RbTreeMap, Vec};
use ngx::core::{SlabPool, Status};
use ngx::http::HttpModuleMainConf;
use ngx::ngx_string;
use ngx::sync::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};

const BLOCK_LIST_SIZE: usize = 100 << 16;
const SID_MAX: usize = 36; // Keycloak session id is a UUID

type Map = RbTreeMap<Sid, Meta, SlabPool>;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Sid {
    len: u8,
    bytes: [u8; SID_MAX],
}

impl Sid {
    fn new(sid: &str) -> Option<Self> {
        let b = sid.as_bytes();
        (b.len() <= SID_MAX).then(|| {
            let mut bytes = [0u8; SID_MAX];
            bytes[..b.len()].copy_from_slice(b);
            Sid {
                len: b.len() as u8,
                bytes,
            }
        })
    }

    #[allow(unused)]
    fn as_str(&self) -> &str {
        str::from_utf8(&self.bytes[..self.len as usize]).unwrap_or("<non-utf8 sid>")
    }
}

#[derive(Clone, Copy)]
struct Meta {
    #[allow(unused)]
    when: u64,
    until: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Block {
    pub when: u64,
    pub until: u64,
    pub what: String,
}

struct Shared {
    map: RwLock<Map>,
    #[cfg(feature = "its")]
    always_expire: std::sync::atomic::AtomicBool,
}

pub struct ShmBlockList {
    shared: &'static Shared,
}

impl ShmBlockList {
    pub fn new(shm_zone: &mut ngx_shm_zone_t) -> Result<Self> {
        let pool = unsafe { SlabPool::from_shm_zone(shm_zone) }.context("block_list_zone")?;

        let shared = unsafe {
            pool.as_ref()
                .data
                .cast::<Shared>()
                .as_ref()
                .context("as_ref")?
        };

        Ok(Self { shared })
    }

    /// Apply a block from the revocation stream. `when`/`until` are stored
    /// verbatim (whatever the PDP assigned), so every pod holds the same entry.
    /// Re-banning a sid keeps the later expiry; replays of an equal/older ban
    /// are no-ops.
    #[instrument(skip(self))]
    pub fn apply(&'static self, block: &Block) -> Result<()> {
        let Some(key) = Sid::new(&block.what) else {
            warn!(sid = %block.what, "sid exceeds SID_MAX ({SID_MAX}); refusing to block");
            return Ok(());
        };
        let meta = Meta {
            when: block.when,
            until: block.until,
        };
        let mut map = self.shared.map.write();
        if let Some(existing) = map.get_mut(&key) {
            if meta.until > existing.until {
                info!(sid = %block.what, until = block.until, was = existing.until, "extended block");
                *existing = meta;
            } else {
                debug!(sid = %block.what, until = block.until, held = existing.until, "block already held; ignoring");
            }
            return Ok(());
        }
        map.try_insert(key, meta)?;
        // Not under the zone lock: it is shared across worker processes, and the
        // counter's internals are not ours to hold it across.
        drop(map);
        crate::metrics::SESSION_BLOCKED_COUNT.add(1, &[]);
        info!(sid = %block.what, until = block.until, "applied block");
        Ok(())
    }

    pub fn is_blocked(&'static self, sid: &str) -> Result<bool> {
        self.maybe_cleanup_expired_blocks();
        let Some(key) = Sid::new(sid) else {
            warn!(sid, "sid exceeds SID_MAX ({SID_MAX}); cannot match a block");
            return Ok(false);
        };
        let map = self.shared.map.read();
        Ok(map.get(&key).is_some_and(|m| m.until > utc_now()))
    }

    #[instrument(skip(self))]
    fn cleanup_expired(&'static self) {
        let mut map = self.shared.map.write();
        let now = utc_now();
        let to_remove: Vec<_> = map
            .iter()
            .filter(|&(_k, v)| v.until <= now)
            .map(|(k, _v)| {
                debug!(sid = k.as_str(), "expire");
                *k
            })
            .collect();
        for key in to_remove {
            map.remove(&key);
        }
    }

    fn maybe_cleanup_expired_blocks(&'static self) {
        #[cfg(not(feature = "its"))]
        // run the cleanup routine with 1% probability, in a background thread.
        if fastrand::u8(0..100) == 0 {
            tokio::task::spawn_blocking(move || {
                self.cleanup_expired();
            });
        };

        #[cfg(feature = "its")]
        // either always or never expire, blockingly; can be toggled with test control client
        if self.shared.always_expire.load(Ordering::Relaxed) {
            self.cleanup_expired();
        };
    }

    /// Number of blocked sessions in the shared cache.
    /// Called from the metrics PeriodicReader thread: the shm rwlock is atomics-based and
    /// thread-agnostic, so a brief read lock from off the event loop is safe.
    #[cfg_attr(test, allow(dead_code))]
    pub fn blocked_count(&'static self) -> u64 {
        self.shared.map.read().iter().count() as u64
    }

    #[cfg(feature = "its")]
    pub fn set_always_expire(&'static self, value: bool) {
        self.shared.always_expire.store(value, Ordering::Relaxed);
    }

    #[cfg(feature = "its")]
    pub async fn unblock_sid(&'static self, sid: &str) -> Result<()> {
        let key = Sid::new(sid).context("sid exceeds SID_MAX")?;
        let mut map = self.shared.map.write();
        map.remove(&key);
        Ok(())
    }

    #[cfg(feature = "its")]
    pub async fn has_sid(&'static self, sid: &str) -> Result<bool> {
        let key = Sid::new(sid).context("sid exceeds SID_MAX")?;
        let map = self.shared.map.read();
        Ok(map.get(&key).is_some())
    }
}

pub(crate) fn init(cf: *mut ngx_conf_t) -> ngx_int_t {
    unsafe {
        let main_conf: &mut MainConfig = Module::main_conf_mut(&*cf).expect("main_conf");
        let Some(shm_zone) = ngx_shared_memory_add(
            cf,
            &mut ngx_string!("block_list"),
            BLOCK_LIST_SIZE,
            ptr::addr_of_mut!(ngx_http_pep_module).cast(),
        )
        .as_mut() else {
            return Status::NGX_ERROR.0;
        };

        shm_zone.init = Some(shared_zone_init);
        shm_zone.data = ptr::from_mut(main_conf).cast();
        main_conf.block_list_zone = shm_zone;

        Status::NGX_OK.0
    }
}

extern "C" fn shared_zone_init(shm_zone: *mut ngx_shm_zone_t, _data: *mut c_void) -> ngx_int_t {
    let mut pool =
        unsafe { SlabPool::from_shm_zone(shm_zone.as_ref().expect("shm_zone")) }.expect("SlabPool");

    if pool.as_mut().data.is_null() {
        let map: RwLock<Map> = RwLock::new(RbTreeMap::try_new_in(pool.clone()).expect("RbTreeMap"));
        let shared = Shared {
            map,
            #[cfg(feature = "its")]
            always_expire: std::sync::atomic::AtomicBool::new(false),
        };

        pool.as_mut().data = ngx::allocator::allocate(shared, &pool.clone())
            .expect("allocate")
            .as_ptr()
            .cast();
        Status::NGX_OK.into()
    } else {
        // Non-null data means nginx handed us a zone inherited from the previous
        // cycle (a reload: same zone name, tag and size), with the `Shared` from
        // before still in place — nothing to initialize, and the blocks stay
        // valid. Failing here would abort the whole reload.
        Status::NGX_OK.into()
    }
}
