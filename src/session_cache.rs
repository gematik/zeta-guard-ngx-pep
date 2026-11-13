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

use std::collections::BinaryHeap;
use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, anyhow, bail};
use asl::{AslError, Config, HandshakeState, SessionState, new_cid, utc_now};
use nginx_sys::{
    NGX_CONF_PREFIX, NGX_PREFIX, ngx_conf_t, ngx_int_t, ngx_shared_memory_add, ngx_shm_zone_t,
};
use ngx::allocator::Allocator;
use ngx::collections::{RbTreeMap, Vec};
use ngx::core::{NgxString, SlabPool, Status};
use ngx::http::HttpModuleMainConf;
use ngx::ngx_string;
use ngx::sync::RwLock;
use tracing::{debug, info, instrument, warn};

use crate::Module;
use crate::asl_keys::{AslConfig, asl_file_path, create_asl_config};
use crate::conf::MainConfig;
use crate::error::ZetaAslResult;
use crate::ngx_http_pep_module;

/// Minimum time between two background cleanup runs.
#[cfg_attr(feature = "its", allow(dead_code))]
const CLEANUP_INTERVAL_SECS: u64 = 10;
/// Entries removed per write-lock acquisition during cleanup, so that the lock is
/// released regularly and request handling is not stalled by a long removal.
const CLEANUP_CHUNK: usize = 256;
/// Lower bound for the number of entries evicted when the zone is full.
const MIN_EVICTION_BATCH: usize = 64;
/// Tries to insert into a full zone: once, then after each of two reclaim rounds.
const RECLAIM_ATTEMPTS: usize = 3;

pub struct ShmHandshakeState<A: Allocator + Clone> {
    pub ss_e: [u8; 64],
    pub transcript: Vec<u8, A>,
    pub expires: u64,
}

fn copy_to_global<T: Clone>(v: &Vec<T, SlabPool>) -> std::vec::Vec<T> {
    let mut nv = std::vec::Vec::with_capacity(v.len());
    nv.extend_from_slice(v);
    nv
}

impl ShmHandshakeState<SlabPool> {
    /// Copy into the shared zone. Fallible: a full zone is reported as an error rather than
    /// aborting the worker.
    fn try_from_global(value: &HandshakeState, expires: u64, pool: SlabPool) -> Result<Self> {
        let mut transcript = Vec::new_in(pool);
        transcript
            .try_reserve_exact(value.transcript.len())
            .map_err(|e| anyhow!("session cache full: {e:?}"))?;
        transcript.extend_from_slice(&value.transcript);
        Ok(ShmHandshakeState {
            ss_e: value.ss_e,
            transcript,
            expires,
        })
    }
}

impl From<&ShmHandshakeState<SlabPool>> for HandshakeState {
    fn from(value: &ShmHandshakeState<SlabPool>) -> Self {
        HandshakeState {
            ss_e: value.ss_e,
            transcript: copy_to_global(&value.transcript),
        }
    }
}

/// Session state stored in shared memory. Key fields are inline fixed-size arrays
/// (no slab allocations needed). Only enc_ctr needs atomic access for concurrent reads.
pub struct ShmSessionState {
    pub key_id: [u8; 32],
    pub k2_c2s_app_data: [u8; 32],
    pub k2_s2c_app_data: [u8; 32],
    pub expires: u64,
    pub enc_ctr: AtomicU64,
}

impl ShmSessionState {
    fn from_global(value: &SessionState) -> Self {
        ShmSessionState {
            key_id: value.key_id,
            k2_c2s_app_data: value.k2_c2s_app_data,
            k2_s2c_app_data: value.k2_s2c_app_data,
            expires: value.expires,
            enc_ctr: AtomicU64::new(value.enc_ctr),
        }
    }
    fn to_global(&self, enc_ctr: u64) -> SessionState {
        SessionState {
            key_id: self.key_id,
            k2_c2s_app_data: self.k2_c2s_app_data,
            k2_s2c_app_data: self.k2_s2c_app_data,
            expires: self.expires,
            enc_ctr,
        }
    }
}

pub enum ShmConnectionState<A: Allocator + Clone> {
    Handshaking(ShmHandshakeState<A>),
    Established(ShmSessionState),
}

type Map = RbTreeMap<NgxString<SlabPool>, ShmConnectionState<SlabPool>, SlabPool>;

struct Shared {
    config: MaybeUninit<Config>,
    map: RwLock<Map>,
    // Counters are kept next to the map so that the metrics reader never has to
    // lock or scan it.
    handshakes: AtomicU64,
    sessions: AtomicU64,
    alloc_failures: AtomicU64,
    evictions: AtomicU64,
    #[cfg_attr(feature = "its", allow(dead_code))]
    last_cleanup: AtomicU64,
    #[cfg(feature = "its")]
    always_expire: std::sync::atomic::AtomicBool,
}

/// Point-in-time view of the cache, read without taking the map lock.
#[cfg_attr(test, allow(dead_code))]
pub struct CacheStats {
    pub handshakes: u64,
    pub sessions: u64,
    pub used_bytes: u64,
    pub size_bytes: u64,
    /// Inserts that failed with the zone full, before any reclaim attempt.
    pub alloc_failures: u64,
    /// Live entries dropped to make room.
    pub evictions: u64,
}

fn dec(counter: &AtomicU64) {
    let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
}

/// Eviction rank: expired entries first, then handshakes (small TTL, cheap to retry), then
/// sessions, each oldest first.
fn eviction_rank(entry: &ShmConnectionState<SlabPool>, now: u64) -> (u8, u64) {
    match entry {
        ShmConnectionState::Handshaking(h) => (u8::from(h.expires > now), h.expires),
        ShmConnectionState::Established(s) => (if s.expires > now { 2 } else { 0 }, s.expires),
    }
}

fn is_expired(entry: &ShmConnectionState<SlabPool>, now: u64) -> bool {
    match entry {
        ShmConnectionState::Handshaking(h) => h.expires <= now,
        ShmConnectionState::Established(s) => s.expires <= now,
    }
}

/// Keys are copied to the process heap: collecting them as `NgxString`s would allocate from
/// the very zone we are trying to free up.
fn expired_keys(map: &Map, now: u64) -> std::vec::Vec<String> {
    map.iter()
        .filter(|(_, v)| is_expired(v, now))
        .map(|(k, _)| k.to_string())
        .collect()
}

/// Picks the entries to drop from `(cid, rank)` pairs, see [`eviction_rank`]: all expired
/// ones, topped up with the oldest live ones to at most `n` in total. Returns
/// `(expired, live)`. Memory use is bounded by `n` plus the number of expired entries.
fn select_victims<K: std::fmt::Display>(
    entries: impl Iterator<Item = (K, (u8, u64))>,
    n: usize,
) -> (std::vec::Vec<String>, std::vec::Vec<String>) {
    let mut expired = std::vec::Vec::new();
    let mut heap: BinaryHeap<((u8, u64), String)> = BinaryHeap::with_capacity(n + 1);
    for (k, rank) in entries {
        if rank.0 == 0 {
            expired.push(k.to_string());
        } else if heap.len() < n {
            heap.push((rank, k.to_string()));
        } else if heap.peek().is_some_and(|(worst, _)| rank < *worst) {
            heap.pop();
            heap.push((rank, k.to_string()));
        }
    }
    let room = n.saturating_sub(expired.len());
    let live = heap
        .into_sorted_vec()
        .into_iter()
        .take(room)
        .map(|(_, k)| k)
        .collect();
    (expired, live)
}

pub struct ShmSessionCache {
    pool: SlabPool,
    shared: &'static Shared,
    // The TTLs are process-local, taken from the current configuration: a reload keeps the
    // zone but starts new workers, which pick up changed values.
    /// Lifetime of established sessions, in seconds.
    session_ttl: u64,
    /// Lifetime of unfinished handshakes, in seconds.
    handshake_ttl: u64,
}

impl ShmSessionCache {
    pub fn new(shm_zone: &mut ngx_shm_zone_t) -> Result<Self> {
        let pool = unsafe { SlabPool::from_shm_zone(shm_zone) }.context("session_cache_zone")?;

        let shared = unsafe {
            pool.as_ref()
                .data
                .cast::<Shared>()
                .as_ref()
                .context("as_ref")?
        };

        let main_conf = unsafe { shm_zone.data.cast::<MainConfig>().as_ref() }
            .context("session_cache_zone: main_conf")?;

        Ok(Self {
            pool,
            shared,
            session_ttl: main_conf.asl_session_ttl.as_secs(),
            handshake_ttl: main_conf.asl_handshake_ttl.as_secs(),
        })
    }

    pub fn server_config(&self) -> &Config {
        unsafe { self.shared.config.assume_init_ref() }
    }

    /// Insert a new entry and count it. When the zone is full, reclaim space and retry:
    /// expired entries go first, then the oldest live ones are evicted. Only when that does
    /// not help either is the failure reported.
    ///
    /// The map lock is taken per attempt: reclaiming scans under the read lock and removes in
    /// small chunks, so readers are not stalled by the scan.
    fn insert_reclaiming(
        &self,
        cid: &str,
        make: impl Fn() -> Result<ShmConnectionState<SlabPool>>,
    ) -> Result<()> {
        for attempt in 0..RECLAIM_ATTEMPTS {
            let result = {
                let mut map = self.shared.map.write();
                if map.get::<[u8]>(cid.as_bytes()).is_some() {
                    bail!("conflict: {cid}");
                }
                // A failed attempt drops key and state, which returns their zone memory, so
                // building them anew per attempt never accumulates.
                (|| -> Result<()> {
                    let key = NgxString::try_from_bytes_in(cid, self.pool.clone())?;
                    let state = make()?;
                    let counter = match state {
                        ShmConnectionState::Handshaking(_) => &self.shared.handshakes,
                        ShmConnectionState::Established(_) => &self.shared.sessions,
                    };
                    map.try_insert(key, state)?;
                    // under the lock, so a concurrent removal never sees an uncounted entry
                    counter.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                })()
            };
            let Err(err) = result else {
                return Ok(());
            };
            if attempt == 0 {
                self.shared.alloc_failures.fetch_add(1, Ordering::Relaxed);
            }
            if attempt + 1 == RECLAIM_ATTEMPTS {
                return Err(err.context("session cache full"));
            }
            let freed = self.reclaim();
            warn!(
                attempt,
                freed,
                handshakes = self.shared.handshakes.load(Ordering::Relaxed),
                sessions = self.shared.sessions.load(Ordering::Relaxed),
                "session cache full, reclaimed entries"
            );
        }
        unreachable!()
    }

    /// Drop expired entries and, if that is not enough, evict the oldest live ones. Returns
    /// the number of entries removed.
    fn reclaim(&self) -> usize {
        let now = utc_now();
        let total = self.shared.handshakes.load(Ordering::Relaxed)
            + self.shared.sessions.load(Ordering::Relaxed);
        let batch = MIN_EVICTION_BATCH.max(total as usize / 100);
        let (expired, live) = {
            let map = self.shared.map.read();
            select_victims(map.iter().map(|(k, v)| (k, eviction_rank(v, now))), batch)
        };
        let mut freed = 0;
        for chunk in expired.chunks(CLEANUP_CHUNK) {
            let mut map = self.shared.map.write();
            freed += self.remove_keys(&mut map, chunk.iter().map(String::as_str));
        }
        let mut evicted = 0;
        for chunk in live.chunks(CLEANUP_CHUNK) {
            let mut map = self.shared.map.write();
            evicted += self.remove_keys(&mut map, chunk.iter().map(String::as_str));
        }
        self.shared
            .evictions
            .fetch_add(evicted as u64, Ordering::Relaxed);
        freed + evicted
    }

    /// Remove the given keys, keeping the counters in sync. Returns the number removed.
    fn remove_keys<'a>(&self, map: &mut Map, keys: impl Iterator<Item = &'a str>) -> usize {
        let mut removed = 0;
        for cid in keys {
            // look up by borrowed bytes: allocating a key here would fail on an exhausted zone
            match map.remove::<[u8]>(cid.as_bytes()) {
                Some(ShmConnectionState::Handshaking(_)) => dec(&self.shared.handshakes),
                Some(ShmConnectionState::Established(_)) => dec(&self.shared.sessions),
                None => continue,
            }
            removed += 1;
        }
        removed
    }

    pub async fn init_handshake(&'static self, state: HandshakeState) -> Result<String> {
        self.maybe_cleanup_expired_sessions();
        let cid = new_cid();
        let expires = utc_now() + self.handshake_ttl;

        self.insert_reclaiming(&cid, || {
            Ok(ShmConnectionState::Handshaking(
                ShmHandshakeState::try_from_global(&state, expires, self.pool.clone())?,
            ))
        })?;
        Ok(cid)
    }

    pub async fn finish_handshake(&'static self, cid: &str) -> ZetaAslResult<HandshakeState> {
        let mut map = self.shared.map.write();
        // A_26924: a handshake that is unknown, expired or evicted is "unknown CID" (403,
        // code 9), so the client knows to run a new handshake.
        match map.get::<[u8]>(cid.as_bytes()) {
            None => {
                debug!(%cid, "unknown cid");
                return Err(AslError::UnknownCID);
            }
            // an M3 must not be able to destroy a live session: leave it in place
            Some(ShmConnectionState::Established(_)) => {
                return Err(AslError::InternalError(anyhow!("not handshaking: {cid}")));
            }
            Some(ShmConnectionState::Handshaking(_)) => {}
        }
        let Some(ShmConnectionState::Handshaking(state)) = map.remove::<[u8]>(cid.as_bytes())
        else {
            unreachable!("checked above, under the same lock");
        };
        dec(&self.shared.handshakes);
        if state.expires <= utc_now() {
            debug!(%cid, "handshake expired");
            return Err(AslError::UnknownCID);
        }
        Ok((&state).into())
    }

    /// Drop expired handshakes and sessions. The scan only holds the read lock; removal
    /// happens in small chunks so the write lock is never held for long.
    #[instrument(skip(self))]
    fn cleanup_expired(&'static self) {
        let expired = {
            let map = self.shared.map.read();
            expired_keys(&map, utc_now())
        };
        for chunk in expired.chunks(CLEANUP_CHUNK) {
            let mut map = self.shared.map.write();
            for cid in chunk {
                debug!(%cid, "expire");
            }
            self.remove_keys(&mut map, chunk.iter().map(String::as_str));
        }
    }

    fn maybe_cleanup_expired_sessions(&'static self) {
        #[cfg(not(feature = "its"))]
        // run the cleanup routine at most every CLEANUP_INTERVAL_SECS, in a background thread.
        {
            let now = utc_now();
            let last = self.shared.last_cleanup.load(Ordering::Relaxed);
            if now >= last + CLEANUP_INTERVAL_SECS
                && self
                    .shared
                    .last_cleanup
                    .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                tokio::task::spawn_blocking(move || {
                    self.cleanup_expired();
                });
            }
        }

        #[cfg(feature = "its")]
        // either always or never expire, blockingly; can be toggled with test control client
        if self.shared.always_expire.load(Ordering::Relaxed) {
            self.cleanup_expired();
        };
    }

    pub async fn start_session(&'static self, cid: &str, mut state: SessionState) -> Result<()> {
        self.maybe_cleanup_expired_sessions();

        // the ASL crate sets the protocol limit; the configured TTL may only shorten it
        state.expires = state.expires.min(utc_now() + self.session_ttl);

        self.insert_reclaiming(cid, || {
            Ok(ShmConnectionState::Established(
                ShmSessionState::from_global(&state),
            ))
        })?;
        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn continue_session(&'static self, cid: &str) -> ZetaAslResult<SessionState> {
        self.maybe_cleanup_expired_sessions();
        let key =
            NgxString::try_from_bytes_in(cid, self.pool.clone()).context("allocation failed")?;

        let result = {
            let map = self.shared.map.read();
            // A_26924: unknown, expired-and-cleaned or evicted sessions are "unknown CID"
            // (403, code 9), so the client knows to run a new handshake.
            let Some(entry) = map.get(&key) else {
                debug!(cid = %key, "unknown cid");
                return Err(AslError::UnknownCID);
            };

            match entry {
                ShmConnectionState::Established(state) => {
                    if state.expires > utc_now() {
                        let prev = state.enc_ctr.fetch_add(1, Ordering::SeqCst);
                        return Ok(state.to_global(prev + 1));
                    }
                    Ok((None, state.expires))
                }
                _ => Err(anyhow!("not established — {key}")),
            }
        };
        match result {
            Ok((Some(session), _)) => Ok(session),
            Ok((None, expired)) => {
                let mut map = self.shared.map.write();
                if map.remove(&key).is_some() {
                    dec(&self.shared.sessions);
                }

                debug!(cid = %key, expired, "expire");
                Err(AslError::SessionExpired(key.to_string(), expired))
            }
            Err(e) => Err(AslError::InternalError(e)),
        }
    }

    /// Counters and zone fill. Called from the metrics PeriodicReader thread: nothing here
    /// takes the map lock or the slab mutex, so it is O(1) and cannot contend with request
    /// handling. The fill level counts whole pages, a page leaves the free list as soon as a
    /// size class takes it, and is read without the slab mutex: a slightly stale value is
    /// fine for a gauge.
    #[cfg_attr(test, allow(dead_code))]
    pub fn stats(&'static self) -> CacheStats {
        let pool = ptr::from_ref(self.pool.as_ref());
        // SAFETY: `start` and `end` never change after the zone is set up. `pfree` is updated
        // by workers under the slab mutex, which we don't take: the volatile read keeps the
        // compiler from caching it, the value itself is a best-effort snapshot.
        let (start, end, pfree) = unsafe {
            (
                (*pool).start,
                (*pool).end,
                (&raw const (*pool).pfree).read_volatile(),
            )
        };
        let size = (end as usize).saturating_sub(start as usize);
        // nginx's ngx_pagesize is getpagesize(); the symbol itself only exists inside nginx
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(1) as usize;
        let free = pfree * page_size;
        CacheStats {
            handshakes: self.shared.handshakes.load(Ordering::Relaxed),
            sessions: self.shared.sessions.load(Ordering::Relaxed),
            used_bytes: size.saturating_sub(free) as u64,
            size_bytes: size as u64,
            alloc_failures: self.shared.alloc_failures.load(Ordering::Relaxed),
            evictions: self.shared.evictions.load(Ordering::Relaxed),
        }
    }

    #[cfg(feature = "its")]
    pub fn set_always_expire(&'static self, value: bool) {
        self.shared.always_expire.store(value, Ordering::Relaxed);
    }

    #[cfg(feature = "its")]
    pub async fn expire_cid(&'static self, cid: &str) -> Result<()> {
        let key = NgxString::try_from_bytes_in(cid, self.pool.clone())?;

        let mut map = self.shared.map.write();
        let item = map
            .remove(&key)
            .ok_or_else(|| anyhow!("expire_cid: {cid} not found"))?;
        let mut state = match item {
            ShmConnectionState::Handshaking(_) => bail!("expire_cid: {cid} is handshaking"),
            ShmConnectionState::Established(shm_session_state) => shm_session_state,
        };
        state.expires = 0;
        if let Err(e) = map.try_insert(key, ShmConnectionState::Established(state)) {
            dec(&self.shared.sessions);
            return Err(e.into());
        }
        Ok(())
    }
}

/// Build the ASL and OCSP configuration from the module config, resolving the
/// key/cert file names against the nginx conf prefix.
///
/// Called twice with the same inputs: once in the master to seed the shared
/// zone with the ASL half, and once per worker for the process-local OCSP cache
/// (whose lock and cached response must not be inherited across `fork`).
pub(crate) fn asl_config(main_conf: &MainConfig) -> Result<AslConfig> {
    let asl_conf_dir = Path::new(NGX_PREFIX.to_str().expect("NGX_PREFIX"))
        .join(NGX_CONF_PREFIX.to_str().expect("NGX_CONF_PREFIX"));
    create_asl_config(
        main_conf.asl_testing,
        asl_file_path(&asl_conf_dir, &main_conf.asl_signer_cert),
        asl_file_path(&asl_conf_dir, &main_conf.asl_signer_key),
        asl_file_path(&asl_conf_dir, &main_conf.asl_ca_cert),
        asl_file_path(&asl_conf_dir, &main_conf.asl_roots_json),
        main_conf.asl_root_ca.clone(),
        main_conf.asl_ocsp.clone(),
        main_conf.asl_ocsp_ttl,
    )
}

pub(crate) fn init(cf: *mut ngx_conf_t) -> ngx_int_t {
    unsafe {
        let main_conf: &mut MainConfig = Module::main_conf_mut(&*cf).expect("main_conf");
        let Some(shm_zone) = ngx_shared_memory_add(
            cf,
            &mut ngx_string!("session_cache"),
            main_conf.asl_session_cache_size,
            ptr::addr_of_mut!(ngx_http_pep_module).cast(),
        )
        .as_mut() else {
            return Status::NGX_ERROR.0;
        };

        shm_zone.init = Some(shared_zone_init);
        shm_zone.data = ptr::from_mut(main_conf).cast();
        main_conf.session_cache_zone = shm_zone;

        Status::NGX_OK.0
    }
}

extern "C" fn shared_zone_init(shm_zone: *mut ngx_shm_zone_t, _data: *mut c_void) -> ngx_int_t {
    let main_conf: &MainConfig = unsafe {
        shm_zone
            .as_ref()
            .expect("shm_zone")
            .data
            .cast::<MainConfig>()
            .as_ref()
    }
    .expect("MainConfig");

    let mut pool =
        unsafe { SlabPool::from_shm_zone(shm_zone.as_ref().expect("shm_zone")) }.expect("SlabPool");

    if pool.as_mut().data.is_null() {
        let map: RwLock<Map> = RwLock::new(RbTreeMap::try_new_in(pool.clone()).expect("RbTreeMap"));

        let asl_config = asl_config(main_conf).expect("asl init");
        if asl_config.asl.is_default() {
            info!("asl environment: disabled");
        } else {
            info!(
                env = ?asl_config.asl.env,
                cert_data_version = %asl_config.asl.signed_keys.version(),
                "asl environment"
            );
            if let Some(url) = &asl_config.ocsp.url {
                info!(%url, ttl_secs = asl_config.ocsp.ttl.as_secs(), "asl ocsp");
            } else {
                info!("asl ocsp: off");
            }
        }
        // Only the ASL part is shared; the OCSP cache is process-local and is
        // built per worker (see `ngx_http_pep_init_worker`).
        let config = MaybeUninit::new(asl_config.asl);
        let shared = Shared {
            map,
            config,
            handshakes: AtomicU64::new(0),
            sessions: AtomicU64::new(0),
            alloc_failures: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            last_cleanup: AtomicU64::new(0),
            #[cfg(feature = "its")]
            always_expire: std::sync::atomic::AtomicBool::new(false),
        };

        pool.as_mut().data = ngx::allocator::allocate(shared, &pool.clone())
            .expect("allocate")
            .as_ptr()
            .cast();
        Status::NGX_OK.into()
    } else {
        // Non-null data means nginx handed us the zone of the previous cycle (a reload with
        // the same name, tag and size), `Shared` still in place. Failing here would abort
        // the reload.
        Status::NGX_OK.into()
    }
}

#[cfg(test)]
mod tests {
    use super::select_victims;

    // rank as in `eviction_rank`: (0, _) expired, (1, _) handshake, (2, _) session
    #[test]
    fn expired_entries_are_all_selected() {
        let entries = vec![("a", (0, 5)), ("b", (2, 90)), ("c", (0, 7)), ("d", (1, 50))];
        let (expired, live) = select_victims(entries.into_iter(), 2);
        assert_eq!(expired, ["a", "c"]);
        assert!(live.is_empty(), "expired fill the batch already");
    }

    #[test]
    fn live_entries_top_up_oldest_handshakes_first() {
        let entries = vec![
            ("s1", (2, 10)),
            ("h2", (1, 60)),
            ("h1", (1, 50)),
            ("e", (0, 1)),
        ];
        let (expired, live) = select_victims(entries.into_iter(), 3);
        assert_eq!(expired, ["e"]);
        assert_eq!(live, ["h1", "h2"]);
    }

    #[test]
    fn batch_bounds_live_selection() {
        let entries = (0..100).map(|i| (format!("k{i}"), (2, i)));
        let (expired, live) = select_victims(entries, 5);
        assert!(expired.is_empty());
        assert_eq!(live, ["k0", "k1", "k2", "k3", "k4"]);
    }
}
