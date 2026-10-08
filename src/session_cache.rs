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
use std::mem::MaybeUninit;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, anyhow, bail};
use asl::{Config, HandshakeState, SessionState, new_cid, utc_now};
use nginx_sys::{
    NGX_CONF_PREFIX, NGX_PREFIX, ngx_conf_t, ngx_int_t, ngx_shared_memory_add, ngx_shm_zone_t,
};
use ngx::allocator::Allocator;
use ngx::collections::{RbTreeMap, Vec};
use ngx::core::{NgxString, SlabPool, Status};
use ngx::http::HttpModuleMainConf;
use ngx::ngx_string;
use ngx::sync::RwLock;
use tracing::{debug, info, instrument};

use crate::Module;
use crate::asl_keys::{AslConfig, asl_file_path, create_asl_config};
use crate::conf::MainConfig;
use crate::ngx_http_pep_module;

const SESSION_CACHE_SIZE: usize = 100 << 20;

pub struct ShmHandshakeState<A: Allocator + Clone> {
    pub ss_e: [u8; 64],
    pub transcript: Vec<u8, A>,
}

fn copy_to_pool<T: Clone>(v: &[T], pool: SlabPool) -> Vec<T, SlabPool> {
    let mut nv = Vec::with_capacity_in(v.len(), pool.clone());
    nv.extend_from_slice(v);
    nv
}

fn copy_to_global<T: Clone>(v: &Vec<T, SlabPool>) -> std::vec::Vec<T> {
    let mut nv = std::vec::Vec::with_capacity(v.len());
    nv.extend_from_slice(v);
    nv
}

impl ShmHandshakeState<SlabPool> {
    fn from_global(value: &HandshakeState, pool: SlabPool) -> Self {
        ShmHandshakeState {
            ss_e: value.ss_e,
            transcript: copy_to_pool(&value.transcript, pool),
        }
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
    #[cfg(feature = "its")]
    always_expire: std::sync::atomic::AtomicBool,
}

pub struct ShmSessionCache {
    pool: SlabPool,
    shared: &'static Shared,
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

        Ok(Self { pool, shared })
    }

    pub fn server_config(&self) -> &Config {
        unsafe { self.shared.config.assume_init_ref() }
    }

    pub async fn init_handshake(&'static self, state: HandshakeState) -> Result<String> {
        let cid = new_cid();

        let key = NgxString::try_from_bytes_in(&cid, self.pool.clone())?;
        let value = ShmConnectionState::Handshaking(ShmHandshakeState::from_global(
            &state,
            self.pool.clone(),
        ));

        let mut map = self.shared.map.write();
        if map.get(&key).is_some() {
            bail!("conflict: {cid}");
        }
        map.try_insert(key, value)?;
        Ok(cid)
    }

    pub async fn finish_handshake(&'static self, cid: &str) -> Result<HandshakeState> {
        let key = NgxString::try_from_bytes_in(cid, self.pool.clone())?;

        let mut map = self.shared.map.write();
        match map.remove(&key).context(format!("missing: {key}"))? {
            ShmConnectionState::Handshaking(ref state) => Ok(state.into()),
            ShmConnectionState::Established(_) => Err(anyhow!("not handshaking: {key}")),
        }
    }

    #[instrument(skip(self))]
    fn cleanup_expired(&'static self) {
        let mut map = self.shared.map.write();
        let now = utc_now();
        let to_remove: Vec<_> = map
            .iter()
            .filter_map(|(k, v)| {
                match v {
                    ShmConnectionState::Handshaking(_shm_handshake_state) => None, // TODO: store timestamp/expiration?
                    ShmConnectionState::Established(shm_session_state) => {
                        if shm_session_state.expires > now {
                            None
                        } else {
                            debug!(cid = %k, "expire");
                            Some(k.clone())
                        }
                    }
                }
            })
            .collect();
        for key in to_remove {
            map.remove(&key);
        }
    }

    fn maybe_cleanup_expired_sessions(&'static self) {
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

    pub async fn start_session(&'static self, cid: &str, state: SessionState) -> Result<()> {
        self.maybe_cleanup_expired_sessions();

        let key = NgxString::try_from_bytes_in(cid, self.pool.clone())?;
        let value = ShmConnectionState::Established(ShmSessionState::from_global(&state));

        let mut map = self.shared.map.write();
        if map.get(&key).is_some() {
            bail!("conflict — {key}");
        }
        map.try_insert(key, value)?;
        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn continue_session(&'static self, cid: &str) -> Result<SessionState> {
        self.maybe_cleanup_expired_sessions();
        let key = NgxString::try_from_bytes_in(cid, self.pool.clone())?;

        let result = {
            let map = self.shared.map.read();
            let entry = map.get(&key).context(format!("missing — {key}"))?;

            match entry {
                ShmConnectionState::Established(state) => {
                    if state.expires > utc_now() {
                        let prev = state.enc_ctr.fetch_add(1, Ordering::SeqCst);
                        return Ok(state.to_global(prev + 1));
                    }
                    Ok(None)
                }
                _ => Err(anyhow!("not established — {key}")),
            }
        };
        match result {
            Ok(Some(session)) => Ok(session),
            Ok(None) => {
                let mut map = self.shared.map.write();
                let _ = map.remove(&key);

                debug!(cid = %key, "expire");
                Err(anyhow!("expired — {key}"))
            }
            Err(e) => Err(e),
        }
    }

    /// Number of entries (handshakes + established sessions) in the shared
    /// cache. Called from the metrics PeriodicReader thread: the shm rwlock is
    /// atomics-based and thread-agnostic, so a brief read lock from off the
    /// event loop is safe.
    #[cfg_attr(test, allow(dead_code))]
    pub fn session_count(&'static self) -> u64 {
        self.shared.map.read().iter().count() as u64
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
        map.try_insert(key, ShmConnectionState::Established(state))?;
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
            SESSION_CACHE_SIZE,
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
            #[cfg(feature = "its")]
            always_expire: std::sync::atomic::AtomicBool::new(false),
        };

        pool.as_mut().data = ngx::allocator::allocate(shared, &pool.clone())
            .expect("allocate")
            .as_ptr()
            .cast();
        Status::NGX_OK.into()
    } else {
        Status::NGX_ERROR.into()
    }
}
