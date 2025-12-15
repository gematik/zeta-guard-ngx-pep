/*-
 * #%L
 * ngx_pep
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH
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
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, anyhow, bail};
use asl::{Config, Environment, HandshakeState, SessionState, generate_asl_keys, new_cid, utc_now};
use nginx_sys::{ngx_conf_t, ngx_int_t, ngx_shared_memory_add, ngx_shm_zone_t};
use ngx::allocator::Allocator;
use ngx::collections::{RbTreeMap, Vec};
use ngx::core::{NgxString, SlabPool, Status};
use ngx::http::HttpModuleMainConf;
use ngx::ngx_string;
use ngx::sync::RwLock;

use crate::conf::MainConfig;
use crate::ngx_http_pep_module;
use crate::{Module, log_debug};

const SESSION_CACHE_SIZE: usize = 10 << 20;

pub struct ShmHandshakeState<A: Allocator + Clone> {
    pub ss_e: Vec<u8, A>,
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
            ss_e: copy_to_pool(&value.ss_e, pool.clone()),
            transcript: copy_to_pool(&value.transcript, pool),
        }
    }
}

impl From<&ShmHandshakeState<SlabPool>> for HandshakeState {
    fn from(value: &ShmHandshakeState<SlabPool>) -> Self {
        HandshakeState {
            ss_e: copy_to_global(&value.ss_e),
            transcript: copy_to_global(&value.transcript),
        }
    }
}

pub struct ShmSessionState<A: Allocator + Clone> {
    pub key_id: Vec<u8, A>,
    pub k2_c2s_app_data: Vec<u8, A>,
    pub k2_s2c_app_data: Vec<u8, A>,
    pub expires: u64,
    pub enc_ctr: AtomicU64,
}

impl ShmSessionState<SlabPool> {
    fn from_global(value: &SessionState, pool: SlabPool) -> Self {
        ShmSessionState {
            key_id: copy_to_pool(&value.key_id, pool.clone()),
            k2_c2s_app_data: copy_to_pool(&value.k2_c2s_app_data, pool.clone()),
            k2_s2c_app_data: copy_to_pool(&value.k2_s2c_app_data, pool),
            expires: value.expires,
            enc_ctr: AtomicU64::new(value.enc_ctr),
        }
    }
    fn to_global(&self, enc_ctr: u64) -> SessionState {
        SessionState {
            key_id: copy_to_global(&self.key_id),
            k2_c2s_app_data: copy_to_global(&self.k2_c2s_app_data),
            k2_s2c_app_data: copy_to_global(&self.k2_s2c_app_data),
            expires: self.expires,
            enc_ctr,
        }
    }
}

pub enum ShmConnectionState<A: Allocator + Clone> {
    Handshaking(ShmHandshakeState<A>),
    Established(ShmSessionState<A>),
}

type Map = RbTreeMap<NgxString<SlabPool>, ShmConnectionState<SlabPool>, SlabPool>;

struct Shared {
    config: MaybeUninit<Config>,
    map: RwLock<Map>,
}

pub struct ShmSessionCache {
    pool: SlabPool,
    shared: &'static Shared,
}

impl ShmSessionCache {
    pub fn new(shm_zone: &mut ngx_shm_zone_t) -> Result<Self> {
        let pool = unsafe { SlabPool::from_shm_zone(shm_zone) }.context("shm_zone")?;

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

        tokio::task::spawn_blocking(move || {
            let mut map = self.shared.map.write();
            if map.get(&key).is_some() {
                bail!("conflict: {cid}");
            }
            map.try_insert(key, value)?;
            Ok(cid)
        })
        .await?
    }

    pub async fn finish_handshake(&'static self, cid: &str) -> Result<HandshakeState> {
        let key = NgxString::try_from_bytes_in(cid, self.pool.clone())?;

        tokio::task::spawn_blocking(move || {
            let mut map = self.shared.map.write();
            match map.remove(&key).context(format!("missing: {key}"))? {
                ShmConnectionState::Handshaking(ref state) => Ok(state.into()),
                ShmConnectionState::Established(_) => Err(anyhow!("not handshaking: {key}")),
            }
        })
        .await?
    }

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
                            log_debug!("session cache: Expire session {}", k);
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

    pub async fn start_session(&'static self, cid: &str, state: SessionState) -> Result<()> {
        // 1%
        if fastrand::u8(0..100) == 0 {
            tokio::task::spawn_blocking(move || {
                self.cleanup_expired();
            });
        }

        let key = NgxString::try_from_bytes_in(cid, self.pool.clone())?;
        let value = ShmConnectionState::Established(ShmSessionState::from_global(
            &state,
            self.pool.clone(),
        ));

        tokio::task::spawn_blocking(move || {
            let mut map = self.shared.map.write();
            if map.get(&key).is_some() {
                bail!("conflict — {key}");
            }
            map.try_insert(key, value)?;
            Ok(())
        })
        .await?
    }

    pub async fn continue_session(&'static self, cid: &str) -> Result<SessionState> {
        let key = NgxString::try_from_bytes_in(cid, self.pool.clone())?;

        let result = {
            let map = self.shared.map.read();
            let entry = map.get(&key).context("missing — {key}")?;

            match entry {
                ShmConnectionState::Established(state) => {
                    if state.expires > utc_now() {
                        let prev = state.enc_ctr.fetch_add(1, Ordering::SeqCst);
                        return Ok(state.to_global(prev + 1));
                    } else {
                        // we need to upgrade our lock to expire — just signal to not deadlock
                        Ok(None)
                    }
                }
                _ => Err(anyhow!("missing — {cid}")),
            }
        };
        match result {
            Ok(Some(session)) => Ok(session),
            Ok(None) => {
                tokio::task::spawn_blocking(move || {
                    // read lock has been dropped, safe to acquire write lock
                    let mut map = self.shared.map.write();
                    let _ = map.remove(&key);
                    Err(anyhow!("expired — {key}"))
                })
                .await?
            }
            Err(e) => Err(e),
        }
    }
}

pub fn init(cf: *mut ngx_conf_t) -> ngx_int_t {
    let main_conf: &mut MainConfig = unsafe { Module::main_conf_mut(&*cf).expect("main_conf") };
    let Some(shm_zone) = (unsafe {
        ngx_shared_memory_add(
            cf,
            &mut ngx_string!("session_cache"),
            SESSION_CACHE_SIZE,
            ptr::addr_of_mut!(ngx_http_pep_module).cast(),
        )
        .as_mut()
    }) else {
        return Status::NGX_ERROR.0;
    };

    shm_zone.init = Some(shared_zone_init);
    shm_zone.data = ptr::from_mut(main_conf).cast();
    main_conf.shm_zone = shm_zone;

    Status::NGX_OK.0
}

static SERVER_SIG_SK_HEX: &str = "30770201010420bd37298383eb3d620da1ed367a9a0898e02443fadff0af783e1fbbfdf8250d95a00a06082a8648ce3d030107a144034200048bf54a359336ad068fc57282552526875f0884a8d5b3bc09716edcaa7e0b4443084eea5f2445fea6cfe558edf4a9efea2732efa2d5888b66be9b5b08101448c2";
static SERVER_SIG_CERT_HEX: &str = "3082017330820119a003020102021450fe87e05a3c00463e0a18387c3dbda92f4828fd300a06082a8648ce3d040302300f310d300b06035504030c0474657374301e170d3235313033303039333430395a170d3335313032383039333430395a300f310d300b06035504030c04746573743059301306072a8648ce3d020106082a8648ce3d030107034200048bf54a359336ad068fc57282552526875f0884a8d5b3bc09716edcaa7e0b4443084eea5f2445fea6cfe558edf4a9efea2732efa2d5888b66be9b5b08101448c2a3533051301d0603551d0e0416041461dd7c90fc9bdf91f8b4c3eaa0ceda715bd523f5301f0603551d2304183016801461dd7c90fc9bdf91f8b4c3eaa0ceda715bd523f5300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020348003045022100d0621bf50aee3ff00713393825f2993adc88a091d1f227e8a2319bc7a33b0e4302201a0276dcceabbf9e7dae50669d9186663f3f00a954e1d9eb87b844bd8733cfe4";

extern "C" fn shared_zone_init(shm_zone: *mut ngx_shm_zone_t, _data: *mut c_void) -> ngx_int_t {
    let mut pool =
        unsafe { SlabPool::from_shm_zone(shm_zone.as_ref().expect("shm_zone")) }.expect("SlabPool");

    if pool.as_mut().data.is_null() {
        let map: RwLock<Map> = RwLock::new(RbTreeMap::try_new_in(pool.clone()).expect("RbTreeMap"));

        let (server_keys, private_keys) = generate_asl_keys(30, "").unwrap();
        let signed_keys = server_keys
            .sign(
                &hex::decode(SERVER_SIG_CERT_HEX).unwrap(),
                &hex::decode(SERVER_SIG_SK_HEX).unwrap(),
                1,
            )
            .unwrap();

        let config = MaybeUninit::new(
            Config::new_with_keys(Environment::Testing, signed_keys, private_keys).unwrap(),
        );
        let shared = Shared { map, config };

        pool.as_mut().data = ngx::allocator::allocate(shared, &pool.clone())
            .expect("allocate")
            .as_ptr()
            .cast();
        Status::NGX_OK.into()
    } else {
        Status::NGX_ERROR.into()
    }
}
