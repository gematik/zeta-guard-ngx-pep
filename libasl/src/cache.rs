/*-
 * #%L
 * libasl
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

use super::server::{HandshakeState, SessionState};
use super::util::utc_now;
use std::collections::HashMap;
use std::sync::Mutex;

pub const CID_PREFIX: &'static str = "/ASL/";

pub trait SessionCache {
    fn init_handshake(&self, state: HandshakeState) -> String; // CID
    fn finish_handshake(&self, cid: &str) -> Option<HandshakeState>;
    /// The enc_ctr of the session should start at 0 here.
    fn start_session(&self, cid: &str, state: SessionState);
    /// Each invocation automatically increments the enc_ctr of the session, first call returns 1.
    /// Deletes sessions past their expires date and returns None instead.
    fn continue_session(&self, cid: &str) -> Option<SessionState>;
}

#[derive(Debug)]
pub enum ConnectionState {
    Handshaking(HandshakeState),
    Established(SessionState),
}

#[derive(Debug)]
pub struct MemorySessionCache {
    state: Mutex<HashMap<String, ConnectionState>>,
}

impl MemorySessionCache {
    pub fn new() -> Self {
        MemorySessionCache {
            state: Mutex::new(HashMap::new()),
        }
    }
}

pub fn new_cid() -> String {
    format!("{}{}", CID_PREFIX, uuid::Uuid::new_v4())
}

impl SessionCache for MemorySessionCache {
    fn init_handshake(&self, state: HandshakeState) -> String {
        let cid = new_cid();
        self.state
            .lock()
            .unwrap()
            .insert(cid.clone(), ConnectionState::Handshaking(state));
        cid
    }

    fn finish_handshake(&self, cid: &str) -> Option<HandshakeState> {
        let state = self.state.lock().unwrap().remove(cid)?;
        if let ConnectionState::Handshaking(state) = state {
            return Some(state);
        }
        None
    }

    fn start_session(&self, cid: &str, state: SessionState) {
        self.state
            .lock()
            .unwrap()
            .insert(cid.to_string(), ConnectionState::Established(state));
    }

    fn continue_session(&self, cid: &str) -> Option<SessionState> {
        let mut sessions = self.state.lock().unwrap();
        let state = sessions.get_mut(cid)?;
        if let ConnectionState::Established(state) = state {
            if state.expires > utc_now() {
                state.enc_ctr += 1;
                return Some(state.clone());
            } else {
                sessions.remove(cid);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::utc_now;

    #[test]
    fn it_handles_handshake_caching() {
        let cache = MemorySessionCache::new();

        let state1 = HandshakeState {
            ss_e: vec![1, 2, 3],
            transcript: vec![4, 5, 6],
        };

        let cid = cache.init_handshake(state1);
        assert!(cid.starts_with(CID_PREFIX));

        let maybe_state = cache.finish_handshake(&cid);
        assert!(maybe_state.is_some());

        let state2 = maybe_state.unwrap();
        assert_eq!(state2.ss_e, vec!(1, 2, 3));
        assert_eq!(state2.transcript, vec!(4, 5, 6));

        let again = cache.finish_handshake(&cid);
        assert!(again.is_none()); // gone after finish
    }

    #[test]
    fn it_handles_session_caching() {
        let cache = MemorySessionCache::new();

        let state1 = SessionState {
            key_id: vec![1, 2, 3],
            k2_c2s_app_data: vec![4, 5, 6],
            k2_s2c_app_data: vec![7, 8, 9],
            expires: utc_now() + 10,
            enc_ctr: 0,
        };

        let cid = String::from(CID_PREFIX) + "whatever";

        cache.start_session(&cid, state1);

        let maybe_state = cache.continue_session(&cid);
        assert!(maybe_state.is_some());

        let state2 = maybe_state.unwrap();
        assert_eq!(state2.key_id, vec!(1, 2, 3));
        assert_eq!(state2.k2_c2s_app_data, vec!(4, 5, 6));
        assert_eq!(state2.k2_s2c_app_data, vec!(7, 8, 9));
        assert_eq!(state2.enc_ctr, 1); // increased

        let again = cache.continue_session(&cid);
        assert!(again.is_some()); // still there for next request
        assert_eq!(again.unwrap().enc_ctr, 2); // increased
    }

    #[test]
    fn it_drops_expired_sessions() {
        let cache = MemorySessionCache::new();

        let state1 = SessionState {
            key_id: vec![],
            k2_c2s_app_data: vec![],
            k2_s2c_app_data: vec![],
            expires: 0, // epoch should be < now
            enc_ctr: 0,
        };

        let cid = String::from(CID_PREFIX) + "whatever";

        cache.start_session(&cid, state1);

        let maybe_state = cache.continue_session(&cid);
        assert!(maybe_state.is_none());
    }
}
