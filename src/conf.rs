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

use nginx_sys::{
    NGX_CONF_TAKE1, NGX_HTTP_LOC_CONF, NGX_HTTP_LOC_CONF_OFFSET, NGX_HTTP_MAIN_CONF,
    NGX_HTTP_MAIN_CONF_OFFSET, NGX_HTTP_SRV_CONF, NGX_LOG_EMERG, ngx_shm_zone_t, ngx_uint_t,
};
use std::collections::HashSet;
use std::ptr;
use std::{
    ffi::{c_char, c_void},
    time::Duration,
};

use ngx::{
    ffi::{ngx_command_t, ngx_conf_t, ngx_str_t},
    http::{HttpModuleLocationConf, HttpModuleMainConf, Merge, MergeConfigError},
    ngx_string,
};

use ngx::ngx_conf_log_error;

use crate::Module;

// simple macro to avoid boilerplate for conf command definition
macro_rules! conf_handler {
    ( $name: ident, $type: ident, $handler: expr ) => {
        extern "C" fn $name(
            cf: *mut ngx_conf_t,
            _cmd: *mut ngx_command_t,
            conf: *mut c_void,
        ) -> *mut c_char {
            let conf = unsafe { &mut *(conf as *mut $type) };
            let args: &[ngx_str_t] = unsafe { (*(*cf).args).as_slice() };

            let val = match args[1].to_str() {
                Ok(s) => s,
                Err(_) => {
                    ngx_conf_log_error!(NGX_LOG_EMERG, cf, "`$name` argument is not utf-8 encoded");
                    return ngx::core::NGX_CONF_ERROR;
                }
            };
            let result = $handler(conf, val);
            match result {
                Ok(s) => s,
                Err(e) => {
                    ngx_conf_log_error!(NGX_LOG_EMERG, cf, "`$name`: {e}");
                    ngx::core::NGX_CONF_ERROR
                }
            }
        }
    };
}

// command valid in http context only
macro_rules! main_command {
    ($name: expr, $handler: ident) => {
        ngx_command_t {
            name: ngx_string!($name),
            type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
            set: Some($handler),
            conf: NGX_HTTP_MAIN_CONF_OFFSET,
            offset: 0,
            post: std::ptr::null_mut(),
        }
    };
}

// command valid in http, server, and location contexts
macro_rules! loc_command {
    ($name: expr, $handler: ident) => {
        ngx_command_t {
            name: ngx_string!($name),
            type_: (NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1)
                as ngx_uint_t,
            set: Some($handler),
            conf: NGX_HTTP_LOC_CONF_OFFSET,
            offset: 0,
            post: std::ptr::null_mut(),
        }
    };
}

// MAIN
#[derive(Debug, Clone)]
pub struct MainConfig {
    pub pdp_issuer: Option<String>,
    pub popp_issuer: Option<String>,
    pub jwks_refresh_interval: Duration,
    pub http_client_idle_timeout: Duration,
    pub http_client_max_idle_per_host: usize,
    pub http_client_tcp_keepalive: Duration,
    pub http_client_connect_timeout: Duration,
    pub http_client_timeout: Duration,
    pub http_client_accept_invalid_certs: bool,
    pub asl_testing: bool,
    pub shm_zone: *mut ngx_shm_zone_t,
}

impl Default for MainConfig {
    fn default() -> Self {
        Self {
            pdp_issuer: None,
            popp_issuer: None,
            jwks_refresh_interval: Duration::from_secs(300), // NOTE: not exposed as directive r.n.
            http_client_idle_timeout: Duration::from_secs(30),
            http_client_max_idle_per_host: 64,
            http_client_tcp_keepalive: Duration::from_secs(30),
            http_client_connect_timeout: Duration::from_secs(2),
            http_client_timeout: Duration::from_secs(10),
            http_client_accept_invalid_certs: false,
            asl_testing: false,
            shm_zone: ptr::null_mut(),
        }
    }
}

impl MainConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.pdp_issuer.is_none() {
            anyhow::bail!("no issuer configured");
        }
        if self.popp_issuer.is_none() {
            anyhow::bail!("no issuer configured");
        }
        Ok(())
    }
}

unsafe impl HttpModuleMainConf for Module {
    type MainConf = MainConfig;
}

conf_handler!(
    pep_http_client_idle_timeout,
    MainConfig,
    |conf: &mut MainConfig, val: &str| -> anyhow::Result<*mut c_char> {
        let val = Duration::from_secs(val.parse()?);
        conf.http_client_idle_timeout = val;

        Ok(ngx::core::NGX_CONF_OK)
    }
);

conf_handler!(
    pep_http_client_max_idle_per_host,
    MainConfig,
    |conf: &mut MainConfig, val: &str| -> anyhow::Result<*mut c_char> {
        let val: usize = val.parse()?;
        conf.http_client_max_idle_per_host = val;

        Ok(ngx::core::NGX_CONF_OK)
    }
);

conf_handler!(
    pep_http_client_tcp_keepalive,
    MainConfig,
    |conf: &mut MainConfig, val: &str| -> anyhow::Result<*mut c_char> {
        let val = Duration::from_secs(val.parse()?);
        conf.http_client_tcp_keepalive = val;

        Ok(ngx::core::NGX_CONF_OK)
    }
);

conf_handler!(
    pep_http_client_connect_timeout,
    MainConfig,
    |conf: &mut MainConfig, val: &str| -> anyhow::Result<*mut c_char> {
        let val = Duration::from_secs(val.parse()?);
        conf.http_client_connect_timeout = val;

        Ok(ngx::core::NGX_CONF_OK)
    }
);

conf_handler!(
    pep_http_client_timeout,
    MainConfig,
    |conf: &mut MainConfig, val: &str| -> anyhow::Result<*mut c_char> {
        let val = Duration::from_secs(val.parse()?);
        conf.http_client_timeout = val;

        Ok(ngx::core::NGX_CONF_OK)
    }
);

conf_handler!(
    pep_http_client_accept_invalid_certs,
    MainConfig,
    |conf: &mut MainConfig, val: &str| -> anyhow::Result<*mut c_char> {
        if val.eq_ignore_ascii_case("on") {
            conf.http_client_accept_invalid_certs = true;
        } else if val.eq_ignore_ascii_case("off") {
            conf.http_client_accept_invalid_certs = false;
        } else {
            anyhow::bail!("Unable to parse http_client_accept_invalid_certs: {val}")
        }

        Ok(ngx::core::NGX_CONF_OK)
    }
);

conf_handler!(pep_pdp_issuer, MainConfig, |conf: &mut MainConfig,
                                           val: &str|
 -> anyhow::Result<
    *mut c_char,
> {
    if val.trim().is_empty() {
        anyhow::bail!("pep_pdp_issuer empty");
    }
    conf.pdp_issuer = Some(val.to_string());

    Ok(ngx::core::NGX_CONF_OK)
});

conf_handler!(pep_popp_issuer, MainConfig, |conf: &mut MainConfig,
                                            val: &str|
 -> anyhow::Result<
    *mut c_char,
> {
    if val.trim().is_empty() {
        anyhow::bail!("pep_popp_issuer empty");
    }
    conf.popp_issuer = Some(val.to_string());

    Ok(ngx::core::NGX_CONF_OK)
});

conf_handler!(
    pep_asl_testing,
    MainConfig,
    |conf: &mut MainConfig, val: &str| -> anyhow::Result<*mut c_char> {
        if val.eq_ignore_ascii_case("on") {
            conf.asl_testing = true;
        } else if val.eq_ignore_ascii_case("off") {
            conf.asl_testing = false;
        } else {
            anyhow::bail!("Unable to parse asl_testing: {val}")
        }

        Ok(ngx::core::NGX_CONF_OK)
    }
);

// LOCATION

#[derive(Debug, Default, Clone)]
pub struct LocationConfig {
    pub pep: Option<bool>,
    pub asl: Option<bool>,

    pub aud: Option<HashSet<String>>,
    pub scope: Option<HashSet<String>>,
    pub leeway: Option<Duration>,
    pub dpop_validity: Option<Duration>,

    pub require_popp: Option<bool>,
    pub popp_validity: Option<Duration>,
}

impl LocationConfig {
    pub fn leeway(&self) -> Duration {
        self.leeway.unwrap_or_else(|| Duration::from_secs(60))
    }
    pub fn dpop_validity(&self) -> Duration {
        self.dpop_validity
            .unwrap_or_else(|| Duration::from_secs(300))
    }
    pub fn ppop_validity(&self) -> Duration {
        self.popp_validity
            .unwrap_or_else(|| Duration::from_secs(31536000)) // TODO: update default
    }
}

unsafe impl HttpModuleLocationConf for Module {
    type LocationConf = LocationConfig;
}

impl Merge for LocationConfig {
    fn merge(&mut self, prev: &LocationConfig) -> Result<(), MergeConfigError> {
        if self.pep.is_none() {
            self.pep = prev.pep;
        }
        if self.aud.is_none() {
            self.aud = prev.aud.clone();
        }
        if self.scope.is_none() {
            self.scope = prev.scope.clone();
        }
        if self.leeway.is_none() {
            self.leeway = prev.leeway;
        }
        if self.dpop_validity.is_none() {
            self.dpop_validity = prev.dpop_validity;
        }
        if self.require_popp.is_none() {
            self.require_popp = prev.require_popp;
        }
        if self.popp_validity.is_none() {
            self.popp_validity = prev.popp_validity;
        }

        Ok(())
    }
}

conf_handler!(pep, LocationConfig, |conf: &mut LocationConfig,
                                    val: &str|
 -> anyhow::Result<*mut c_char> {
    if val.eq_ignore_ascii_case("on") {
        conf.pep = Some(true);
    } else if val.eq_ignore_ascii_case("off") {
        conf.pep = Some(false);
    } else {
        anyhow::bail!("Unable to parse pep: {val}")
    }

    Ok(ngx::core::NGX_CONF_OK)
});

conf_handler!(asl, LocationConfig, |conf: &mut LocationConfig,
                                    val: &str|
 -> anyhow::Result<*mut c_char> {
    if val.eq_ignore_ascii_case("on") {
        conf.asl = Some(true);
    } else if val.eq_ignore_ascii_case("off") {
        conf.asl = Some(false);
    } else {
        anyhow::bail!("Unable to parse asl: {val}")
    }

    Ok(ngx::core::NGX_CONF_OK)
});

conf_handler!(
    pep_require_aud,
    LocationConfig,
    |conf: &mut LocationConfig, val: &str| -> anyhow::Result<*mut c_char> {
        conf.aud = Some(HashSet::from_iter(
            val.trim().split(" ").map(str::to_string),
        ));

        Ok(ngx::core::NGX_CONF_OK)
    }
);

conf_handler!(
    pep_require_scope,
    LocationConfig,
    |conf: &mut LocationConfig, val: &str| -> anyhow::Result<*mut c_char> {
        conf.scope = Some(HashSet::from_iter(
            val.trim().split(" ").map(str::to_string),
        ));

        Ok(ngx::core::NGX_CONF_OK)
    }
);

conf_handler!(pep_leeway, LocationConfig, |conf: &mut LocationConfig,
                                           val: &str|
 -> anyhow::Result<
    *mut c_char,
> {
    let val = Duration::from_secs(val.parse()?);

    conf.leeway = Some(val);

    Ok(ngx::core::NGX_CONF_OK)
});

conf_handler!(
    pep_dpop_validity,
    LocationConfig,
    |conf: &mut LocationConfig, val: &str| -> anyhow::Result<*mut c_char> {
        let val = Duration::from_secs(val.parse()?);

        conf.dpop_validity = Some(val);

        Ok(ngx::core::NGX_CONF_OK)
    }
);

conf_handler!(
    pep_require_popp,
    LocationConfig,
    |conf: &mut LocationConfig, val: &str| -> anyhow::Result<*mut c_char> {
        if val.eq_ignore_ascii_case("on") {
            conf.require_popp = Some(true);
        } else if val.eq_ignore_ascii_case("off") {
            conf.require_popp = Some(false);
        } else {
            anyhow::bail!("Unable to parse pep_require_popp: {val}")
        }

        Ok(ngx::core::NGX_CONF_OK)
    }
);

conf_handler!(
    pep_popp_validity,
    LocationConfig,
    |conf: &mut LocationConfig, val: &str| -> anyhow::Result<*mut c_char> {
        let val = Duration::from_secs(val.parse()?);

        conf.dpop_validity = Some(val);

        Ok(ngx::core::NGX_CONF_OK)
    }
);

pub(crate) static mut NGX_HTTP_PEP_COMMANDS: [ngx_command_t; 18] = [
    main_command!("pep_pdp_issuer", pep_pdp_issuer),
    main_command!("pep_popp_issuer", pep_popp_issuer),
    main_command!("pep_http_client_idle_timeout", pep_http_client_idle_timeout),
    main_command!(
        "pep_http_client_max_idle_per_host",
        pep_http_client_max_idle_per_host
    ),
    main_command!(
        "pep_http_client_tcp_keepalive",
        pep_http_client_tcp_keepalive
    ),
    main_command!(
        "pep_http_client_connect_timeout",
        pep_http_client_connect_timeout
    ),
    main_command!("pep_http_client_timeout", pep_http_client_timeout),
    main_command!(
        "pep_http_client_accept_invalid_certs",
        pep_http_client_accept_invalid_certs
    ),
    main_command!("pep_asl_testing", pep_asl_testing),
    loc_command!("pep", pep),
    loc_command!("pep_require_aud", pep_require_aud),
    loc_command!("pep_require_scope", pep_require_scope),
    loc_command!("pep_leeway", pep_leeway),
    loc_command!("pep_dpop_validity", pep_dpop_validity),
    loc_command!("pep_require_popp", pep_require_popp),
    loc_command!("pep_popp_validity", pep_popp_validity),
    loc_command!("asl", asl),
    // terminate sequence
    ngx_command_t::empty(),
];

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::time::Duration;

    use ngx::http::Merge;

    use crate::conf::LocationConfig;

    #[test]
    fn merge_inherits_unset_values() {
        let some_scope = HashSet::from_iter(["scope".to_string()]);
        let some_duration = Duration::from_secs(123);
        let parent = LocationConfig {
            pep: Some(true),
            asl: None,
            aud: None,
            scope: Some(some_scope.clone()),
            leeway: None,
            dpop_validity: None,
            require_popp: None,
            popp_validity: None,
        };
        let mut child = LocationConfig {
            pep: Some(false),
            asl: None,
            aud: None,
            scope: None,
            leeway: Some(some_duration),
            dpop_validity: None,
            require_popp: None,
            popp_validity: None,
        };
        child.merge(&parent).expect("merge");
        assert_eq!(child.pep, Some(false));
        assert_eq!(child.aud, None);
        assert_eq!(child.scope, Some(some_scope));
        assert_eq!(child.leeway, Some(some_duration));
    }
}
