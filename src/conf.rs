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
    NGX_HTTP_MAIN_CONF_OFFSET, NGX_HTTP_SRV_CONF, NGX_LOG_EMERG, ngx_uint_t,
};
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
            type_: (NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
            set: Some($handler),
            conf: NGX_HTTP_LOC_CONF_OFFSET,
            offset: 0,
            post: std::ptr::null_mut(),
        }
    };
}

// MAIN
#[derive(Debug)]
pub(crate) struct MainConfig {
    pub issuer: Option<String>,
    pub jwks_refresh_interval: Duration,
    pub http_client_idle_timeout: Duration,
    pub http_client_max_idle_per_host: usize,
    pub http_client_tcp_keepalive: Duration,
    pub http_client_connect_timeout: Duration,
    pub http_client_timeout: Duration,
    pub http_client_accept_invalid_certs: bool,
}

impl Default for MainConfig {
    fn default() -> Self {
        Self {
            issuer: None,
            jwks_refresh_interval: Duration::from_secs(300), // NOTE: not exposed as directive r.n.
            http_client_idle_timeout: Duration::from_secs(30),
            http_client_max_idle_per_host: 64,
            http_client_tcp_keepalive: Duration::from_secs(30),
            http_client_connect_timeout: Duration::from_secs(2),
            http_client_timeout: Duration::from_secs(10),
            http_client_accept_invalid_certs: false,
        }
    }
}

impl MainConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.issuer.is_none() {
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

conf_handler!(pep_issuer, MainConfig, |conf: &mut MainConfig,
                                       val: &str|
 -> anyhow::Result<*mut c_char> {
    if val.trim().is_empty() {
        anyhow::bail!("issuer empty");
    }
    conf.issuer = Some(val.to_string());

    Ok(ngx::core::NGX_CONF_OK)
});

// LOCATION

#[derive(Debug)]
pub(crate) struct LocationConfig {
    pub enable: bool,

    pub require_aud_any: Option<Vec<String>>, // optional
    pub require_scope: Option<String>,        // optional
    pub leeway: Duration,
}

impl Default for LocationConfig {
    fn default() -> Self {
        Self {
            enable: false,
            require_aud_any: None,
            require_scope: None,
            leeway: Duration::from_secs(60),
        }
    }
}

unsafe impl HttpModuleLocationConf for Module {
    type LocationConf = LocationConfig;
}

impl Merge for LocationConfig {
    fn merge(&mut self, prev: &LocationConfig) -> Result<(), MergeConfigError> {
        if prev.enable {
            self.enable = true;
        };

        if let Some(require_aud) = &prev.require_aud_any {
            self.require_aud_any = Some(require_aud.clone());
        }

        if let Some(require_scope) = &prev.require_scope {
            self.require_scope = Some(require_scope.clone());
        }
        self.leeway = prev.leeway;

        Ok(())
    }
}

conf_handler!(pep, LocationConfig, |conf: &mut LocationConfig,
                                    val: &str|
 -> anyhow::Result<*mut c_char> {
    if val.eq_ignore_ascii_case("on") {
        conf.enable = true;
    } else if val.eq_ignore_ascii_case("off") {
        conf.enable = false;
    } else {
        anyhow::bail!("Unable to parse pep: {val}")
    }

    Ok(ngx::core::NGX_CONF_OK)
});

conf_handler!(
    pep_require_aud_any,
    LocationConfig,
    |conf: &mut LocationConfig, val: &str| -> anyhow::Result<*mut c_char> {
        if !val.trim().is_empty() {
            conf.require_aud_any = Some(val.trim().split("|").map(str::to_string).collect());
        }

        Ok(ngx::core::NGX_CONF_OK)
    }
);

conf_handler!(
    pep_require_scope,
    LocationConfig,
    |conf: &mut LocationConfig, val: &str| -> anyhow::Result<*mut c_char> {
        if !val.trim().is_empty() {
            conf.require_scope = Some(val.to_string());
        }

        Ok(ngx::core::NGX_CONF_OK)
    }
);

conf_handler!(pep_leeway, LocationConfig, |conf: &mut LocationConfig,
                                           val: &str|
 -> anyhow::Result<
    *mut c_char,
> {
    let val = Duration::from_secs(val.parse()?);
    conf.leeway = val;

    Ok(ngx::core::NGX_CONF_OK)
});

pub(crate) static mut NGX_HTTP_PEP_COMMANDS: [ngx_command_t; 12] = [
    main_command!("pep_issuer", pep_issuer),
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
    loc_command!("pep", pep),
    loc_command!("pep_require_aud_any", pep_require_aud_any),
    loc_command!("pep_require_scope", pep_require_scope),
    loc_command!("pep_leeway", pep_leeway),
    // terminate sequence
    ngx_command_t::empty(),
];
