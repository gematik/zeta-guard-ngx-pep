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

use anyhow::anyhow;
use http::Uri;
use nginx_sys::{
    NGX_CONF_TAKE1, NGX_HTTP_LOC_CONF, NGX_HTTP_LOC_CONF_OFFSET, NGX_HTTP_MAIN_CONF,
    NGX_HTTP_MAIN_CONF_OFFSET, NGX_HTTP_SRV_CONF, NGX_LOG_EMERG, ngx_shm_zone_t, ngx_uint_t,
};
use ngx::{
    ffi::{ngx_command_t, ngx_conf_t, ngx_str_t},
    http::{HttpModuleLocationConf, HttpModuleMainConf, Merge, MergeConfigError},
    ngx_string,
};
use std::collections::HashSet;
use std::ptr;
use std::{
    ffi::{c_char, c_void},
    time::Duration,
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

#[derive(Debug, Clone, Default)]
pub enum OcspMode {
    Disable,
    #[default]
    Cert,
    Override(Uri),
}

// MAIN
#[derive(Debug, Clone)]
#[cfg_attr(test, allow(unused))]
pub struct MainConfig {
    pub pdp_issuer: Option<String>,
    pub popp_issuer: Option<String>,
    pub jwks_refresh_interval: Duration,
    pub http_client_connect_timeout: Duration,
    pub http_client_timeout: Duration,
    pub http_client_accept_invalid_certs: bool,
    pub no_travel: bool,
    pub asl_testing: bool,
    pub asl_signer_cert: Option<String>,
    pub asl_signer_key: Option<String>,
    pub asl_ca_cert: Option<String>,
    pub asl_roots_json: Option<String>,
    pub asl_root_ca: Option<String>,
    pub asl_ocsp: OcspMode,
    pub asl_ocsp_ttl: Duration,
    pub shm_zone: *mut ngx_shm_zone_t,
}

impl Default for MainConfig {
    fn default() -> Self {
        Self {
            pdp_issuer: None,
            popp_issuer: None,
            jwks_refresh_interval: Duration::from_secs(300), // NOTE: not exposed as directive r.n.
            http_client_connect_timeout: Duration::from_secs(2),
            http_client_timeout: Duration::from_secs(10),
            http_client_accept_invalid_certs: false,
            no_travel: false,
            asl_testing: false,
            asl_signer_cert: None,
            asl_signer_key: None,
            asl_ca_cert: None,
            asl_roots_json: None,
            asl_root_ca: None,
            asl_ocsp: Default::default(),
            asl_ocsp_ttl: Duration::from_hours(24), // A_24624-01 #1
            shm_zone: ptr::null_mut(),
        }
    }
}

impl MainConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.pdp_issuer.is_none() {
            anyhow::bail!("no issuer configured");
        }
        Ok(())
    }
}

unsafe impl HttpModuleMainConf for Module {
    type MainConf = MainConfig;
}

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

#[inline(always)]
fn non_empty(name: &str, val: &str) -> anyhow::Result<String> {
    let res = val.trim();
    if res.is_empty() {
        Err(anyhow!("{name} empty"))
    } else {
        Ok(res.to_string())
    }
}

// parse a duration spec of the form 1d, 2h, 30m or 45s; assumes given unit if no suffix
fn parse_duration(name: &str, def: char, val: &str) -> anyhow::Result<Duration> {
    let spec = val.trim();
    if spec.is_empty() {
        return Err(anyhow!("{name} empty"));
    }

    let last_char = spec.chars().last().unwrap();
    let (amount_str, unit) = if last_char.is_ascii_alphabetic() {
        (&spec[..spec.len() - 1], last_char)
    } else {
        (spec, def)
    };

    let amount: u64 = amount_str
        .parse()
        .map_err(|_| anyhow!("invalid number in {name}: {val}"))?;

    let duration = match unit {
        'd' => Duration::from_hours(amount * 24),
        'h' => Duration::from_hours(amount),
        'm' => Duration::from_mins(amount),
        's' => Duration::from_secs(amount),
        _ => return Err(anyhow!("invalid unit in {name}: {val}")),
    };

    Ok(duration)
}

conf_handler!(pep_asl_signer_cert, MainConfig, |conf: &mut MainConfig,
                                                val: &str|
 -> anyhow::Result<
    *mut c_char,
> {
    conf.asl_signer_cert = Some(non_empty("pep_asl_signer_cert", val)?);
    Ok(ngx::core::NGX_CONF_OK)
});

conf_handler!(pep_asl_signer_key, MainConfig, |conf: &mut MainConfig,
                                               val: &str|
 -> anyhow::Result<
    *mut c_char,
> {
    conf.asl_signer_key = Some(non_empty("pep_asl_signer_key", val)?);
    Ok(ngx::core::NGX_CONF_OK)
});

conf_handler!(pep_asl_ca_cert, MainConfig, |conf: &mut MainConfig,
                                            val: &str|
 -> anyhow::Result<
    *mut c_char,
> {
    conf.asl_ca_cert = Some(non_empty("pep_asl_ca_cert", val)?);
    Ok(ngx::core::NGX_CONF_OK)
});

conf_handler!(pep_asl_roots_json, MainConfig, |conf: &mut MainConfig,
                                               val: &str|
 -> anyhow::Result<
    *mut c_char,
> {
    conf.asl_roots_json = Some(non_empty("pep_asl_roots_json", val)?);
    Ok(ngx::core::NGX_CONF_OK)
});

conf_handler!(pep_asl_root_ca, MainConfig, |conf: &mut MainConfig,
                                            val: &str|
 -> anyhow::Result<
    *mut c_char,
> {
    conf.asl_root_ca = Some(non_empty("pep_asl_root_ca", val)?);
    Ok(ngx::core::NGX_CONF_OK)
});

conf_handler!(pep_asl_ocsp, MainConfig, |conf: &mut MainConfig,
                                         val: &str|
 -> anyhow::Result<
    *mut c_char,
> {
    let asl_ocsp = non_empty("pep_asl_ocsp", val)?;
    let asl_ocsp = match asl_ocsp.to_ascii_lowercase().as_str() {
        "off" => OcspMode::Disable,
        "cert" => OcspMode::Cert,
        _ => OcspMode::Override(asl_ocsp.parse().expect("unparseable pep_asl_ocsp")),
    };
    conf.asl_ocsp = asl_ocsp;

    Ok(ngx::core::NGX_CONF_OK)
});

conf_handler!(pep_asl_ocsp_ttl, MainConfig, |conf: &mut MainConfig,
                                             val: &str|
 -> anyhow::Result<
    *mut c_char,
> {
    conf.asl_ocsp_ttl = parse_duration("pep_asl_ocsp_ttl", 'm', val)?;
    Ok(ngx::core::NGX_CONF_OK)
});

conf_handler!(pep_asl_testing, MainConfig, |conf: &mut MainConfig,
                                            val: &str|
 -> anyhow::Result<
    *mut c_char,
> {
    if val.eq_ignore_ascii_case("on") {
        conf.asl_testing = true;
    } else if val.eq_ignore_ascii_case("off") {
        conf.asl_testing = false;
    } else {
        anyhow::bail!("Unable to parse asl_testing: {val}")
    }

    Ok(ngx::core::NGX_CONF_OK)
});

conf_handler!(pep_no_travel, MainConfig, |conf: &mut MainConfig,
                                          val: &str|
 -> anyhow::Result<
    *mut c_char,
> {
    if val.eq_ignore_ascii_case("on") {
        conf.no_travel = true;
    } else if val.eq_ignore_ascii_case("off") {
        conf.no_travel = false;
    } else {
        anyhow::bail!("Unable to parse no_travel: {val}")
    }
    Ok(ngx::core::NGX_CONF_OK)
});

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
    pub popp_validity: Option<PoppValidity>,

    pub forward_client_data: Option<bool>,
}

/// How long a PoPP token is considered valid. See gemSpec_Zeta_Guide_PoPP
/// §3.x: operators must be able to pick either a fixed duration since `iat`,
/// or a "same calendar quarter" rule (matching the German statutory
/// healthcare billing cycle).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PoppValidity {
    /// Token valid for this duration after `iat`.
    Fixed(Duration),
    /// Token valid while `iat` and the check time are in the same calendar
    /// quarter (UTC).
    Quarter,
}

impl LocationConfig {
    pub fn leeway(&self) -> Duration {
        self.leeway.unwrap_or_else(|| Duration::from_secs(60))
    }
    pub fn dpop_validity(&self) -> Duration {
        self.dpop_validity
            .unwrap_or_else(|| Duration::from_secs(300))
    }
    pub fn popp_validity(&self) -> PoppValidity {
        self.popp_validity.unwrap_or(PoppValidity::Quarter)
    }
    /// Unix epoch second up to which a PoPP token with the given `iat` is
    /// considered valid, including `leeway`.
    pub fn popp_valid_until(&self, iat: i64, leeway: i64) -> i64 {
        match self.popp_validity() {
            PoppValidity::Fixed(d) => iat + d.as_secs() as i64 + leeway,
            PoppValidity::Quarter => end_of_quarter_utc(iat) + leeway,
        }
    }
}

/// Last Unix epoch second of the UTC calendar quarter containing `epoch`.
fn end_of_quarter_utc(epoch: i64) -> i64 {
    let t: libc::time_t = epoch as _;
    let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
    let tm = unsafe {
        libc::gmtime_r(&t, tm.as_mut_ptr());
        tm.assume_init()
    };
    // tm_mon: 0=Jan..11=Dec. Quarter index 0..3 = tm_mon / 3.
    // First month of next quarter = (q + 1) * 3, wrapping into next year at 12.
    let (next_y, next_m) = match tm.tm_mon / 3 {
        0 => (tm.tm_year, 3),     // Q1 (Jan-Mar) → Apr
        1 => (tm.tm_year, 6),     // Q2 (Apr-Jun) → Jul
        2 => (tm.tm_year, 9),     // Q3 (Jul-Sep) → Oct
        _ => (tm.tm_year + 1, 0), // Q4 (Oct-Dec) → Jan (next year)
    };
    let mut next_q_start = libc::tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 1,
        tm_mon: next_m,
        tm_year: next_y,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: std::ptr::null_mut(),
    };
    let next_q_start_epoch = unsafe { libc::timegm(&mut next_q_start) };
    next_q_start_epoch as i64 - 1
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
        let validity = if val.eq_ignore_ascii_case("quarter") {
            PoppValidity::Quarter
        } else {
            PoppValidity::Fixed(parse_duration("pep_popp_validity", 's', val)?)
        };
        conf.popp_validity = Some(validity);

        Ok(ngx::core::NGX_CONF_OK)
    }
);

conf_handler!(
    pep_forward_client_data,
    LocationConfig,
    |conf: &mut LocationConfig, val: &str| -> anyhow::Result<*mut c_char> {
        if val.eq_ignore_ascii_case("on") {
            conf.forward_client_data = Some(true);
        } else if val.eq_ignore_ascii_case("off") {
            conf.forward_client_data = Some(false);
        } else {
            anyhow::bail!("Unable to parse pep_forward_client_data: {val}")
        }

        Ok(ngx::core::NGX_CONF_OK)
    }
);

pub(crate) static mut NGX_HTTP_PEP_COMMANDS: [ngx_command_t; 24] = [
    main_command!("pep_pdp_issuer", pep_pdp_issuer),
    main_command!("pep_popp_issuer", pep_popp_issuer),
    main_command!(
        "pep_http_client_connect_timeout",
        pep_http_client_connect_timeout
    ),
    main_command!("pep_http_client_timeout", pep_http_client_timeout),
    main_command!(
        "pep_http_client_accept_invalid_certs",
        pep_http_client_accept_invalid_certs
    ),
    main_command!("pep_no_travel", pep_no_travel),
    main_command!("pep_asl_testing", pep_asl_testing),
    main_command!("pep_asl_signer_cert", pep_asl_signer_cert),
    main_command!("pep_asl_signer_key", pep_asl_signer_key),
    main_command!("pep_asl_ca_cert", pep_asl_ca_cert),
    main_command!("pep_asl_roots_json", pep_asl_roots_json),
    main_command!("pep_asl_root_ca", pep_asl_root_ca),
    main_command!("pep_asl_ocsp", pep_asl_ocsp),
    main_command!("pep_asl_ocsp_ttl", pep_asl_ocsp_ttl),
    loc_command!("pep", pep),
    loc_command!("pep_require_aud", pep_require_aud),
    loc_command!("pep_require_scope", pep_require_scope),
    loc_command!("pep_leeway", pep_leeway),
    loc_command!("pep_dpop_validity", pep_dpop_validity),
    loc_command!("pep_require_popp", pep_require_popp),
    loc_command!("pep_popp_validity", pep_popp_validity),
    loc_command!("pep_forward_client_data", pep_forward_client_data),
    loc_command!("asl", asl),
    // terminate sequence
    ngx_command_t::empty(),
];

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::time::Duration;

    use ngx::http::Merge;

    use crate::conf::{LocationConfig, PoppValidity, end_of_quarter_utc};

    /// Days within a given UTC year and month (1-based day)
    fn utc_epoch(year: i32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> i64 {
        let mut tm = libc::tm {
            tm_sec: sec as i32,
            tm_min: min as i32,
            tm_hour: hour as i32,
            tm_mday: day as i32,
            tm_mon: month as i32 - 1,
            tm_year: year - 1900,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: 0,
            tm_gmtoff: 0,
            tm_zone: std::ptr::null_mut(),
        };
        unsafe { libc::timegm(&mut tm) as i64 }
    }

    #[test]
    fn end_of_q1() {
        // Mid-Feb 2026 → Mar 31 23:59:59 UTC
        let iat = utc_epoch(2026, 2, 15, 12, 0, 0);
        let expected = utc_epoch(2026, 3, 31, 23, 59, 59);
        assert_eq!(end_of_quarter_utc(iat), expected);
    }

    #[test]
    fn end_of_q2() {
        let iat = utc_epoch(2026, 5, 15, 12, 0, 0);
        let expected = utc_epoch(2026, 6, 30, 23, 59, 59);
        assert_eq!(end_of_quarter_utc(iat), expected);
    }

    #[test]
    fn end_of_q3() {
        let iat = utc_epoch(2026, 8, 15, 12, 0, 0);
        let expected = utc_epoch(2026, 9, 30, 23, 59, 59);
        assert_eq!(end_of_quarter_utc(iat), expected);
    }

    #[test]
    fn end_of_q4() {
        // Dec 15 2026 → Dec 31 2026 23:59:59 (not Jan 1 2027)
        let iat = utc_epoch(2026, 11, 15, 12, 0, 0);
        let expected = utc_epoch(2026, 12, 31, 23, 59, 59);
        assert_eq!(end_of_quarter_utc(iat), expected);
    }

    #[test]
    fn end_of_quarter_at_exact_last_second() {
        // iat = last second of Q2 → returns itself
        let iat = utc_epoch(2026, 6, 30, 23, 59, 59);
        assert_eq!(end_of_quarter_utc(iat), iat);
    }

    #[test]
    fn end_of_quarter_at_quarter_start() {
        // iat = first second of Q3 → returns last second of Q3
        let iat = utc_epoch(2026, 7, 1, 0, 0, 0);
        let expected = utc_epoch(2026, 9, 30, 23, 59, 59);
        assert_eq!(end_of_quarter_utc(iat), expected);
    }

    #[test]
    fn end_of_quarter_leap_year_q1() {
        // 2024 is a leap year; Feb 29 is in Q1, end is still Mar 31
        let iat = utc_epoch(2024, 2, 29, 12, 0, 0);
        let expected = utc_epoch(2024, 3, 31, 23, 59, 59);
        assert_eq!(end_of_quarter_utc(iat), expected);
    }

    #[test]
    fn popp_valid_until_seconds_mode() {
        let cfg = LocationConfig {
            popp_validity: Some(PoppValidity::Fixed(Duration::from_secs(3600))),
            ..Default::default()
        };
        assert_eq!(cfg.popp_valid_until(1_000_000, 60), 1_000_000 + 3600 + 60);
    }

    #[test]
    fn popp_valid_until_quarter_mode() {
        let cfg = LocationConfig {
            popp_validity: Some(PoppValidity::Quarter),
            ..Default::default()
        };
        let iat = utc_epoch(2026, 5, 15, 12, 0, 0); // Q2
        let end_q2 = utc_epoch(2026, 6, 30, 23, 59, 59);
        assert_eq!(cfg.popp_valid_until(iat, 60), end_q2 + 60);
    }

    #[test]
    fn popp_valid_until_default_is_quarter() {
        // Unconfigured → Quarter semantics (matches TODO from prior implementation).
        let cfg = LocationConfig::default();
        let iat = utc_epoch(2026, 5, 15, 12, 0, 0);
        let end_q2 = utc_epoch(2026, 6, 30, 23, 59, 59);
        assert_eq!(cfg.popp_valid_until(iat, 0), end_q2);
    }

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
            forward_client_data: None,
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
            forward_client_data: None,
        };
        child.merge(&parent).expect("merge");
        assert_eq!(child.pep, Some(false));
        assert_eq!(child.aud, None);
        assert_eq!(child.scope, Some(some_scope));
        assert_eq!(child.leeway, Some(some_duration));
    }
}
