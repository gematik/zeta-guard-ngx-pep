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

use anyhow::{Result, anyhow, bail};
use http::Uri;
use nginx_sys::{ngx_http_core_main_conf_t, ngx_http_core_srv_conf_t};
use ngx::http::{
    HttpModuleLocationConf, HttpModuleMainConf, HttpModuleServerConf, NgxHttpCoreModule, Request,
};

use crate::Module;
use crate::conf::{LocationConfig, MainConfig};

#[cfg(test)]
use {ambassador::delegatable_trait, mockall::automock};

#[cfg_attr(test, delegatable_trait)]
#[cfg_attr(test, automock)]
pub trait RequestOps {
    fn method(&self) -> String;
    fn self_uri(&self) -> anyhow::Result<http::Uri>;
    fn get_authorization_token(&self) -> anyhow::Result<String>;
    #[allow(clippy::needless_lifetimes)] // automock
    fn get_header_in<'a, 'b>(&'a self, name: &'b str) -> Option<&'a str>;
    #[allow(clippy::needless_lifetimes)] // automock
    fn get_header_out<'a, 'b>(&'a self, name: &'b str) -> Option<&'a str>;
    // additional *request* headers, e.g. passed to upstream
    fn ensure_header_in(&mut self, name: &str, value: &str) -> anyhow::Result<()>;
    // additional *response* headers, will be added to response headers from upstream
    fn ensure_header_out(&mut self, name: &str, value: &str) -> anyhow::Result<()>;
    fn acceptable(&self, content_type: &str) -> anyhow::Result<bool>;
}

fn split_authority(authority: &str) -> Result<(&str, Option<u16>)> {
    if authority.is_empty() {
        bail!("empty authority");
    }

    // IPv6 literal: [2001:db8::1]:443
    if authority.starts_with('[') {
        if let Some(end) = authority.find(']') {
            let host = &authority[..=end]; // include brackets
            let rest = &authority[end + 1..];
            if let Some(port_str) = rest.strip_prefix(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    return Ok((host, Some(port)));
                } else {
                    // port indicated, but unparseable
                    return Err(anyhow!("unparseable port {port_str}"));
                }
            }
            return Ok((host, None));
        }
    }

    // host or host:port
    if let Some(idx) = authority.rfind(':') {
        let (h, p) = authority.split_at(idx);
        let port_str = &p[1..];
        if let Ok(port) = port_str.parse::<u16>() {
            return Ok((h, Some(port)));
        } else {
            // port indicated, but unparseable
            return Err(anyhow!("unparseable port {port_str}"));
        }
    }

    Ok((authority, None))
}

// RFC 7239 "Forwarded"
fn try_parse_forwarded(forwarded: Option<&str>) -> Option<(&str, &str, Option<u16>)> {
    forwarded.and_then(|forwarded| {
        let elem = forwarded.split(',').next().unwrap_or("").trim();
        let mut proto = None;
        let mut host = None;

        for part in elem.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let mut kv = part.splitn(2, '=');
            let key = kv.next().unwrap().trim().to_ascii_lowercase();
            let val = kv.next().unwrap_or("").trim().trim_matches('"');

            match key.as_str() {
                "proto" => proto = Some(val),
                "host" => host = Some(val),
                _ => {}
            }
        }
        match host {
            Some(host) => match split_authority(&host) {
                Ok((host, port)) => Some((proto.unwrap_or("https"), host, port)),
                Err(_) => None,
            },
            None => None,
        }
    })
}

fn try_parse_xforwarded<'a>(
    xfpr: Option<&'a str>,
    xfh: Option<&'a str>,
    xfpo: Option<&'a str>,
) -> Option<(&'a str, &'a str, Option<u16>)> {
    xfh.map(|xfh| match xfh.split_once(",") {
        Some((first, _)) => first.trim(),
        None => xfh.trim(),
    })
    .and_then(|host| {
        let xfpr = xfpr.unwrap_or("https");
        let proto = match xfpr.split_once(",") {
            Some((proto, _)) => proto.trim(),
            None => xfpr.trim(),
        };
        match xfpo.map(|xfpo| {
            match xfpo.split_once(",") {
                Some((port, _)) => port,
                None => xfpo,
            }
            .trim()
            .parse::<u16>()
        }) {
            Some(Ok(port)) => Some((proto, host, Some(port))),
            Some(Err(_)) => None,
            None => Some((proto, host, None)),
        }
    })
}

fn try_parse_host(host: Option<&str>) -> Option<(&str, &str, Option<u16>)> {
    host.and_then(|host| match split_authority(host.trim()) {
        Ok((host, port)) => Some(("https", host, port)),
        Err(_) => None,
    })
}

pub fn normalized_uri(scheme: &str, host: &str, port: Option<u16>, path: &str) -> Result<Uri> {
    let scheme = scheme.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    let port = port
        .or(match scheme.as_str() {
            "https" => Some(443),
            "http" => Some(80),
            _ => None,
        })
        .ok_or_else(|| anyhow!("unknown scheme {scheme} and no port specified"))?;

    let uri = match (scheme.as_str(), port) {
        ("https", 443) => format!("https://{}{}", host, path),
        ("https", port) => format!("https://{}:{}{}", host, port, path),
        ("http", 80) => format!("http://{}{}", host, path),
        ("http", port) => format!("http://{}:{}{}", host, port, path),
        (scheme, port) => format!("{}://{}:{}{}", scheme, host, port, path),
    };
    Ok(uri.parse()?)
}

impl RequestOps for ngx::http::Request {
    fn method(&self) -> String {
        self.method().to_string()
    }

    /// returns request uri, without query
    fn self_uri(&self) -> Result<Uri> {
        let (scheme, host, port) = try_parse_forwarded(self.get_header_in("forwarded"))
            .or_else(|| {
                try_parse_xforwarded(
                    self.get_header_in("x-forwarded-proto"),
                    self.get_header_in("x-forwarded-host"),
                    self.get_header_in("x-forwarded-port"),
                )
            })
            .or_else(|| try_parse_host(self.get_header_in("host")))
            .ok_or_else(|| anyhow!("unable to determine self uri from Request"))?;
        normalized_uri(scheme, host, port, self.path().to_str()?)
    }

    fn get_header_in(&self, name: &str) -> Option<&str> {
        self.headers_in_iterator()
            .find(|(k, _)| k.to_str().is_ok_and(|s| s.eq_ignore_ascii_case(name)))
            .and_then(|(_, v)| v.to_str().ok())
    }

    fn get_header_out(&self, name: &str) -> Option<&str> {
        self.headers_out_iterator()
            .find(|(k, _)| k.to_str().is_ok_and(|s| s.eq_ignore_ascii_case(name)))
            .and_then(|(_, v)| v.to_str().ok())
    }

    // we accept DPoP-bound access tokens in Bearer for compatibility reasons
    fn get_authorization_token(&self) -> Result<String> {
        self.get_header_in("authorization")
            .and_then(|v| v.split_once(' '))
            .and_then(|(scheme, token)| match scheme {
                "Bearer" => Some(token),
                "DPoP" => Some(token),
                _ => None,
            })
            .ok_or_else(|| anyhow!("no token"))
            .map(String::from)
    }

    fn ensure_header_in(&mut self, name: &str, value: &str) -> Result<()> {
        if let Some(existing) = self.get_header_in(name)
            && existing != value
        {
            anyhow::bail!("in header {name}: conflicting value declarations: {value}, {existing}")
        }
        self.add_header_in(name, value)
            .ok_or(anyhow!("null table pointer"))
    }

    fn ensure_header_out(&mut self, name: &str, value: &str) -> Result<()> {
        if let Some(existing) = self.get_header_out(name)
            && existing != value
        {
            anyhow::bail!("out header {name}: conflicting value declarations: {value}, {existing}")
        }
        self.add_header_out(name, value)
            .ok_or(anyhow!("null table pointer"))
    }

    fn acceptable(&self, content_type: &str) -> Result<bool> {
        let (media_type, sub_type) = content_type
            .split_once('/')
            .ok_or_else(|| anyhow!("invalid content_type: {content_type}"))?;

        let accept = match self.get_header_in("accept") {
            Some(v) => v,
            // no Accept — everything is acceptable
            None => return Ok(true),
        };

        for part in accept.split(',').map(str::trim) {
            // strip any ;q=0.8…
            let (mtst, _) = part.split_once(';').unwrap_or((part, ""));

            let (mt, st) = match mtst.split_once('/') {
                Some((mt, st)) => (mt.trim(), st.trim()),
                None => continue, // malformed, ignore item
            };

            if (mt == "*" || mt == media_type) && (st == "*" || st == sub_type) {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

pub trait ConfigOps {
    fn main_config(&self) -> Result<&MainConfig>;
    fn location_config(&self) -> Result<&LocationConfig>;
    fn ngx_main_config(&self) -> Result<&ngx_http_core_main_conf_t>;
    fn ngx_server_config(&self) -> Result<&ngx_http_core_srv_conf_t>;
}

impl ConfigOps for Request {
    fn main_config(&self) -> Result<&MainConfig> {
        Module::main_conf(self).ok_or_else(|| anyhow::anyhow!("no main config"))
    }

    fn location_config(&self) -> Result<&LocationConfig> {
        Module::location_conf(self).ok_or_else(|| anyhow::anyhow!("no location config"))
    }

    fn ngx_main_config(&self) -> Result<&ngx_http_core_main_conf_t> {
        NgxHttpCoreModule::main_conf(self).ok_or_else(|| anyhow::anyhow!("no nginx main config"))
    }

    fn ngx_server_config(&self) -> Result<&ngx_http_core_srv_conf_t> {
        NgxHttpCoreModule::server_conf(self)
            .ok_or_else(|| anyhow::anyhow!("no nginx location config"))
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use http::Uri;

    use super::*;

    #[test]
    fn test_forwarded() {
        assert_eq!(None, try_parse_forwarded(None));
        assert_eq!(
            Some(("http", "some_host", None)),
            try_parse_forwarded(Some(
                "Forwarded: by=someone;for=client;host=some_host;proto=http"
            ))
        );
        // default proto https
        assert_eq!(
            Some(("https", "some_host", None)),
            try_parse_forwarded(Some("Forwarded: by=someone;for=client;host=some_host"))
        );
        // with port
        assert_eq!(
            Some(("https", "some_host", Some(1234))),
            try_parse_forwarded(Some("Forwarded: by=someone;for=client;host=some_host:1234"))
        );
        // None with unparseable port
        assert_eq!(
            None,
            try_parse_forwarded(Some(
                "Forwarded: by=someone;for=client;host=some_host:invalid"
            ))
        );
        // multi-valued
        assert_eq!(
            Some(("https", "some_host", Some(1234))),
            try_parse_forwarded(Some(
                "Forwarded: by=someone;for=client;host=some_host:1234,by=someone-else;for=someone;host=weird_host:777"
            ))
        );
    }

    #[test]
    fn test_xforwarded() {
        // always None without x-forwarded-host
        assert_eq!(None, try_parse_xforwarded(None, None, None));
        assert_eq!(
            None,
            try_parse_xforwarded(Some("https"), None, Some("1234"))
        );
        // default https
        assert_eq!(
            Some(("https", "host", None)),
            try_parse_xforwarded(None, Some("host"), None)
        );
        // with port
        assert_eq!(
            Some(("https", "host", Some(1234))),
            try_parse_xforwarded(None, Some("host"), Some("1234"))
        );
        // None with unparseable port
        assert_eq!(
            None,
            try_parse_xforwarded(None, Some("host"), Some("weird"))
        );
        // multi-valued
        assert_eq!(
            Some(("https", "host", Some(1234))),
            try_parse_xforwarded(Some("https,http"), Some("host,another"), Some("1234,777"))
        );
    }

    #[test]
    fn test_host() {
        assert_eq!(None, try_parse_host(None));
        // always https
        assert_eq!(Some(("https", "host", None)), try_parse_host(Some("host")));
        // with port
        assert_eq!(
            Some(("https", "host", Some(123))),
            try_parse_host(Some("host:123"))
        );
        // with unparseable port
        assert_eq!(None, try_parse_host(Some("host:invalid")));
    }

    #[test]
    fn test_normalized_uri() -> Result<()> {
        assert_eq!(
            "https://host".parse::<Uri>()?,
            normalized_uri("https", "host", None, "")?
        );
        assert_eq!(
            "https://host".parse::<Uri>()?,
            normalized_uri("https", "host", Some(443), "")?
        );
        assert_eq!(
            "https://host:123".parse::<Uri>()?,
            normalized_uri("https", "host", Some(123), "")?
        );

        assert_eq!(
            "http://host".parse::<Uri>()?,
            normalized_uri("http", "host", None, "")?
        );
        assert_eq!(
            "http://host".parse::<Uri>()?,
            normalized_uri("http", "host", Some(80), "")?
        );
        assert_eq!(
            "http://host:123".parse::<Uri>()?,
            normalized_uri("http", "host", Some(123), "")?
        );

        assert_eq!(
            "http://host:123/path".parse::<Uri>()?,
            normalized_uri("http", "host", Some(123), "/path")?
        );
        Ok(())
    }
}
