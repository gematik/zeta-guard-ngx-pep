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

use asl::AslError;
use http::Uri;
use ngx::http::HTTPStatus;
use std::collections::HashMap;
use std::convert::AsRef;
use strum::AsRefStr;
use thiserror::Error;

use crate::response::Response;
use crate::typify::HttpZetaErrorResponse;

pub type ZetaResult<T> = Result<T, ZetaError>;

// When adding a variant, make sure there is an entry in `../book/src/errors/$name.md`, e.g.
// `../book/src/errors/AccessToken.md`, as the error Response will automatically link to that.
#[derive(Error, Debug, AsRefStr)]
pub enum ZetaError {
    #[error("access token error: {0}")]
    AccessToken(#[source] anyhow::Error),
    #[error("access token invalid: {0}")]
    AccessTokenInvalid(#[source] anyhow::Error),
    #[error("DPoP error: {0}")]
    DPoP(#[source] anyhow::Error),
    #[error("PoPP error: {0}")]
    PoPP(#[source] anyhow::Error),
    #[error("PoPP header missing")]
    PoPPMissing,
    #[error("PoPP actorId mismatch: want {access_token_sub}, got {actor_id}")]
    PoPPInvalidActor {
        access_token_sub: String,
        actor_id: String,
    },
    #[error("Impossible Travel: {0}")]
    ImpossibleTravel(#[source] anyhow::Error),
    #[error("Revoked Session")]
    RevokedSession,
    #[error("upstream proxy signaled error: {0}")]
    Proxy(#[source] anyhow::Error),
    #[error(
        "proxy headers not configured for this location: `include proxy_headers.conf;` is \
         missing (or was clobbered by a location-level `proxy_set_header`)"
    )]
    ProxyHeadersMissing,
    #[error("ASL session expired: {0} (@{1})")]
    AslSessionExpired(String, u64),
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

#[macro_export]
macro_rules! zeta_anyhow {
    ( $type: ident, $($arg:tt)+ ) => {
        $crate::error::ZetaError::$type(anyhow::anyhow!($($arg)+))
    };
}

#[macro_export]
macro_rules! zeta_bail {
    ( $type: ident, $($arg:tt)+ ) => {
        return Err($crate::zeta_anyhow!($type, $($arg)+))
    };
}

impl ZetaError {
    fn http_code(&self) -> usize {
        match self {
            Self::AccessToken(_) => 401,
            Self::AccessTokenInvalid(_) => 401,
            Self::DPoP(_) => 401,
            Self::PoPP(_) => 403,
            Self::PoPPMissing => 400,
            Self::PoPPInvalidActor { .. } => 403,
            Self::ImpossibleTravel(_) => 401,
            Self::RevokedSession => 401,
            Self::Proxy(_) => 500,
            Self::ProxyHeadersMissing => 500,
            Self::AslSessionExpired(_, _) => 403,
            Self::Internal(_) => 500,
        }
    }

    // A_29850: errors raised by the PEP carry `zeta-error-origin: pep`, so the ZETA-Client can tell
    // them apart from errors of the resource server — but only if the ZETA-Client is the one to
    // act on them. PoPP errors (missing or invalid token) are addressed to the caller, who supplies
    // the token: the client must hand them on instead of re-authenticating.
    fn carries_error_origin(&self) -> bool {
        match self {
            Self::PoPP(_) | Self::PoPPMissing | Self::PoPPInvalidActor { .. } => false,
            Self::AccessToken(_)
            | Self::AccessTokenInvalid(_)
            | Self::DPoP(_)
            | Self::ImpossibleTravel(_)
            | Self::RevokedSession
            | Self::Proxy(_)
            | Self::ProxyHeadersMissing
            | Self::AslSessionExpired(_, _)
            | Self::Internal(_) => true,
        }
    }

    pub fn response(&self, base: Uri) -> anyhow::Result<Response> {
        let mut parts = base.into_parts();
        parts.path_and_query = Some(format!("/doc/errors/{}.html", self.as_ref()).parse()?);
        let error_response = HttpZetaErrorResponse {
            error: self.as_ref().to_string(),
            error_description: Some(self.to_string()),
            error_uri: Some(Uri::from_parts(parts)?.to_string()),
        };

        let body = serde_json::to_string_pretty(&error_response)?;
        let extra_headers = if self.carries_error_origin() {
            HashMap::from([("zeta-error-origin".to_string(), "pep".to_string())])
        } else {
            HashMap::new()
        };
        Ok(Response::new_with_body_and_extra_header(
            HTTPStatus(self.http_code()),
            "application/json",
            body.into_bytes(),
            extra_headers,
        ))
    }
}

pub type ZetaAslResult<T> = Result<T, AslError>;

pub trait ToHttpResponse {
    fn to_http_response(&self, base: Uri) -> ZetaResult<Response>;
}

impl ToHttpResponse for AslError {
    fn to_http_response(&self, base: Uri) -> ZetaResult<Response> {
        if let AslError::SessionExpired(cid, expired) = self {
            let err = ZetaError::AslSessionExpired(cid.clone(), *expired);
            err.response(base).map_err(ZetaError::Internal)
        } else {
            Ok(Response::new_with_body(
                HTTPStatus(self.status() as usize),
                "application/cbor",
                self.to_response(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::{Result, anyhow};
    use ngx::http::HTTPStatus;

    use super::ZetaError;
    use crate::response::Response;
    use crate::typify::HttpZetaErrorResponse;

    #[test]
    fn into_response() -> Result<()> {
        let error = ZetaError::Internal(anyhow!("request completed successfully"));
        let response: Response = error.response("http://base".parse()?)?;

        assert!(response.status == HTTPStatus::INTERNAL_SERVER_ERROR);
        assert!(response.content_type == Some("application/json".to_string()));

        let body: HttpZetaErrorResponse = serde_json::from_slice(response.body.as_slice())?;
        let expected_body = HttpZetaErrorResponse {
            error: "Internal".to_string(),
            error_description: Some("internal error: request completed successfully".to_string()),
            error_uri: Some("http://base/doc/errors/Internal.html".to_string()),
        };
        assert!(body == expected_body);
        Ok(())
    }

    #[test]
    fn error_response_carries_zeta_error_origin_header() -> Result<()> {
        let variants: Vec<ZetaError> = vec![
            ZetaError::AccessToken(anyhow!("expired")),
            ZetaError::AccessTokenInvalid(anyhow!("bad sig")),
            ZetaError::DPoP(anyhow!("missing")),
            ZetaError::ImpossibleTravel(anyhow!("too fast")),
            ZetaError::Proxy(anyhow!("upstream died")),
            ZetaError::Internal(anyhow!("oops")),
        ];

        for error in variants {
            let response = error.response("http://base".parse()?)?;
            assert_eq!(
                response
                    .extra_headers
                    .get("zeta-error-origin")
                    .map(String::as_str),
                Some("pep"),
                "ZetaError::{} must set zeta-error-origin: pep",
                error.as_ref()
            );
        }
        Ok(())
    }

    // A_29850: PoPP errors are addressed to the caller, not the ZETA-Client.
    #[test]
    fn popp_error_response_has_no_zeta_error_origin_header() -> Result<()> {
        let variants: Vec<ZetaError> = vec![
            ZetaError::PoPP(anyhow!("invalid")),
            ZetaError::PoPPMissing,
            ZetaError::PoPPInvalidActor {
                access_token_sub: "a".into(),
                actor_id: "b".into(),
            },
        ];

        for error in variants {
            let response = error.response("http://base".parse()?)?;
            assert!(
                !response.extra_headers.contains_key("zeta-error-origin"),
                "ZetaError::{} must not set zeta-error-origin",
                error.as_ref()
            );
        }
        Ok(())
    }
}
