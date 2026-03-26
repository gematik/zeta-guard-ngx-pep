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
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl ZetaError {
    fn http_code(&self) -> usize {
        match self {
            Self::AccessToken(_) => 401,
            Self::AccessTokenInvalid(_) => 401,
            Self::DPoP(_) => 401,
            Self::PoPP(_) => 403,
            Self::Internal(_) => 500,
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
        Ok(Response::new_with_body(
            HTTPStatus(self.http_code()),
            "application/json",
            body.into_bytes(),
        ))
    }
}

pub type ZetaAslResult<T> = Result<T, AslError>;

pub trait ToHttpResponse {
    fn to_http_resposnse(&self) -> Response;
}

impl ToHttpResponse for AslError {
    fn to_http_resposnse(&self) -> Response {
        Response::new_with_body(
            HTTPStatus(self.status() as usize),
            "application/cbor",
            self.to_response(),
        )
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

        let body: HttpZetaErrorResponse = serde_json::from_slice(&response.body.0)?;
        let expected_body = HttpZetaErrorResponse {
            error: "Internal".to_string(),
            error_description: Some("internal error: request completed successfully".to_string()),
            error_uri: Some("http://base/doc/errors/Internal.html".to_string()),
        };
        assert!(body == expected_body);
        Ok(())
    }
}
