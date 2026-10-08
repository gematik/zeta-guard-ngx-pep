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

use crate::error::ZetaError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capec {
    AuthenticationBypass,
    UseOfKnownDomainCredentials,
    PrivilegeEscalation,
    ExploitationOfTrustedIdentifiers,
    ProtocolManipulation,
}

impl Capec {
    pub fn id(&self) -> u32 {
        match self {
            Self::AuthenticationBypass => 115,
            Self::UseOfKnownDomainCredentials => 560,
            Self::PrivilegeEscalation => 233,
            Self::ExploitationOfTrustedIdentifiers => 21,
            Self::ProtocolManipulation => 272,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::AuthenticationBypass => "Authentication Bypass",
            Self::UseOfKnownDomainCredentials => "Use of Known Domain Credentials",
            Self::PrivilegeEscalation => "Privilege Escalation",
            Self::ExploitationOfTrustedIdentifiers => "Exploitation of Trusted Identifiers",
            Self::ProtocolManipulation => "Protocol Manipulation",
        }
    }
}

pub fn zeta_capec(err: &ZetaError) -> Option<Capec> {
    match err {
        ZetaError::AccessToken(_) => Some(Capec::AuthenticationBypass),
        ZetaError::AccessTokenInvalid(_) => Some(Capec::AuthenticationBypass),
        ZetaError::DPoP(_) => Some(Capec::UseOfKnownDomainCredentials),
        ZetaError::PoPP(_) => Some(Capec::PrivilegeEscalation),
        ZetaError::PoPPMissing => Some(Capec::AuthenticationBypass),
        ZetaError::PoPPInvalidActor { .. } => Some(Capec::ExploitationOfTrustedIdentifiers),
        ZetaError::ImpossibleTravel(_) => Some(Capec::UseOfKnownDomainCredentials),
        ZetaError::RevokedSession => Some(Capec::UseOfKnownDomainCredentials),
        ZetaError::Proxy(_) => None,
        ZetaError::ProxyHeadersMissing => None,
        ZetaError::Internal(_) => None,
    }
}

pub fn asl_capec(err: &AslError) -> Option<Capec> {
    match err {
        AslError::DecodingError(_) => Some(Capec::ProtocolManipulation),
        AslError::BadFormat => Some(Capec::ProtocolManipulation),
        AslError::DecryptionFailure => Some(Capec::ProtocolManipulation),
        AslError::TranscriptError => Some(Capec::ProtocolManipulation),
        AslError::WrongEnvironment => Some(Capec::ProtocolManipulation),
        AslError::NotRequest => Some(Capec::ProtocolManipulation),
        AslError::UnknownKeyID => Some(Capec::ProtocolManipulation),
        AslError::IllegalTracing => Some(Capec::ProtocolManipulation),
        AslError::MissingParameters => None,
        AslError::UnknownCID => None,
        AslError::BadRequest(_) => Some(Capec::ProtocolManipulation),
        AslError::VerificationError => None,
        AslError::InternalError(_) => None,
    }
}
