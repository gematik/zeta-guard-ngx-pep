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

use anyhow::bail;
use asn1_rs::*;

/// AdmissionSyntax ::= SEQUENCE {
///   admissionAuthority        [0] EXPLICIT GeneralName OPTIONAL,
///   contentsOfAdmissions      SEQUENCE OF Admissions
/// }
#[derive(Debug, DerSequence)]
pub struct AdmissionSyntax<'a> {
    #[tag_explicit(0)]
    #[optional]
    pub _admission_authority: Option<Any<'a>>,

    pub contents_of_admissions: Vec<Admissions<'a>>,
}

impl AdmissionSyntax<'_> {
    pub fn single_profession_info(&self) -> anyhow::Result<&ProfessionInfo<'_>> {
        let admissions = &self.contents_of_admissions;
        if admissions.len() != 1 {
            bail!("Expected exactly 1 Admissions, found: {:?}", admissions)
        }
        let admissions = &admissions[0];
        let profession_info = &admissions.profession_infos;
        if profession_info.len() != 1 {
            bail!(
                "Expected exactly 1 ProfessionInfo, found: {:?}",
                profession_info
            )
        }
        Ok(&profession_info[0])
    }
}

/// Admissions ::= SEQUENCE {
///   admissionAuthority        [0] EXPLICIT GeneralName OPTIONAL,
///   namingAuthority           [1] EXPLICIT NamingAuthority OPTIONAL,
///   professionInfos           SEQUENCE OF ProfessionInfo
/// }
#[derive(Debug, DerSequence)]
pub struct Admissions<'a> {
    #[tag_explicit(0)]
    #[optional]
    pub _admission_authority: Option<Any<'a>>, // ignored
    #[tag_explicit(1)]
    #[optional]
    pub _naming_authority: Option<Any<'a>>, // ignored

    pub profession_infos: Vec<ProfessionInfo<'a>>,
}

/// ProfessionInfo ::= SEQUENCE {
///   namingAuthority    [0] EXPLICIT NamingAuthority OPTIONAL,
///   professionItems    SEQUENCE OF DirectoryString OPTIONAL,
///   professionOIDs     SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
///   registrationNumber DirectoryString OPTIONAL,
///   addProfessionInfo  OCTET STRING OPTIONAL
/// }
#[derive(Debug, DerSequence)]
pub struct ProfessionInfo<'a> {
    #[tag_explicit(0)]
    #[optional]
    pub _naming_authority: Option<Any<'a>>, // ignored

    #[optional]
    pub _profession_items: Option<Vec<Any<'a>>>, // ignored

    #[optional]
    pub profession_oids: Option<Vec<Oid<'a>>>,

    #[optional]
    pub registration_number: Option<Any<'a>>,

    #[optional]
    pub _add_profession_info: Option<&'a [u8]>, // ignored
}

impl ProfessionInfo<'_> {
    pub fn registration_number(&self) -> Result<Option<String>> {
        if let Some(any) = &self.registration_number {
            Ok(Some(match any.tag() {
                Tag::Utf8String => any.as_string()?,
                Tag::PrintableString => any.as_printablestring()?.string(),
                Tag::BmpString => any.as_bmpstring()?.string(),
                Tag::TeletexString => any.as_teletexstring()?.string(),
                Tag::UniversalString => any.as_universalstring()?.string(),
                _ => return Err(Error::InvalidTag),
            }))
        } else {
            Ok(None)
        }
    }
}
