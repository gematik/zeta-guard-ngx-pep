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

//! A_25484-03: role of the access token's subject, derived from its `profession_oid` claim
//! and logged as the `user.roles` OpenTelemetry attribute.
//!
//! The professionOIDs and what they stand for are defined in gemSpec_OID (V3.12.3):
//! Tab_PKI_402 (Berufsgruppen, i.e. HBA and other person certificates) and Tab_PKI_403
//! (Institutionen, i.e. SMC-B).

/// professionOID of insured persons (Tab_PKI_402, `oid_versicherter`).
const PROFESSION_OID_VERSICHERTER: &str = "1.2.276.0.76.4.49";

/// professionOIDs of Leistungserbringer: every Berufsgruppe of Tab_PKI_402 except
/// `oid_versicherter`, and the Tab_PKI_403 institutions that provide care themselves
/// (Praxen, Krankenhäuser, Apotheken, Rettungsdienst, Pflege, Heil- und Hilfsmittel, …).
///
/// Deliberately *not* listed, so they map to [`UserRole::Unbekannt`]: Kostenträger and their
/// environments, Leistungserbringerorganisationen (KVen, Kammern, Verbände — they represent
/// Leistungserbringer but don't provide care), gematik, registers, Abrechnungsdienstleister,
/// KIM and DiGA manufacturers, Pflegeberatung, "weitere Organisationen der
/// Gesundheitsversorgung", technical roles (Tab_PKI_406) and OIDs no longer in use.
const PROFESSION_OIDS_LEISTUNGSERBRINGER: &[&str] = &[
    // Tab_PKI_402: Berufsgruppen
    "1.2.276.0.76.4.30",  // oid_arzt
    "1.2.276.0.76.4.31",  // oid_zahnarzt
    "1.2.276.0.76.4.32",  // oid_apotheker
    "1.2.276.0.76.4.33",  // oid_apothekerassistent
    "1.2.276.0.76.4.34",  // oid_pharmazieingenieur
    "1.2.276.0.76.4.35",  // oid_pharm_techn_assistent
    "1.2.276.0.76.4.36",  // oid_pharm_kaufm_angestellter
    "1.2.276.0.76.4.37",  // oid_apothekenhelfer
    "1.2.276.0.76.4.38",  // oid_apothekenassistent
    "1.2.276.0.76.4.39",  // oid_pharm_assistent
    "1.2.276.0.76.4.40",  // oid_apothekenfacharbeiter
    "1.2.276.0.76.4.41",  // oid_pharmaziepraktikant
    "1.2.276.0.76.4.42",  // oid_famulant
    "1.2.276.0.76.4.43",  // oid_pta_praktikant
    "1.2.276.0.76.4.44",  // oid_pka_auszubildender
    "1.2.276.0.76.4.45",  // oid_psychotherapeut
    "1.2.276.0.76.4.46",  // oid_ps_psychotherapeut
    "1.2.276.0.76.4.47",  // oid_kuj_psychotherapeut
    "1.2.276.0.76.4.48",  // oid_rettungsassistent
    "1.2.276.0.76.4.178", // oid_notfallsanitaeter
    "1.2.276.0.76.4.232", // oid_pfleger-hpc
    "1.2.276.0.76.4.233", // oid_altenpfleger-hpc
    "1.2.276.0.76.4.234", // oid_pflegefachkraft-hpc
    "1.2.276.0.76.4.235", // oid_hebamme-hpc
    "1.2.276.0.76.4.236", // oid_physiotherapeut-hpc
    "1.2.276.0.76.4.237", // oid_augenoptiker-hpc
    "1.2.276.0.76.4.238", // oid_hoerakustiker-hpc
    "1.2.276.0.76.4.239", // oid_orthopaedieschuhmacher-hpc
    "1.2.276.0.76.4.240", // oid_orthopaedietechniker-hpc
    "1.2.276.0.76.4.241", // oid_zahntechniker-hpc
    "1.2.276.0.76.4.274", // oid_ergotherapeut-hpc
    "1.2.276.0.76.4.275", // oid_logopaede-hpc
    "1.2.276.0.76.4.276", // oid_podologe-hpc
    "1.2.276.0.76.4.277", // oid_ernaehrungstherapeut-hpc
    // Tab_PKI_403: Institutionen, die selbst Leistungen erbringen
    "1.2.276.0.76.4.50",  // oid_praxis_arzt
    "1.2.276.0.76.4.51",  // oid_zahnarztpraxis
    "1.2.276.0.76.4.52",  // oid_praxis_psychotherapeut
    "1.2.276.0.76.4.53",  // oid_krankenhaus
    "1.2.276.0.76.4.54",  // oid_oeffentliche_apotheke
    "1.2.276.0.76.4.55",  // oid_krankenhausapotheke
    "1.2.276.0.76.4.56",  // oid_bundeswehrapotheke
    "1.2.276.0.76.4.57",  // oid_mobile_einrichtung_rettungsdienst
    "1.2.276.0.76.4.245", // oid_institution-pflege
    "1.2.276.0.76.4.246", // oid_institution-geburtshilfe
    "1.2.276.0.76.4.247", // oid_praxis-physiotherapeut
    "1.2.276.0.76.4.248", // oid_institution-augenoptiker
    "1.2.276.0.76.4.249", // oid_institution-hoerakustiker
    "1.2.276.0.76.4.250", // oid_institution-orthopaedieschuhmacher
    "1.2.276.0.76.4.251", // oid_institution-orthopaedietechniker
    "1.2.276.0.76.4.252", // oid_institution-zahntechniker
    "1.2.276.0.76.4.253", // oid_institution-rettungsleitstellen
    "1.2.276.0.76.4.254", // oid_sanitaetsdienst-bundeswehr
    "1.2.276.0.76.4.255", // oid_institution-oegd
    "1.2.276.0.76.4.256", // oid_institution-arbeitsmedizin
    "1.2.276.0.76.4.257", // oid_institution-vorsorge-reha
    "1.2.276.0.76.4.278", // oid_praxis-ergotherapeut
    "1.2.276.0.76.4.279", // oid_praxis-logopaede
    "1.2.276.0.76.4.280", // oid_praxis-podologe
    "1.2.276.0.76.4.281", // oid_praxis-ernaehrungstherapeut
];

/// A_25484-03: user role of an attack detection, logged as `user.roles`
/// (OpenTelemetry semconv). Derived from the `profession_oid` claim of a
/// *validated* access token; the OID itself is never logged.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UserRole {
    Versicherter,
    Leistungserbringer,
    /// No access token, one that failed validation (its claims can't be trusted), or a
    /// professionOID that belongs neither to an insured person nor to a Leistungserbringer.
    #[default]
    Unbekannt,
}

impl UserRole {
    pub fn from_profession_oid(profession_oid: &str) -> Self {
        if profession_oid == PROFESSION_OID_VERSICHERTER {
            Self::Versicherter
        } else if PROFESSION_OIDS_LEISTUNGSERBRINGER.contains(&profession_oid) {
            Self::Leistungserbringer
        } else {
            Self::Unbekannt
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Versicherter => "Versicherter",
            Self::Leistungserbringer => "Leistungserbringer",
            Self::Unbekannt => "Unbekannt",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_role_from_profession_oid() {
        assert_eq!(
            UserRole::from_profession_oid("1.2.276.0.76.4.49"),
            UserRole::Versicherter
        );
        for oid in [
            "1.2.276.0.76.4.30",  // HBA Arzt
            "1.2.276.0.76.4.277", // HBA Ernährungstherapeut (last of Tab_PKI_402)
            "1.2.276.0.76.4.50",  // SMC-B Betriebsstätte Arzt
            "1.2.276.0.76.4.54",  // SMC-B Öffentliche Apotheke
            "1.2.276.0.76.4.281", // SMC-B Ernährungstherapeutische Praxis
        ] {
            assert_eq!(
                UserRole::from_profession_oid(oid),
                UserRole::Leistungserbringer,
                "{oid}"
            );
        }
        for oid in [
            "1.2.276.0.76.4.58",  // Betriebsstätte gematik
            "1.2.276.0.76.4.59",  // Betriebsstätte Kostenträger
            "1.2.276.0.76.4.210", // LEO Kassenärztliche Vereinigung
            "1.2.276.0.76.4.230", // LEO Ärztekammer
            "1.2.276.0.76.4.282", // DiGA-Hersteller und -Anbieter
            "1.2.276.0.76.4.286", // KIM-Hersteller und -Anbieter
            "1.2.276.0.76.4.97",  // technische Rolle VSDD
            "1.2.276.0.76.4.143", // nicht mehr verwendet
            "1.2.276.0.76.4.3",   // prefix of a Leistungserbringer OID, but none itself
            "1.2.276.0.76.4.300", // not (yet) assigned
            "",
            "profession_oid",
        ] {
            assert_eq!(
                UserRole::from_profession_oid(oid),
                UserRole::Unbekannt,
                "{oid}"
            );
        }
        assert_eq!(UserRole::default(), UserRole::Unbekannt);
    }

    #[test]
    fn user_role_as_str() {
        assert_eq!(UserRole::Versicherter.as_str(), "Versicherter");
        assert_eq!(UserRole::Leistungserbringer.as_str(), "Leistungserbringer");
        assert_eq!(UserRole::Unbekannt.as_str(), "Unbekannt");
    }
}
