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

use super::model::*;
use super::util::*;
use libcrux_kem as kem;
use libcrux_ml_kem::mlkem768;
use rand::Rng;

const SECONDS_PER_DAY: u64 = 60 * 60 * 24;

pub fn generate_raw_keys() -> Result<(PublicKeys, PrivateKeys), AslError> {
    RNG.with_borrow_mut(|rng| {
        let (ecdh_sk, ecdh_pk) = kem::key_gen(kem::Algorithm::Secp256r1, rng).to_error()?;
        let rv: [u8; 64] = rng.random();
        let pqc = mlkem768::generate_key_pair(rv);

        let pqc_pk = pqc.public_key().clone();
        let pqc_sk = pqc.private_key().clone();
        Ok((
            PublicKeys { ecdh_pk, pqc_pk },
            PrivateKeys { ecdh_sk, pqc_sk },
        ))
    })
}

pub fn generate_asl_keys(
    days_valid: u64,
    comment: &str,
) -> Result<(AslKeys, AslPrivateKeys), AslError> {
    let (pk, sk) = generate_raw_keys()?;
    let now = utc_now();
    Ok((
        AslKeys::new(&pk, now, days_valid, comment),
        AslPrivateKeys::new(&sk),
    ))
}

impl AslPrivateKeys {
    pub fn new(sk: &PrivateKeys) -> Self {
        Self {
            ecdh_sk: sk.ecdh_sk.encode(),
            pqc_sk: sk.pqc_sk.as_slice().to_vec(),
        }
    }
}

impl AslKeys {
    pub fn new(pk: &PublicKeys, issued_utc: u64, days_valid: u64, comment: &str) -> Self {
        Self {
            ecdh_pk: ECDHKey::from(pk.ecdh_pk.encode()),
            pqc_pk: pk.pqc_pk.as_slice().to_vec(),
            iat: issued_utc,
            exp: issued_utc + days_valid * SECONDS_PER_DAY,
            comment: String::from(comment),
        }
    }

    pub fn sign(
        &self,
        signer_der: &[u8],
        signer_sk: &[u8],
        version: u64,
    ) -> Result<SignedAslKeys, AslError> {
        self.sign_with(signer_der, version, |data| {
            let sk_arr: [u8; 32] = signer_sk
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid private key length"))?;
            let sk = libcrux_ecdsa::p256::PrivateKey::try_from(&sk_arr)
                .map_err(|e| anyhow::anyhow!("invalid private key: {e:?}"))?;
            let sig = RNG
                .with_borrow_mut(|rng| {
                    libcrux_ecdsa::p256::rand::sign(libcrux_sha2::Algorithm::Sha256, data, &sk, rng)
                })
                .map_err(|e| anyhow::anyhow!("sign error: {e:?}"))?;
            let (r, s) = sig.as_bytes();
            Ok([r.as_slice(), s.as_slice()].concat())
        })
    }

    pub fn sign_with<F>(
        &self,
        signer_der: &[u8],
        version: u64,
        sign: F,
    ) -> Result<SignedAslKeys, AslError>
    where
        F: Fn(&[u8]) -> anyhow::Result<Vec<u8>>, // signfunc(data) -> signature
    {
        let signed_pub_keys = serde_cbor::to_vec(&self).to_error()?;
        let signature_es256 = sign(&signed_pub_keys).to_error()?;
        let cert_hash = libcrux_sha2::sha256(signer_der).to_vec();

        let signed = SignedAslKeys {
            signed_pub_keys,
            signature_es256,
            cert_hash,
            cdv: version,
            ocsp_response: None,
        };
        Ok(signed)
    }
}

#[derive(Debug)]
pub enum AslVerifyError {
    WrongCertificate,
    SignatureMismatch,
    Decoding,
}

impl SignedAslKeys {
    pub fn verify_with<E, F>(&self, signer_der: &[u8], verify: F) -> Result<AslKeys, AslVerifyError>
    where
        F: Fn(&[u8], &[u8], &[u8]) -> Result<(), E>, // verifyfunc(data, sig, cert) -> ()
    {
        let cert_hash = libcrux_sha2::sha256(signer_der).to_vec();
        if cert_hash != self.cert_hash {
            return Err(AslVerifyError::WrongCertificate);
        }
        verify(&self.signed_pub_keys, &self.signature_es256, signer_der)
            .map_err(|_| AslVerifyError::SignatureMismatch)?;
        let asl_keys =
            serde_cbor::from_slice(&self.signed_pub_keys).map_err(|_| AslVerifyError::Decoding)?;
        Ok(asl_keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libcrux_ecdsa::p256;
    use x509_parser::parse_x509_certificate;

    #[test]
    fn it_generates_asl_keys() {
        let maybe_asl_keys = generate_asl_keys(7, "test keys");
        assert!(maybe_asl_keys.is_ok());
        let (asl_keys, asl_pks) = maybe_asl_keys.unwrap();
        assert_eq!(asl_keys.comment, "test keys");
        assert!(asl_keys.exp - asl_keys.iat >= 7 * SECONDS_PER_DAY);
        assert_eq!(asl_pks.pqc_sk.len(), PQC_SK_SIZE);
    }

    #[test]
    fn it_signs_asl_keys() {
        const SERVER_SIG_SK_HEX: &str =
            "BD37298383EB3D620DA1ED367A9A0898E02443FADFF0AF783E1FBBFDF8250D95";
        const SERVER_SIG_CERT_HEX: &str = "3082017330820119a003020102021450fe87e05a3c00463e0a18387c3dbda92f4828fd300a06082a8648ce3d040302300f310d300b06035504030c0474657374301e170d3235313033303039333430395a170d3335313032383039333430395a300f310d300b06035504030c04746573743059301306072a8648ce3d020106082a8648ce3d030107034200048bf54a359336ad068fc57282552526875f0884a8d5b3bc09716edcaa7e0b4443084eea5f2445fea6cfe558edf4a9efea2732efa2d5888b66be9b5b08101448c2a3533051301d0603551d0e0416041461dd7c90fc9bdf91f8b4c3eaa0ceda715bd523f5301f0603551d2304183016801461dd7c90fc9bdf91f8b4c3eaa0ceda715bd523f5300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020348003045022100d0621bf50aee3ff00713393825f2993adc88a091d1f227e8a2319bc7a33b0e4302201a0276dcceabbf9e7dae50669d9186663f3f00a954e1d9eb87b844bd8733cfe4";

        let (server_keys, _) = generate_asl_keys(30, "test keys").unwrap();
        let maybe_signed_keys = server_keys.sign(
            &hex::decode(SERVER_SIG_CERT_HEX).unwrap(),
            &hex::decode(SERVER_SIG_SK_HEX).unwrap(),
            42,
        );
        assert!(maybe_signed_keys.is_ok());
        let signed_keys = maybe_signed_keys.unwrap();
        println!("{}", hex::encode(serde_cbor::to_vec(&signed_keys).unwrap()));
        assert_eq!(signed_keys.cdv, 42);
    }

    #[test]
    fn it_verifies_signed_asl_keys() {
        const SERVER_SIGNED_ASL_KEYS_HEX: &str = "a56f7369676e65645f7075625f6b657973590531a567454344485f504ba36363727665502d323536617858206cc92b885f0c266a92bb127c21a630f52d78b11fe8969fcf88bebbbf7ba644d261795820a954e43a5c13bdac1fc7cc829c0925c4b2774fa6653d681dae0c350324992a986d4d4c2d4b454d2d3736385f504b5904a0a0a23ec4710f262b5a644ac207958801d74f571a9649800d56c2ad002771d4fc713a89a510801421e29cafe273ecc44bd1fa3852877d471bc574e9b272a114b7f46b79d0af4e80cb8555995d976c98a28a3b964b36e821601459b2f841373727448a80751bad96d71fc0714d578b00828c930cb92b580cb007fc00d51c365eb287d043383e8c3c7a1984f7d481f109b281201e68bb84e040764d0b63fe0c51a1a22db082acb4197dc9cb1f3535ccc08c177d798690420ab9f6905d92724779ca57c8bae42630b973cc2f944e8526b51b72a4ef494f8b1ac93bc067825aa8235ba8a0066dbba0a92039b519b32dcba20a4cb308d42043212b76ebbc0c22944a4d9538405017baba86ca21055ae4755397729aa60e24175a81d56798c5773563169704c18d2397924794ba925ddceb59f49413499b3ba1628e8c6cbc11943e34f8cea744c682cc6797254f9da422e59b7eb2da5e199296bb838b869895243c5f29b5a1fe2cb83d7044b98aad7182bda919af7b7ca747026ccf40cc6c69a610143c3bcb3878399259c6bf8f31bb8d388d90204595b62962baa3bb616c9143a1cd410ba3fb09fbe66fc8298eccf0393c3568f462909bea241fbba0d9ba923a532525ea655cecc88a58921998b2f2d24586f3321a1805a2f24d331626b568a501495052779afc947b5991a7bd01845056c42d087026699f82022c84a6a192032091dbc8deecbb7a209588d0a8a404bfd3cb22e0f7b2bdb27a8669440934b5799b8e97815b4ffc35352c9e6b29132f228057d05c107c3e79d243de89c3afa897c3379f740b147fc21caf1625837c9e3ab0b7025563dbdcadcde2273d7b3137025c6b0029feb160c8fb53d9605336d8229051ce98aa527c4a3ce3d090fc863f0ce376d7aace1111726079346dc26d24e539f3714429915a5b3ccbf8576f5211776689c0fbb43b2fb717e6735c401142f0249451240a4ceb2db8f16390a52a003008eea8134a8b0c8fa189d5514377fc6d61145fe203bb8c081e7c5acf7437b386410304a30bfb920678548a17ac93b2dabd1679375241be42d88a00341eadc7763d0456eb644242c32eecf70458c0955447c5a4bb38aa2a822f2174c1832d45bb6ae8b9bfeba027eaa6494e6bcccb616aac19b8d24476795866781caab420b5ff996aa228b792d1307dcb447130c991c432fc245c0010c7b4958aa73a5715366aeff926ef998c931013a27b5e9b2b723b128a56841bec248e885ab1e5016749ba32d1e173a61a43fb11644260772c7031bd5c0ed7c982b9e4af4d385a8f47017c714fb92a04099b63f26ba8c1e4a748a7c9fe5173ada73b2ab6b65a77b8db983b16f37afc152b5966a2c7d5c7e214c2bac56d5c6bc5a7b1c5944094f796b04fd84a735a7dca5987d9a1a8b1ba3582d124a18557a60b7e85d28067c87c38646ccf4533cbb17617075b34837e036cc5aee985306c137c5116757838981c2f40a1b82c58b62774cfbe02768c75013cc27f8d47be43643fd7592e76e927248b987bb54bd5b7137f226cdb133030852547b6a88b996747a8cad072c31128aa8c60990b45841d0b06b4107fee8124e2467bcbe5129e787d5657acd515bdcd72a3ff04a20038505da779e367794759ec4d9316751379735a94effa9a0160c49f136123f399a5e1636961741a699dba8c636578701a69c5478c67636f6d6d656e746974657374206b6579736f7369676e61747572652d455332353658400ae125bd7a43c914e6b3467e6c0bf196d5cc7922481c4490b12c1bbce3867c5e732d6b4e2235e38606e43707d871c90858c7ac54325963e281a46fb005fe3e5969636572745f686173685820b28a377426822eca7ac923e644ad05ba6a3f203095c2c8fd5682ecaae9cc41a963636476182a6d6f6373705f726573706f6e7365f6";
        const SERVER_SIG_CERT_HEX: &str = "3082017330820119a003020102021450fe87e05a3c00463e0a18387c3dbda92f4828fd300a06082a8648ce3d040302300f310d300b06035504030c0474657374301e170d3235313033303039333430395a170d3335313032383039333430395a300f310d300b06035504030c04746573743059301306072a8648ce3d020106082a8648ce3d030107034200048bf54a359336ad068fc57282552526875f0884a8d5b3bc09716edcaa7e0b4443084eea5f2445fea6cfe558edf4a9efea2732efa2d5888b66be9b5b08101448c2a3533051301d0603551d0e0416041461dd7c90fc9bdf91f8b4c3eaa0ceda715bd523f5301f0603551d2304183016801461dd7c90fc9bdf91f8b4c3eaa0ceda715bd523f5300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020348003045022100d0621bf50aee3ff00713393825f2993adc88a091d1f227e8a2319bc7a33b0e4302201a0276dcceabbf9e7dae50669d9186663f3f00a954e1d9eb87b844bd8733cfe4";
        const SERVER_SIG_PK_HEX: &str = "048BF54A359336AD068FC57282552526875F0884A8D5B3BC09716EDCAA7E0B4443084EEA5F2445FEA6CFE558EDF4A9EFEA2732EFA2D5888B66BE9B5B08101448C2";

        let signed_asl_keys: SignedAslKeys =
            serde_cbor::from_slice(&hex::decode(SERVER_SIGNED_ASL_KEYS_HEX).unwrap()).unwrap();
        let maybe_asl_keys = signed_asl_keys.verify_with(
            &hex::decode(SERVER_SIG_CERT_HEX).unwrap(),
            |data, sig, cert| {
                let (_, parsed_cert) = parse_x509_certificate(cert).unwrap();
                let pk = parsed_cert.subject_pki.subject_public_key.as_ref();
                assert_eq!(pk, hex::decode(SERVER_SIG_PK_HEX).unwrap());

                let sig_array: [u8; 64] = sig.try_into().unwrap();
                let signature = p256::Signature::from_bytes(sig_array);
                let public_key = p256::PublicKey::try_from(pk).unwrap();

                p256::verify(
                    libcrux_sha2::Algorithm::Sha256,
                    data,
                    &signature,
                    &public_key,
                )
            },
        );
        assert!(maybe_asl_keys.is_ok());
        let asl_keys = maybe_asl_keys.unwrap();
        assert_eq!(asl_keys.comment, "test keys");
    }
}
