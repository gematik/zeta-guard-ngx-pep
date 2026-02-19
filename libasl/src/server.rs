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
use libcrux::{aead, digest};
use serde::Serialize;

const EXPIRES_AFTER_SECONDS: u64 = 24 * 60 * 60;

pub struct Config {
    pub env: Environment,
    pub signed_keys: SignedAslKeys,
    pub sk: PrivateKeys,
}

impl Config {
    pub fn new_with_encoded(
        env: Environment,
        signed_keys_encoded: &[u8],
        private_keys_encoded: &[u8],
    ) -> Result<Self, AslError> {
        let signed_keys: SignedAslKeys =
            serde_cbor::from_slice(signed_keys_encoded).map_err(|_| AslError::DecodingError)?;
        let private_keys: AslPrivateKeys =
            serde_cbor::from_slice(private_keys_encoded).map_err(|_| AslError::DecodingError)?;
        Self::new_with_keys(env, signed_keys, private_keys)
    }

    pub fn new_with_keys(
        env: Environment,
        signed_keys: SignedAslKeys,
        private_keys: AslPrivateKeys,
    ) -> Result<Self, AslError> {
        Ok(Config {
            env,
            signed_keys,
            sk: PrivateKeys::try_from(&private_keys)?,
        })
    }
}

#[derive(Debug)]
pub struct HandshakeState {
    pub ss_e: Vec<u8>,
    pub transcript: Vec<u8>, // M1 || M2
}

#[derive(Debug, Clone)]
pub struct SessionState {
    pub key_id: Vec<u8>,
    pub k2_c2s_app_data: Vec<u8>,
    pub k2_s2c_app_data: Vec<u8>,
    pub expires: u64,
    pub enc_ctr: u64,
}

// This allows modifying the OCSP response without cloning the original
#[derive(Serialize)]
struct SignedAslKeysRef<'a> {
    #[serde(with = "serde_bytes")]
    signed_pub_keys: &'a [u8],
    #[serde(rename = "signature-ES256", with = "serde_bytes")]
    signature_es256: &'a [u8],
    #[serde(with = "serde_bytes")]
    cert_hash: &'a [u8],
    cdv: u64,
    #[serde(with = "serde_bytes")]
    ocsp_response: &'a [u8],
}

pub fn initiate_handshake(
    conf: &Config,
    msg1: &[u8],
    ocsp_response: &[u8],
) -> Result<(HandshakeState, Vec<u8>), AslError> {
    let m1: Message1 = serde_cbor::from_slice(msg1).map_err(|_| AslError::DecodingError)?;
    if m1.message_type != MESSAGE_TYPE_1 {
        return Err(AslError::DecodingError);
    }

    let mat =
        derive_handshake_material(&m1.ecdh_pk, &m1.pqc_pk).map_err(|_| AslError::DecodingError)?;
    let keys = derive_handshake_keys(&mat.ss_p)?;

    let server_keys = SignedAslKeysRef {
        signed_pub_keys: &conf.signed_keys.signed_pub_keys,
        signature_es256: &conf.signed_keys.signature_es256,
        cert_hash: &conf.signed_keys.cert_hash,
        cdv: conf.signed_keys.cdv,
        ocsp_response,
    };
    let signed_public_vau_keys =
        serde_cbor::to_vec(&server_keys).map_err(|_| AslError::InternalError)?;
    let aead_ciphertext_msg_2 = encrypt_handshake(&keys.k1_s2c, &signed_public_vau_keys)?;

    let m2 = Message2 {
        message_type: String::from(MESSAGE_TYPE_2),
        ecdh_ct: ECDHKey::from(mat.ecdh_ct),
        pqc_ct: mat.pqc_ct,
        aead_ct: aead_ciphertext_msg_2.clone(),
    };
    let msg2 = serde_cbor::to_vec(&m2).map_err(|_| AslError::InternalError)?;

    let mut transcript = Vec::with_capacity(msg1.len() + msg2.len());
    transcript.extend(msg1);
    transcript.extend(msg2.iter());

    let handshake = HandshakeState {
        ss_e: mat.ss_p,
        transcript,
    };

    Ok((handshake, msg2))
}

pub fn finish_handshake(
    conf: &Config,
    state: HandshakeState,
    msg3: &[u8],
) -> Result<(SessionState, Vec<u8>), AslError> {
    let keys = derive_handshake_keys(&state.ss_e)?;

    let m3: Message3 = serde_cbor::from_slice(msg3).map_err(|_| AslError::DecodingError)?;
    if m3.message_type != MESSAGE_TYPE_3 {
        return Err(AslError::DecodingError);
    }

    let inner_cbor =
        decrypt_handshake(&keys.k1_c2s, &m3.aead_ct).map_err(|_| AslError::DecryptionFailure)?;
    let inner: Message3InnerLayer =
        serde_cbor::from_slice(&inner_cbor).map_err(|_| AslError::DecodingError)?;
    if inner.eso || inner.erp {
        return Err(AslError::MissingParameters);
    }; // not supported

    let ss_s = derive_shared_secret(
        &conf.sk.ecdh_sk,
        &conf.sk.pqc_sk,
        &inner.ecdh_ct,
        &inner.pqc_ct,
    )?;

    let mat = derive_session_keys(&state.ss_e, &ss_s)?;

    let mut client_transcript = state.transcript.clone();
    client_transcript.extend(m3.aead_ct); // = ciphertext_msg_3
    let client_hash = digest::hash(digest::Algorithm::Sha256, &client_transcript);
    let expected_hash =
        decrypt_handshake(&mat.k2_c2s_key_confirmation, &m3.aead_ct_key_confirmation)?;
    if client_hash != expected_hash {
        return Err(AslError::TranscriptError);
    }

    let mut server_transcript = state.transcript.clone();
    server_transcript.extend(msg3);
    let server_hash = digest::hash(digest::Algorithm::Sha256, &server_transcript);
    let ct_key_confirmation = encrypt_handshake(&mat.k2_s2c_key_confirmation, &server_hash)?;

    let m4 = Message4 {
        message_type: String::from(MESSAGE_TYPE_4),
        aead_ct_key_confirmation: ct_key_confirmation,
    };

    let msg4 = serde_cbor::to_vec(&m4).map_err(|_| AslError::InternalError)?;

    let session = SessionState {
        key_id: mat.key_id,
        k2_c2s_app_data: mat.k2_c2s_app_data,
        k2_s2c_app_data: mat.k2_s2c_app_data,
        expires: utc_now() + EXPIRES_AFTER_SECONDS,
        enc_ctr: 0,
    };

    Ok((session, msg4))
}

pub fn decrypt_request(
    conf: &Config,
    state: &SessionState,
    request: &[u8],
) -> Result<(u64, Vec<u8>), AslError> {
    let key = aead::Key::from_slice(aead::Algorithm::Aes256Gcm, &state.k2_c2s_app_data)
        .map_err(|_| AslError::InternalError)?;
    let res = decrypt_session(&key, &state.key_id, conf.env, MessageMode::Request, request)?;
    Ok(res)
}

pub fn encrypt_response(
    conf: &Config,
    state: &SessionState,
    req_ctr: u64,
    plain: &[u8],
) -> Result<Vec<u8>, AslError> {
    let key = aead::Key::from_slice(aead::Algorithm::Aes256Gcm, &state.k2_s2c_app_data)
        .map_err(|_| AslError::InternalError)?;
    let res = encrypt_session(
        &key,
        &state.key_id,
        conf.env,
        MessageMode::Response,
        req_ctr,
        state.enc_ctr,
        plain,
    )?;
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::super::keys::*;
    use super::*;

    fn create_config() -> Config {
        const SERVER_ECDH_SK_HEX: &str =
            "af5b31d69d3f9e12ada4400b969823005209edc8740fb54fe45a74a634eddff4";
        const SERVER_ECDH_PK_HEX: &str = "72943a491acc09bd121d98e6f3699259d2deaf880d33fa103b193dee2679783a137ada82d2d5b143eeec63b62f6a97b7315dd34739284b816100bb1cc333a8ab";
        const SERVER_PQC_SK_HEX: &str = "84428ca0db4237d1172a0b0eaf4917b47cc608b5a92a7710d236c5a84cb542b96f8fd870fd849494434ca2ba9e78c945d411bc0abc8b1a7c1a90c581792b2cbd397f9450b6bcf4ced316260f687bf7cacb89187213a67930904797720331534211fa32709ac07113949bc84c95f65c089689fd02bbbe02678a3c04e76948dd33385fa159da10acf3605d7b858d9e59a44212c963eb25fd3459ee956d01a729f9840a53630cbe8980cd7c7f907c0619a803f22a94f963aed29999e6fc982cf7be5ee9bdfcd28729587fb7c98f9686b99f55c3b60a8504e826e463be1905883175237596cad2a190e3134851274ce3078ad4195392c625bf4b7d5ff783760598d41451ea1626159192a569b345031f38b6b26f7c735ea836d9a6bfba217d5305393728a5feac4220f1bb3c551a975a89fe8b0e22f5b0c011ac6afb8f94d9c684b3151828a8296aacfcf195a5434a4ad4917c5859ceeca071ebcebed6918b7b6ce70c9027a9ba1bc07f77fac5401c8b6172a994f67170ec244018af976694b62245cb099ed29b2c4c807e63b3bee5bb3f21c869554a3c0f1c9457b1a2b6d7337cd2aeff0466d62598d7fc6c5bb7108a6c710f5acf6f656bbbba60301784e0785b375b761340ba8146164adaa8ec780309d34eaa8933d94797741b9fbb85c84e1a7156e3ac741c2008134a0807946282923e138a4b26aa69f02b3fd55b0898ceb074443a554e8ea80cbd206413c7cd2196734aec6fa6931919db0c7aea5e7c240d582318aa396d5c130992ac58a7693e0b5a6ba6d83fd5483d2dda4260471799fb9cabbcad0560762c5a2286cba1ce482082183460131ef78cb2a3ab8e3c7786b2222e73f4a90a478b1064c9ffe04289fca983a9b203fca00c0abf10ca2197e778d959c0621b8f7b3c2b22fc65613a987a26a7c82a63c7627c75e16c7df6c0506aac3a9b590f52696cebaefef367f9312c9d0b89b771b7d44a47ad0060753752522b79bd423ad239121db9c42c9860d5bc7179d962e6d6a99e8a285b975840aa761bfc7aaa835888a23dc4009621415763689ed0167b5573917a6010fdf97ddc047abd073efa733fa95574054571bd16988c6605381b73b9f023742a3f4c8b38ac702576e241a41987a1a4a128d2223125a4bdbc33ef65af4282c8bbea453ac86d612c6c9c26754efa6921941b5d2c09a020aff2d4a3bcd41a0959125e9b6261321a920c89658671db665e582bcc3d877b9d04c5c90680b11607beb1c1fb73a6a2903b1a9c3e2d0b36d45713b65199b3e85c74441b650cba37119b8219bf88688445c7336de1495705c2145883d1d25512b7478394039092242094345e2406d8c57cb7543481e27cafd749e8f8bbe900450ab9459fd58f06ab24ae5a522f8c510e0034bdf4cf46618e34fc57e9ccc124a203a985ca6aab7fcadac9023ca78303238ce2143a2ca4b97800eec0b0b2e27f56813fb1778f56e69684a53d10e63ff89bb8e0d908b1c72a2d2bb04d2562edd4a007bc1533795e77436667c5794bd2015f1805fe2c01ecaa1e3827b1b227b08b6115674157679697b1900dd03822abba0803bcc3d7644d2150b2c3974b9fa80ab82842aafa3691964837e43a56070e11da26b5dc97ac36028ba414a6c01844c3050d40b2636098a4d3a3d28741d358716ff8c1509cab01aa03c0f796ae92834440cd23f53c5d787cb8184a2a6b98f9e1bab3a8c5fe4b04b4fccf5e770a94677d91236fc06bccef73ad594456487a4547235e6b5811fb805b65b74eca47ac6d997e8896b15e5099891855bfc86e4f2967912b6c98398c05b70c590386f5f844e33a336d2b911b9923294393973389e05536a40751ee2910bfe373cc973509c9c093b1a3fc704e3273c6d4574ef3b1425aa56a026a2a0ff17d61164d3d8729f7b56da0805630d24dad8bbedef2186b0107762b86cd078def21b0e8e8b67ba8c301ab73d70325ac6b5654c058e5c01d1d6966f30b161fab8639c5608fbb8b590b4e5d4615814322b4e75ca7c2cfdbecc2c09c4d97608ffd5c239dd46b203c125db68771499f1b26a36deb7f46d7c98d4357de70a10e199036755eee93159dc247039bce6e729d9ef77574f2c02d2847f046105d646786b514daf7a57c935b7605361d01248d5b9b7e72516e78992a28030d553b8884c11765b3542a6dcd782c5a4a2278939b62b14979a968a9f9168eba89c19cb7bda956768b059fe8b8d6c080e1d590fb0a163f536b8c7988057c5d88357756dc9def5b8583823a0fc720d0dc646b9537eb776604eb2a93996a91e73b409a1552e78102a97201ac4da5ca547016ba0e6645c8d16b995338a366422a173da7851651d78b98e897ce23a253a09e8ce57b6779609ea204b24b13a44663ea4a17231895f898ceb2f915cd177efef3c88e6b41d2c3a74f40502c9350628a74c63b3673d4915f68349af7c9141c5f8dd906061c074bdb2d59f87ac5116cc84ba13c398ba203c6039c2bc4ac6a774160db218a1401714584b247235c8100463da3352fc566f12ab9fe387b62b0c269a628d31219b532a8d8f397ad455fee1c7647f612d129961c07b01960393c491a323b236be64b826a87c00bba4603cab7b2165ce869eda4ccca15bc98479409c09f1d491c0498aab2d29d29c51b6d784d07c86580251c822b26cfe1684c75422ffbcffad011528394e9bc63a827484fb05279ba06a0c7aab211aeb4e9c72af72a3e31ccb6d60bfbe03efdf41895a455f2199e9f4b7168f51f95932c2210bc1a197e7d991ea4111188717123d407960303b34613347443b885651c6038ea3686598813071a9f0f320fc1b94d96f56fb0a1587ea32ec7e86cc5793b412c4e33f770633c675e6288eb23c31b630ebd916b871b098e787e79fb3f7cacc8aa559196a4c6dfd3bb9fcc436a43491a66018d10b14cd219ac9c320c487c02c7a49b88b3fa1bb35172b9e79b42e6d2af7f8582853641a8f8a047f402cd17631a50c5a6d02d5df4236e421a880b8bd4749a01a4c70ef8bb8080301b828922e70f5dc05f10759e2f18096986301b52989a4552eaf67d1499a7fbe6298eb5b39a9750877c17d6e630fb9830cdca38a4c8b401a853f773a64738548989241926905f77a9f240b0393c4222286eaef145db2a7486593e8111b4f8c56507293ada2313e336847708a9c57213c83ccae273897efc6110205153d5189f823d8c744772c22d07e92709006a1e45614e431cee4aa3a2e4bff6c7796989ab5c81f61dd423624ae8595744f831e1f5b5c56e8ccde0384d1f312ea66a1cdfac9c8c2d698e58b5036ba871f4247d845fd97265bdef1ba1db360721d462bacd71c3bcfa015553f4dae1ed82b59a1e0b2af4acdd5039aed98f1e55f26a66b391ae";
        const SERVER_PQC_PK_HEX: &str = "b5dc97ac36028ba414a6c01844c3050d40b2636098a4d3a3d28741d358716ff8c1509cab01aa03c0f796ae92834440cd23f53c5d787cb8184a2a6b98f9e1bab3a8c5fe4b04b4fccf5e770a94677d91236fc06bccef73ad594456487a4547235e6b5811fb805b65b74eca47ac6d997e8896b15e5099891855bfc86e4f2967912b6c98398c05b70c590386f5f844e33a336d2b911b9923294393973389e05536a40751ee2910bfe373cc973509c9c093b1a3fc704e3273c6d4574ef3b1425aa56a026a2a0ff17d61164d3d8729f7b56da0805630d24dad8bbedef2186b0107762b86cd078def21b0e8e8b67ba8c301ab73d70325ac6b5654c058e5c01d1d6966f30b161fab8639c5608fbb8b590b4e5d4615814322b4e75ca7c2cfdbecc2c09c4d97608ffd5c239dd46b203c125db68771499f1b26a36deb7f46d7c98d4357de70a10e199036755eee93159dc247039bce6e729d9ef77574f2c02d2847f046105d646786b514daf7a57c935b7605361d01248d5b9b7e72516e78992a28030d553b8884c11765b3542a6dcd782c5a4a2278939b62b14979a968a9f9168eba89c19cb7bda956768b059fe8b8d6c080e1d590fb0a163f536b8c7988057c5d88357756dc9def5b8583823a0fc720d0dc646b9537eb776604eb2a93996a91e73b409a1552e78102a97201ac4da5ca547016ba0e6645c8d16b995338a366422a173da7851651d78b98e897ce23a253a09e8ce57b6779609ea204b24b13a44663ea4a17231895f898ceb2f915cd177efef3c88e6b41d2c3a74f40502c9350628a74c63b3673d4915f68349af7c9141c5f8dd906061c074bdb2d59f87ac5116cc84ba13c398ba203c6039c2bc4ac6a774160db218a1401714584b247235c8100463da3352fc566f12ab9fe387b62b0c269a628d31219b532a8d8f397ad455fee1c7647f612d129961c07b01960393c491a323b236be64b826a87c00bba4603cab7b2165ce869eda4ccca15bc98479409c09f1d491c0498aab2d29d29c51b6d784d07c86580251c822b26cfe1684c75422ffbcffad011528394e9bc63a827484fb05279ba06a0c7aab211aeb4e9c72af72a3e31ccb6d60bfbe03efdf41895a455f2199e9f4b7168f51f95932c2210bc1a197e7d991ea4111188717123d407960303b34613347443b885651c6038ea3686598813071a9f0f320fc1b94d96f56fb0a1587ea32ec7e86cc5793b412c4e33f770633c675e6288eb23c31b630ebd916b871b098e787e79fb3f7cacc8aa559196a4c6dfd3bb9fcc436a43491a66018d10b14cd219ac9c320c487c02c7a49b88b3fa1bb35172b9e79b42e6d2af7f8582853641a8f8a047f402cd17631a50c5a6d02d5df4236e421a880b8bd4749a01a4c70ef8bb8080301b828922e70f5dc05f10759e2f18096986301b52989a4552eaf67d1499a7fbe6298eb5b39a9750877c17d6e630fb9830cdca38a4c8b401a853f773a64738548989241926905f77a9f240b0393c4222286eaef145db2a7486593e8111b4f8c56507293ada2313e336847708a9c57213c83ccae273897efc6110205153d5189f823d8c744772c22d07e92709006a1e45614e431cee4aa3a2e4bff6c7796989ab5c81f61dd423624ae8595744f831e1f5b5c56e8ccde0384d1f312ea66a1cdfac";
        const SERVER_SIG_SK_HEX: &str = "30770201010420bd37298383eb3d620da1ed367a9a0898e02443fadff0af783e1fbbfdf8250d95a00a06082a8648ce3d030107a144034200048bf54a359336ad068fc57282552526875f0884a8d5b3bc09716edcaa7e0b4443084eea5f2445fea6cfe558edf4a9efea2732efa2d5888b66be9b5b08101448c2";
        const SERVER_SIG_CERT_HEX: &str = "3082017330820119a003020102021450fe87e05a3c00463e0a18387c3dbda92f4828fd300a06082a8648ce3d040302300f310d300b06035504030c0474657374301e170d3235313033303039333430395a170d3335313032383039333430395a300f310d300b06035504030c04746573743059301306072a8648ce3d020106082a8648ce3d030107034200048bf54a359336ad068fc57282552526875f0884a8d5b3bc09716edcaa7e0b4443084eea5f2445fea6cfe558edf4a9efea2732efa2d5888b66be9b5b08101448c2a3533051301d0603551d0e0416041461dd7c90fc9bdf91f8b4c3eaa0ceda715bd523f5301f0603551d2304183016801461dd7c90fc9bdf91f8b4c3eaa0ceda715bd523f5300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020348003045022100d0621bf50aee3ff00713393825f2993adc88a091d1f227e8a2319bc7a33b0e4302201a0276dcceabbf9e7dae50669d9186663f3f00a954e1d9eb87b844bd8733cfe4";
        const REF_DATE_UTC: u64 = 0x69000000u64;

        let (pk, sk) = raw_keys_from_bytes(
            &hex::decode(SERVER_ECDH_SK_HEX).unwrap(),
            &hex::decode(SERVER_ECDH_PK_HEX).unwrap(),
            &hex::decode(SERVER_PQC_SK_HEX).unwrap(),
            &hex::decode(SERVER_PQC_PK_HEX).unwrap(),
        )
        .unwrap();

        let asl_pk = AslKeys::new(&pk, REF_DATE_UTC, 30, "");
        let signed_keys = asl_pk
            .sign(
                &hex::decode(SERVER_SIG_CERT_HEX).unwrap(),
                &hex::decode(SERVER_SIG_SK_HEX).unwrap(),
                1,
            )
            .unwrap();

        Config {
            env: Environment::Testing,
            signed_keys,
            sk,
        }
    }

    #[test]
    fn it_handles_initial_handshake() {
        const MESSAGE1_HEX: &str = "a36b4d65737361676554797065624d3167454344485f504ba36363727665502d32353661785820da21f42b328836f901a502a7a7f815c3e55d3cbf9a01465eef1baf7a33187879617958203235090c34c6a4f54598585a53ab2fd111949483ab01e221ff732033a9dbc8c96d4d4c2d4b454d2d3736385f504b5904a0ff759bda3785c8e2218aa165bc87ca6f308b64dc34c628c9ad45a1c4824eb3304753b20e0b499853e569c5db222daa4b6bcc9242e0abbcf452d409465993b3f18a5e4a5553cb210eda9ba95c7859ae57ab625632fc12cac300b6ded594d4b0144032beab540f87c1b49616b631420d4868353be474f5d4c9d0b918545806e0e33873886375fc330842ab0c357ab2f31ac7c3643b525f0feb31cf62988801aa01564a5b7c47ed720a5ecccd70e61e6c494c6c917e60c728cf618745622ef3b691243b7eb1807fc9019543e0a1ee38530de143df0b93a3a389d621996d2cc8e763264f95317f074bc823cfb35974d0f199839511341649cb4669d0b39240d37bc9e128f8916e11c411c8095e5b02a7b8717118c1886e780e6c533f35a2c17b980fdfb6c650aaaf05e062c982b663266ab1955d29635051487e7d144ec789c51be283a4a21ae8328190ac6a25ebb1ab505f9b08c4081185fdb77883c26821ea8016e3bd04faabdba37712e31ed5b94622b75bb3490659a00a88681ddcc3aa40a964ebb3657bc2870ad14a0c255c978ab498d9061fc59324592e6f630b70e4b6e06b6bdc1a36a63b20fc9744ff2078ec5258d4f4761a487c3ca84120b61a79d79b3519870c8c02fb37c571878ad7f73a5a6369607574dc46cb8012bfb43a3ef6e13c2768b09d23bc494603b1a0caa0148783f99ebc37a06b765aa483c67a82aa8a1c39b7bb10e7b2b347d151561889da01693db98ec9e53fa3b5754b645f4a3b7c1ec32a7f267c88eb0938b09d70941ac2c963e8dc956b14535dc852e1403856651dead596f19443a5577ca2488c328c7118da89ce3aca09fab53874838c2c55c5799f7ed49e5ea158eb29c019eaa2fdcabca268b1baf6be9542b1bc56590cb0243128a95e25262e5b451363473bf612b90138cb146ed115c9bd74611768c62153203c924e0c646f7862757712a50aa1119b11c2e3fa0b42a0b01d3b645f400186f98e9ab045396702e193c081e7460ffc56725b7798007eea01c601a67d8ebcbce59926443961078b2109b04a79eb65d7c718540a168c4b5ef67218e8840322954b7a41b033634af7d1c7a0e504e8840c3c08858c03ccbd498e42439f5ccc78a42c5c9504649b4c7a3be6abfd3810a6927900a7c687389765227212a4cfda4938eb9828d7664e5b721bac1294d146c790499dc47098ad067c0c0245b3f21d461bbeebf935691523c63203d060b0fb0b5a3b19b990b3b2a571abba4a0e617a4aa4e2034a64a164e8b73de27bf8030337758df849aeaa885badf7339c188693613a34b91dcaf801bfa3be5b0c7e901a8be7c253bf241e75b3786a8c81161915c2b722ff906626270844239023f0bf6d954098752403b55a13257596d1bf7488560557a38ddab01e2a8ed977443f74cfa2b4893c26955529aca1066a4ee121e5ab34938aae9b049604540329fcb30d5ccc7da55899423421779d6f3601408bbe1ef232c01b1fcbe8670527185c4c130157bec95c81ecd28b9b8c25c28a70a6f3550108bf085588d28386ea262eaa61cd5c25445cc8924d62bd2f404190a61b0de53af3a36ba4783d796c3e22c86f3f040d159878d7548811d60a42bb3eb84026b8f00d95ca98c0cc662d21ca0e51c6cf7420d1a5a23f9f88074e0c009e23e87904e1e1";

        let conf = create_config();
        let msg1 = hex::decode(MESSAGE1_HEX).unwrap();

        let result2 = initiate_handshake(&conf, &msg1, &[]);
        assert!(result2.is_ok());

        let (handshake, msg2) = result2.unwrap();
        assert_eq!(handshake.ss_e.len(), 64);

        let mut expected_transcript = msg1;
        expected_transcript.extend(msg2);
        assert_eq!(handshake.transcript, expected_transcript);
    }

    #[test]
    fn it_handles_finished_handshake() {
        const MESSAGE1_HEX: &str = "a36b4d65737361676554797065624d3167454344485f504ba36363727665502d32353661785820c9866ead808bdfe93d597d33c35c7aa13a90cfb5004fd77163584f32b749596d6179582008533ad25e362e6152caae985f72b627b270d9d0700717d8df3dfa3b49250dcf6d4d4c2d4b454d2d3736385f504b5904a059562fd5a54b1f80269621c34f82ab6ec45de66bc3382212cd7c1c20e4173443c5959a3187d0b390ea21f0248aeb33073adc6296999ed1aa033968cfbc365cde9c26e078800cc908c27a2f8ada723ec83cefd2c6b280582a061b407c33ad69541ebc883b012ed7987e3116bcdc3c47ab859f8ed6378750b056e49a53cb1bd567606cf7094d0b42abe7a20cf75cb9a4c875f3c34e48954e0c0e1d0b76499bbaf48b4d62b2b63d8a3d689c6e4ad9409734804aa87e58abcb10dc5910d42758127722857d7a5b49a50b8a987017ac3416055ab530ea1b1ec86efd4abf3520cbfedb8760032b0264bb4d58774bf7aaa87701a09bba8a10aca9908b3c614253ab7af9d8058e25cd781270a29b1f5780aa0ab749c63510f8951a9cd059d240a7035ba16bf36baddac60a058cdab7ad9ea94b1e273626faa2e7f6423ac4c5bfc428c09c5ec272365098780f7b8f51f5429727590164688df64d364c6398239271634b7234ba9396b3819a6c93e78b23c595196745a9822609a204c6ecb558fa1fc9baae03d7472a07c39a6049a26322ffda93a8606f57938cc95786dd28724c6854de2717de324422a24b4b9973ca540fa3a5073109478b95bc5029c6e1a0298ca2a4e2e78bf3babaff0848fbf8c3aefb2cb641017f8270ec81c91c9840f62051c4fc16738a11c394b9098b080da2201da8493b3662ff05159f623368228de0790d8bd312c1b63e2b46b362c111c1f42977e44e94194ce090b1e0d99b79f587b1f8318920c77b877d31e3ac6ec367e6f7c124827cc8c81ddeb66850c091e8203cf8c2b3edfc00dfaa23f0020c687b4a367a7a958a8710dbc22e36c300bc5e49acbdc56768b0002736681c8edbc1cfdc56b113cf600563e0f045d789ce5bb481bff7059345450c8b63de612a58755875567363eba9f9bc014d736049311d7a7c93eaa56619141fa4a73dacf14274b4b813fbad5f1c97d295486bc113233a87cd13c35ec2b833aa87e083cd8b542e7de1919a051cdd471da78b4ee0645a8588067e2a78c5c2910a69cb68402ce95b4c13061f76e61e6775157dab44e221352bf54605c29933f63b59f3810bc152009a1002acce5cf94b1f3bb9fa74cff0aa4d376a0818796bddd14cdba84050b311e230aa0df114f4404e057ac7fcec0d9c2b1e544854950833a34a01b4339df0864f0987018f765b8b6425d049ceba21aded177f3bc732294b3bfba39abad3b9ec5391dc53a7b036c9a3c9c47ff8a5c0d734aa97786d4c64e0b00920b18acbdac37dbabe8ef8387796a601431533b620b34861c2300061db7e3c876f64ba1e7cc06f12437ecb77cee5e2b25db89d14e8294a35c79375195cbab08e9a6190568daf712fa95b70241b12651c9e6e833d5d33718b9cbb8fcc3c5fec0520618f093632443c8f57a6930e598ffa5a585437112ad5c36f6c4f4a4776c27ba281422c8db2c3d5754f97f19dd50210f9ac3cbb15b52de3b30e8c669d05979f534df5c09aa76c2a7009536d2421e85454f8a42e7732c638b1c4517061749c8e9684ce94f8a0e8054451b52611608390319b9d559d1e6957f7385dde2253f06698246bc7d489b6a6dc4e3e41126cca994a9918acf27a28e33038b8bbb46c320403d4f09d117a121270c58496355a690054b281a7e5ee61692ba0785e";
        const MESSAGE2_HEX: &str = "a46b4d65737361676554797065624d3267454344485f6374a36363727665502d32353661785820477235528ff210337b2405ba94407aa6061c432c255024e572f3a577ac3d11026179582016408ea9a905cf589474b32b633e79d6ec07884c49939c9280c209183366add26d4d4c2d4b454d2d3736385f6374590440ca50cf1b49d524fff2ce25b194b59200b522c3ff0230f9e8f82bb5daabe160cef5efc8b656d38ad9499ce9e013b23bb575077a6461bbfd65afecf3eb2545c2ec2732896d38d8ec086ca7859a6e434a3d774810c4f80ffffccfd04219a823c3714e3cb39f91a7258566ead9fff5aa9f32bac20f56b74516a12e3449f1eac3f6536094ec4ee1df127d0c2b5274de6ba8d2ab970dbdb95078ae2d17f3891069eecc8a38034fccd8a253f43a91ec1b3a4513fd9a8bd9a985e8f0c66afa71c0ad48c62a65467e8d395539fb3cd56430cf57dec9c41217e6fdb4a03669390830b6d9829f9845d2415024fe72a98f587a7f665ba7e2b4a37d7dded7215376b31e51a4dec3e4d875ce46c96a114e4fc452fc286d8e0915be97d4c1aaf5b11900b355aaae79fe7b296182c70063f454a59152f9f630b778be55e790f41ba388713feaf5118ed3184a2b0b389327f662b63266bd66a516e93322c9e0098bb19405e026078cd899d6ae50a5bacba7279cf159c8ba760ad8696ee23abf6e5e9db83e1df70c4254ec5580c7b34f8f9667491aed4ea49b26a5a4bab4b56b1e973246a6ad9d66da3982c4b3e231cfa11cfb681e2b85ea7b3c2e8815ea3c87e3faf9f72f80267bd3621d81ec806c45bb18a7579f1eb433db7711bfbdb456ef20a22b7f87460799f779c4e1066b1af004c87b0acd60d00ab922d32655d7ffed8612cdfc70d56bd4b4f8d9241f26a6d77f5710da9812cba6c3306182e31f5457bf9b1e124fa120e84a6a9b22858fceff408a207a04c31296d3eabc90601418ac41a2a2f7cf15cd4656cb4f6f88f909120e4e36f422c2c38947d3e3f1b02fba8f48e163f2fd666cb2894ff9bd70a0bb0d1b20a1780c83b6c2e8dd7cd1099136c2f3281b36f243582662875325f9b1c84b2373d6d4d00d2af8bc366a3ddad178a141f54ede1e9779fb30d5c4614dadd119ad64cd165c2d2c951c67fd1fd722eae09db384a19e85b4fd7c66e7c21120967040af265e8cf3e67ea73ae7b89e3fa272e6465f6660cb51b5b9b8d8fb756ee54327478876e46c00a6df9d58ff0e2e0aba26bbc54b63ae9f9b7f88d06af276537b7b123ac737328fb3e864abc78948815484743b62185f2bba3b575a3e4cc47e902356b6454f854b4aaecfce1f5043c2d79c01534d6bcbd7c1f63934ad3b0e5295f10daeccfebaa7faba8191065d034550c6dbb5c3457689a96625ab10b1de61ba03bb9b6777d0cc206735b284effb7799284cccc9ed876209b2cf20c9318b91273304c3d57ca4a055ef39950a713e71abf5b1e54310af6c87195633f06fdfedfedf14142fec3352326520b3986e6a976dcf6e2f34c19e2edb366eb98c1bbd28d701d75b0d4a2ab58fc844141f3facc9af537d625501a3018e7b4a8c4faf0d4154ea6e9b2ba89907607d3690368e415dd04e6b0b9d23aa2063be661850dd68469d8d91d5137fd5979c7ee039fd217b6db7ac4f0bda2e9b7c2206609ff3ebf0e585d7f25d33ae6edd182c132fbe44c7b1eefaec9292dae015229e67414541445f6374590588fd7dca7a14c13d63173fa092c170019833525beeecdc3254a9facf6e7e02e620ac22c05e71f82ed76e0436c48c12587d907842c80d99f2b55026632ba1e4d7a46e66a635a10ae1f14070e2c922450171feadae36e64e9015c25f86a76670691fb6f8ab495a338c88bb78e9d41b1d414b4e07c1cbcb0d9357c224f643083203382a711be883192526019f6f7c8f658037d9fc386a28dd673a93db4512e15863be17aaf13b7a42e1f033b12e25ace80d7e449d9254bcf02b7600e68ec4782552c514553c9a1939876374cc67713b00cd56a8bd32fb50c9bf802b9a0678b3db111dd350bfa833a58b57d6e4b681b0555532914f92b2f62a3357dc8b6310efd3f1834525a240f5ce489ba38d9e7c38be2a0f3697179756749d7cbca1c552d5c3aacbc94586864eda9896c1458af2971f13234f1f8503c9fd71a05921eaeaaf9f6094ced18ae4ea2b5128525149c012c50943e664ac6ed9058655ce173b48244d0ddafde7a35cbeb26f9423edf83ce6337dc1d01a973ac7f3deac10b0e2f6880cce20fb98fa310359199f7e0ed9d2329683f30ef30d21dad3ae7307ecbfa5c45b308ad09495997bf9ed5de0e2f563ec77a168b47edbb22a4c8db8a68dadfef790a47c59df26e984482b03583e70db00f0d39477c0a43444672f277cec79750b22c74d4fef0d2489b5efa2cce71308e2ffd41ac101bbed50f69de8cf007fdd2341ca21dccbb412f1c026141d4e18f0da68c1e1b6d5c7dce024fa96bd6f65169d62bed58288272358636e5337edb896b0494d4c480019d87b20c5c5da9bea5166453318f67c0efc1e88cfb38ab927f24d639f6f54bcff251983f1c193a2417b4c2a2b65218b71184a5172e4afb32755f4ea3db79bc0162583f69038a9900b505d808f8204b198e4ac1564f26df55ff21472dbdcf1fa054813c0cf86a431d45178256d87169a42180f601afee13ea8a3ef6e5be285075946cd2389a2094d5e672a416a400c7b8f0407efa2f5f5020b9b012bf8b13471959ba4698f012bd4d436dfcf8fac3244c323945211d0ee342fc2d7a7a3451bf95aa72824324f66ac9aff97747be37ec807d54dc855a9e50f1d326c81f07e350bb9f7fe3bb121e7abde9e7208eb37f9b5970bf209f6f72f44b2025814150e9d998787a81165743d64256ee22474f953a97cf3a8622bb6c7179f5de4809c8d6cbfd800791eba4d27402f0369053f9a32192cc66218cb74402a888551b25c9d43e8498963c741f3d74d302b0c7e7a1b3e6ff2849a1e664b21f1e4858a83359285bc0a3f091d9731cdb692b4bdad1a486d317bd718330f9881c544683cdbb9915eda1c904ed0ea6997e9aa78c7ae9d3049475cda7d29c008f0f1a531da62fdce6aa4698ea69dbe3cbe7b829cf5b0322c453bda3e0e38409ad5d2845b3bc082f2fb59072aeac9330cb1e7d41fd05cf5f230b38f31d86872fcde54322091712969a7a75030a684e18f613d9156c2bdfb3cf8bdcb35ca423fd62064b0c9d8247e764722612ee2c00ef3a1409aada0e99d137a37e3bdeddb4d21ce7febd857ebff322a261c51dfa5632f6bf4e8582e9308c01d17ef89d70ab7881ead9111620ac60768206720e9a1a3ed4e5b21d201bcfe1e6dd938e3fb9e4265bbe4cf81a62891806766bf8b8c63bcdb03098d33fce0856758dfb674c8b33def88ebdd71fda775de64d85ec4d2c14dcca6e289919d40a3092958a7489e1263e39efbaf4eabbf8e2e3416c673fc533b3dae91ebd4c18dea891615cb5aa5c92ed8b78da24f140998ed137afbe6e1d1d01e1afa8522ee416abdc4f02d676825d22cf71b3108386f58d379c12993db333cdf61dd36738ab8b01f96b6fb1d0b4c6317a159fc1f75e925f574e601f596ea945a305d4b18fcdf97c2f05aa585e02dc4840fd4ef0ca455b012aee4abf3cf386c9aa442c425ba6ade1f1079fb0aee5af4ac26cfca7882a7454361f81309ab6ed51151a548f8e0750ff4945c8560468f1702";
        const MESSAGE3_HEX: &str = "a36b4d65737361676554797065624d3367414541445f63745904d390880475019bbc58ff53a002c55381aaa53318696e85a4d9f04e37b80c2e46857adce9ee220361a8398429a95728480f7b7ee123054f6cff56d7e75bf18846923ec87b3d25d2dc28902cd18c5c43ea89a279718fc8bac55c6f7e5c8ba9809d05dfa2f232da5fb4e0b2b28957108f56847e742112190c2fbcd739d11ad03d7f5af083ff51aa27599fe75c12d1bf9b9a0f252911c0574e4e7c93d980820fa9dd803ce99e37d3859eba39fac7ace5788ff34e68ee5c481e0384de60daf13384541af85282f95d19a25119782ca380b7fa1f18a72a2934668e56619238cc170b5f832c9325d3d4f5aec780e471b031df1cfb21d4f1bb1416ab660d292ac7cbf4e29b28ff4baa2aefeec4b5e63cc0bb4caa88ffd782bbe49139d01d42a1f5bbcee3382cdbaf9d004ae07941ebcb402cd59772e8202450664ab0ef0121ef35c2d602fa5456cf1ef8634656cd493e0fd6ec15b3e8e6d580ddb80d6728879261c39c09f13a06a4664bcaaa7f3f3045b68b9de510a5f6ff887a284c0c1b1eac24e92963c9a2a0e23d05951aa97ee3f5e46ee3764a81c725d1e15dcfcd0e5ce8d5da0102eb8816a4147d17fb1b8cac8ed6714a505abbb7876c87f64d368b0014d37ad9739985e90987e99990e3c52211d819965a18dbd5948a98ec75e6e5847e8ca6b1b6fd959bd55fc9d92e4ca4158843e1843c427eaf5f85b6c08bb2c4708b044c078e5647ce95a6b328faaf638013b3c2bc31f975fccb06e48d0ceb3a96377638d792bc7433e4da5e01435b8d0576d27a22313ddf334770195b2f671f9af87b747ecae9d9c76e348d0c2478dd5d04b93d776e76087ff8fd1e17ad89bfc3989804392e80d84267a09d1e956ef391de2c48d7627dd1be752cf006e353de611c8d2e3a87e81325aaea52d86501e23aaa6602273b14f6a523205f03a27b3d25ee0825623928fcc260f55395b6a4410672d357c5186b7c937a0d22d39a369319de274f211303b114c14fa458ce536c2d9b744eb919e4993d0a05c5ef4b740fe5dcdcc60e92b22e963194a87e02b874cd3c1f011fb92417096f2ea9d6955ad76bed1d8902c23329724d32e4d48e707fc3c8ef402c0b5818f2075a8dd1b106fe08f00762d08776d499b6e4b73239f286ae043295d919f381bd83c8d5753582ea2496173f0f6caa9be152854829e8b9e688f21eb88a047ea23a3ea87132b4ca3bc9ec751c4011d6b86b96e066734377411bd22dfe32111f3b030c89926c5c6440e452e34e1928910ca3bddc60dbc0fbb58e014596f3c57c3ddcb887b208b9e38a7faff043211182858db59166b7f548a300eb71e1864a66eaf22b8acb526775c147ecc33e752f4d52532dd737a52535df7864dbecd24a8d9c03352406c8d8da990e17346a77b3405dd140691f586a0d86a6c7d94780740e8bfc1d99edb5590dbdd989dc17daa6bf8ae9c12838c69877c4cd44e7bb6a5040fdea5114b295a82cf65d2b1bb5220e4a7c74b4267b14003c94c5074baa77fd0c8491524df4895244de7ba623213935b2c7d432eceaaa9af03248f6cd198dd229ef81f4c080c72961e77fd1784aedd7a00a93299d4924e1413295a0df89f74ee7e146c1334f0bc25a591339fc3d7102181ee33140380dd39fac1bb8ef90431af7d51690e50002cbd8a3d4b227905435f60ba275bb619a367d720daa412bff7859e40ffad4f6df958a0e26217c0f8facb2a89d5354fc98cb5c3bad7597b6d81272467ee87818414541445f63745f6b65795f636f6e6669726d6174696f6e583cabf384836d7c2e14bb94d5f7e0bfaf62084e189c1d45c95d0b0fc29d7983e51c8d6fdb8231e30a36e48230a001657fc64b08ba4ad13f675c7602dfae";
        const SS_E_HEX: &str = "24a4911976cf0a6631fe8cd9696c8d551b4c12e181c9822b5721d41a7ad413b4b26ad58cf9804d9a97426095e4d9129d6608b9a6726f7ff2f1d04d199b7dc345";

        const EXPECTED_KEY_ID: &str =
            "446a75ec32b648437db6c1c81eeb1ea6704d335928f319bd57756424ea834536";
        const EXPECTED_C2S_KEY: &str =
            "f6295611fdf269e3042a8e76bbc753509db212b820c8976230844ac305e0cca6";
        const EXPECTED_S2C_KEY: &str =
            "f529ae94a5d8ba8de87738906e9b870511a9f2a9332133f83e9b06b83f2e4926";

        let conf = create_config();
        let handshake = HandshakeState {
            ss_e: hex::decode(SS_E_HEX).unwrap(),
            transcript: [
                hex::decode(MESSAGE1_HEX).unwrap(),
                hex::decode(MESSAGE2_HEX).unwrap(),
            ]
            .concat(),
        };

        let msg3 = hex::decode(MESSAGE3_HEX).unwrap();

        let result4 = finish_handshake(&conf, handshake, &msg3);
        assert!(result4.is_ok());

        let (session, msg4) = result4.unwrap();
        assert_eq!(session.key_id, hex::decode(EXPECTED_KEY_ID).unwrap());
        assert_eq!(
            session.k2_c2s_app_data,
            hex::decode(EXPECTED_C2S_KEY).unwrap()
        );
        assert_eq!(
            session.k2_s2c_app_data,
            hex::decode(EXPECTED_S2C_KEY).unwrap()
        );
        assert!(msg4.len() > 32); // enough for key confirmation, i.e. sha256 block len
    }

    #[test]
    fn it_decrypts_request() {
        const CRYPTO_MESSAGE_HEX: &str = "02000100000000000000010470e2427cc237c7b0ab31162059d47a8c251223c65bc4ec0022227545d9e66b0170ebef0000000000000001544ad8aa9cfc25c9224320a8d82dbff5adc05ee112fcd6cb75e470";
        const KEY_ID_HEX: &str = "0470e2427cc237c7b0ab31162059d47a8c251223c65bc4ec0022227545d9e66b";
        const C2S_KEY_HEX: &str =
            "49b9376b0da3dd6b14eef77301e8b2a508a41667f3946b026b7a0b8d7bfd4baf";

        const EXPECTED_REQUEST_COUNTER: u64 = 1;
        const EXPECTED_MESSAGE_HEX: &str = "48656c6c6f20576f726c64"; // "Hello World"

        let conf = create_config();
        let session = SessionState {
            key_id: hex::decode(KEY_ID_HEX).unwrap(),
            k2_c2s_app_data: hex::decode(C2S_KEY_HEX).unwrap(),
            k2_s2c_app_data: vec![], // unused
            expires: 0, // unused
            enc_ctr: 0, // unused
        };

        let msg = hex::decode(CRYPTO_MESSAGE_HEX).unwrap();

        let result = decrypt_request(&conf, &session, &msg);
        assert!(result.is_ok());

        let (req_ctr, plain) = result.unwrap();
        assert_eq!(req_ctr, EXPECTED_REQUEST_COUNTER);
        assert_eq!(plain, hex::decode(EXPECTED_MESSAGE_HEX).unwrap());
    }

    #[test]
    fn it_encrypts_response() {
        const REQUEST_COUNTER: u64 = 1;
        const PLAIN_MESSAGE_HEX: &str = "48656c6c6f20576f726c64"; // "Hello World"
        const KEY_ID_HEX: &str = "0470e2427cc237c7b0ab31162059d47a8c251223c65bc4ec0022227545d9e66b";
        const S2C_KEY_HEX: &str =
            "49b9376b0da3dd6b14eef77301e8b2a508a41667f3946b026b7a0b8d7bfd4baf";

        const EXPECTED_HEADER: &str = "02000200000000000000010470e2427cc237c7b0ab31162059d47a8c251223c65bc4ec0022227545d9e66b";

        let conf = create_config();
        let session = SessionState {
            key_id: hex::decode(KEY_ID_HEX).unwrap(),
            k2_c2s_app_data: vec![], // unused
            k2_s2c_app_data: hex::decode(S2C_KEY_HEX).unwrap(),
            expires: 0, // unused
            enc_ctr: 0,
        };

        let plain = hex::decode(PLAIN_MESSAGE_HEX).unwrap();

        let result = encrypt_response(&conf, &session, REQUEST_COUNTER, &plain);
        assert!(result.is_ok());

        let crypt = result.unwrap();
        assert!(crypt.starts_with(&hex::decode(EXPECTED_HEADER).unwrap()));
    }
}
