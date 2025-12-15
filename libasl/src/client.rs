/*-
 * #%L
 * libasl
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

use super::model::*;
use super::util::*;
use libcrux::{aead, digest, kem};
use libcrux_ml_kem::mlkem768;

pub struct HandshakeState {
    env: Environment,
    ecdh_sk: kem::PrivateKey,
    pqc_sk: PqcPrivateKey,
    msg1: Vec<u8>,
}

pub struct ContinuationState {
    env: Environment,
    key_id: Vec<u8>,
    k2_c2s_app_data: Vec<u8>,
    k2_s2c_app_data: Vec<u8>,
    k2_s2c_key_confirmation: Vec<u8>,
    expected_hash: Vec<u8>,
}

#[derive(Debug)]
pub struct SessionState {
    pub env: Environment,
    pub key_id: Vec<u8>,
    pub k2_c2s_app_data: Vec<u8>,
    pub k2_s2c_app_data: Vec<u8>,
    pub enc_ctr: u64,
}

#[derive(Clone)]
pub struct HandshakeKeys {
    pub pk: PublicKeys,
    pub sk: PrivateKeys,
}

pub fn initiate_handshake(env: Environment) -> Result<(HandshakeState, Vec<u8>), AslError> {
    initiate_handshake_with_keys(env, generate_handshake_keys()?)
}

pub fn generate_handshake_keys() -> Result<HandshakeKeys, AslError> {
    RNG.with_borrow_mut(|rng| {
        let (ecdh_sk, ecdh_pk) =
            kem::key_gen(kem::Algorithm::Secp256r1, rng).map_err(|_| AslError::InternalError)?;

        let rv: [u8; 64] = rng.generate_array().map_err(|_| AslError::InternalError)?;
        let keys = mlkem768::generate_key_pair(rv);

        Ok(HandshakeKeys {
            pk: PublicKeys {
                ecdh_pk,
                pqc_pk: PqcPublicKey::from(keys.pk()),
            },
            sk: PrivateKeys {
                ecdh_sk,
                pqc_sk: PqcPrivateKey::from(keys.sk()),
            },
        })
    })
}

pub fn initiate_handshake_with_keys(
    env: Environment,
    keys: HandshakeKeys,
) -> Result<(HandshakeState, Vec<u8>), AslError> {
    let m1 = Message1 {
        message_type: String::from(MESSAGE_TYPE_1),
        ecdh_pk: ECDHKey::from(keys.pk.ecdh_pk.encode()),
        pqc_pk: keys.pk.pqc_pk.as_slice().to_vec(),
    };
    let msg1 = serde_cbor::to_vec(&m1).map_err(|_| AslError::InternalError)?;

    let handshake = HandshakeState {
        env,
        ecdh_sk: keys.sk.ecdh_sk,
        pqc_sk: keys.sk.pqc_sk,
        msg1: msg1.clone(),
    };

    Ok((handshake, msg1))
}

pub fn continue_handshake(
    handshake: HandshakeState,
    msg2: &[u8],
) -> Result<(ContinuationState, Vec<u8>), AslError> {
    let m2: Message2 = serde_cbor::from_slice(&msg2).map_err(|_| AslError::DecodingError)?;
    let ss_e = derive_shared_secret(
        &handshake.ecdh_sk,
        &handshake.pqc_sk,
        &m2.ecdh_ct,
        &m2.pqc_ct,
    )?;
    let hk = derive_handshake_keys(&ss_e)?;

    let sig_pk_bytes = decrypt_handshake(&hk.k1_s2c, &m2.aead_ct)?;
    let sig_pk: SignedAslKeys =
        serde_cbor::from_slice(&sig_pk_bytes).map_err(|_| AslError::DecodingError)?;

    // TODO: validate sig_pk incl. stapled OCSP

    let pk: AslKeys =
        serde_cbor::from_slice(&sig_pk.signed_pub_keys).map_err(|_| AslError::DecodingError)?;
    let mat = derive_handshake_material(&pk.ecdh_pk, &pk.pqc_pk)?;
    let sk = derive_session_keys(&ss_e, &mat.ss_p)?;

    let inner = Message3InnerLayer {
        ecdh_ct: ECDHKey::from(mat.ecdh_ct),
        pqc_ct: mat.pqc_ct,
        erp: false,
        eso: false,
    };
    let inner_cbor = serde_cbor::to_vec(&inner).map_err(|_| AslError::InternalError)?;
    let ct_msg_3 = encrypt_handshake(&hk.k1_c2s, &inner_cbor)?;

    let client_hash = digest::hash(
        digest::Algorithm::Sha256,
        &[&handshake.msg1, msg2, &ct_msg_3].concat(),
    );
    let ct_msg_3_key_confirmation = encrypt_handshake(&sk.k2_c2s_key_confirmation, &client_hash)?;

    let m3 = Message3 {
        message_type: String::from(MESSAGE_TYPE_3),
        aead_ct: ct_msg_3,
        aead_ct_key_confirmation: ct_msg_3_key_confirmation,
    };
    let msg3 = serde_cbor::to_vec(&m3).map_err(|_| AslError::InternalError)?;

    let server_hash = digest::hash(
        digest::Algorithm::Sha256,
        &[&handshake.msg1, msg2, &msg3].concat(),
    );

    let state = ContinuationState {
        env: handshake.env,
        key_id: sk.key_id,
        k2_c2s_app_data: sk.k2_c2s_app_data,
        k2_s2c_app_data: sk.k2_s2c_app_data,
        k2_s2c_key_confirmation: sk.k2_s2c_key_confirmation,
        expected_hash: server_hash,
    };

    Ok((state, msg3))
}

pub fn finish_handshake(
    continuation: ContinuationState,
    msg4: &[u8],
) -> Result<SessionState, AslError> {
    let m4: Message4 = serde_cbor::from_slice(&msg4).map_err(|_| AslError::DecodingError)?;

    let server_hash = decrypt_handshake(
        &continuation.k2_s2c_key_confirmation,
        &m4.aead_ct_key_confirmation,
    )?;
    if server_hash != continuation.expected_hash {
        return Err(AslError::TranscriptError);
    }

    let session = SessionState {
        env: continuation.env,
        key_id: continuation.key_id.clone(),
        k2_c2s_app_data: continuation.k2_c2s_app_data.clone(),
        k2_s2c_app_data: continuation.k2_s2c_app_data.clone(),
        enc_ctr: 0,
    };

    Ok(session)
}

pub fn encrypt_request(
    state: &mut SessionState,
    req_ctr: u64,
    request: &[u8],
) -> Result<Vec<u8>, AslError> {
    let key = aead::Key::from_slice(aead::Algorithm::Aes256Gcm, &state.k2_c2s_app_data)
        .map_err(|_| AslError::InternalError)?;
    state.enc_ctr += 1;
    let res = encrypt_session(
        &key,
        &state.key_id,
        state.env,
        MessageMode::Request,
        req_ctr,
        state.enc_ctr,
        request,
    )?;
    Ok(res)
}

pub fn decrypt_response(
    state: &SessionState,
    expect_req_ctr: u64,
    response: &[u8],
) -> Result<Vec<u8>, AslError> {
    let key = aead::Key::from_slice(aead::Algorithm::Aes256Gcm, &state.k2_s2c_app_data)
        .map_err(|_| AslError::InternalError)?;
    let (req_ctr, res) = decrypt_session(
        &key,
        &state.key_id,
        state.env,
        MessageMode::Response,
        response,
    )?;
    if req_ctr != expect_req_ctr {
        return Err(AslError::NotRequest);
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_initiates_handshake() {
        let result = initiate_handshake(Environment::Testing);
        assert!(result.is_ok());

        let (handshake, msg1) = result.unwrap();
        assert!(msg1.len() >= 32 + PQC_PK_SIZE); // enough to contain both public keys
        assert_eq!(handshake.env, Environment::Testing);
        assert_eq!(handshake.msg1, msg1);
    }

    #[test]
    fn it_initiates_handshake_with_keys() {
        const CLIENT_PRIV_EC_HEX: &str =
            "af5b31d69d3f9e12ada4400b969823005209edc8740fb54fe45a74a634eddff4";
        const CLIENT_PUB_EC_HEX: &str = "72943a491acc09bd121d98e6f3699259d2deaf880d33fa103b193dee2679783a137ada82d2d5b143eeec63b62f6a97b7315dd34739284b816100bb1cc333a8ab";
        const CLIENT_PUB_PQ_HEX: &str = "b5dc97ac36028ba414a6c01844c3050d40b2636098a4d3a3d28741d358716ff8c1509cab01aa03c0f796ae92834440cd23f53c5d787cb8184a2a6b98f9e1bab3a8c5fe4b04b4fccf5e770a94677d91236fc06bccef73ad594456487a4547235e6b5811fb805b65b74eca47ac6d997e8896b15e5099891855bfc86e4f2967912b6c98398c05b70c590386f5f844e33a336d2b911b9923294393973389e05536a40751ee2910bfe373cc973509c9c093b1a3fc704e3273c6d4574ef3b1425aa56a026a2a0ff17d61164d3d8729f7b56da0805630d24dad8bbedef2186b0107762b86cd078def21b0e8e8b67ba8c301ab73d70325ac6b5654c058e5c01d1d6966f30b161fab8639c5608fbb8b590b4e5d4615814322b4e75ca7c2cfdbecc2c09c4d97608ffd5c239dd46b203c125db68771499f1b26a36deb7f46d7c98d4357de70a10e199036755eee93159dc247039bce6e729d9ef77574f2c02d2847f046105d646786b514daf7a57c935b7605361d01248d5b9b7e72516e78992a28030d553b8884c11765b3542a6dcd782c5a4a2278939b62b14979a968a9f9168eba89c19cb7bda956768b059fe8b8d6c080e1d590fb0a163f536b8c7988057c5d88357756dc9def5b8583823a0fc720d0dc646b9537eb776604eb2a93996a91e73b409a1552e78102a97201ac4da5ca547016ba0e6645c8d16b995338a366422a173da7851651d78b98e897ce23a253a09e8ce57b6779609ea204b24b13a44663ea4a17231895f898ceb2f915cd177efef3c88e6b41d2c3a74f40502c9350628a74c63b3673d4915f68349af7c9141c5f8dd906061c074bdb2d59f87ac5116cc84ba13c398ba203c6039c2bc4ac6a774160db218a1401714584b247235c8100463da3352fc566f12ab9fe387b62b0c269a628d31219b532a8d8f397ad455fee1c7647f612d129961c07b01960393c491a323b236be64b826a87c00bba4603cab7b2165ce869eda4ccca15bc98479409c09f1d491c0498aab2d29d29c51b6d784d07c86580251c822b26cfe1684c75422ffbcffad011528394e9bc63a827484fb05279ba06a0c7aab211aeb4e9c72af72a3e31ccb6d60bfbe03efdf41895a455f2199e9f4b7168f51f95932c2210bc1a197e7d991ea4111188717123d407960303b34613347443b885651c6038ea3686598813071a9f0f320fc1b94d96f56fb0a1587ea32ec7e86cc5793b412c4e33f770633c675e6288eb23c31b630ebd916b871b098e787e79fb3f7cacc8aa559196a4c6dfd3bb9fcc436a43491a66018d10b14cd219ac9c320c487c02c7a49b88b3fa1bb35172b9e79b42e6d2af7f8582853641a8f8a047f402cd17631a50c5a6d02d5df4236e421a880b8bd4749a01a4c70ef8bb8080301b828922e70f5dc05f10759e2f18096986301b52989a4552eaf67d1499a7fbe6298eb5b39a9750877c17d6e630fb9830cdca38a4c8b401a853f773a64738548989241926905f77a9f240b0393c4222286eaef145db2a7486593e8111b4f8c56507293ada2313e336847708a9c57213c83ccae273897efc6110205153d5189f823d8c744772c22d07e92709006a1e45614e431cee4aa3a2e4bff6c7796989ab5c81f61dd423624ae8595744f831e1f5b5c56e8ccde0384d1f312ea66a1cdfac";
        const CLIENT_PRIV_PQ_HEX: &str = "84428ca0db4237d1172a0b0eaf4917b47cc608b5a92a7710d236c5a84cb542b96f8fd870fd849494434ca2ba9e78c945d411bc0abc8b1a7c1a90c581792b2cbd397f9450b6bcf4ced316260f687bf7cacb89187213a67930904797720331534211fa32709ac07113949bc84c95f65c089689fd02bbbe02678a3c04e76948dd33385fa159da10acf3605d7b858d9e59a44212c963eb25fd3459ee956d01a729f9840a53630cbe8980cd7c7f907c0619a803f22a94f963aed29999e6fc982cf7be5ee9bdfcd28729587fb7c98f9686b99f55c3b60a8504e826e463be1905883175237596cad2a190e3134851274ce3078ad4195392c625bf4b7d5ff783760598d41451ea1626159192a569b345031f38b6b26f7c735ea836d9a6bfba217d5305393728a5feac4220f1bb3c551a975a89fe8b0e22f5b0c011ac6afb8f94d9c684b3151828a8296aacfcf195a5434a4ad4917c5859ceeca071ebcebed6918b7b6ce70c9027a9ba1bc07f77fac5401c8b6172a994f67170ec244018af976694b62245cb099ed29b2c4c807e63b3bee5bb3f21c869554a3c0f1c9457b1a2b6d7337cd2aeff0466d62598d7fc6c5bb7108a6c710f5acf6f656bbbba60301784e0785b375b761340ba8146164adaa8ec780309d34eaa8933d94797741b9fbb85c84e1a7156e3ac741c2008134a0807946282923e138a4b26aa69f02b3fd55b0898ceb074443a554e8ea80cbd206413c7cd2196734aec6fa6931919db0c7aea5e7c240d582318aa396d5c130992ac58a7693e0b5a6ba6d83fd5483d2dda4260471799fb9cabbcad0560762c5a2286cba1ce482082183460131ef78cb2a3ab8e3c7786b2222e73f4a90a478b1064c9ffe04289fca983a9b203fca00c0abf10ca2197e778d959c0621b8f7b3c2b22fc65613a987a26a7c82a63c7627c75e16c7df6c0506aac3a9b590f52696cebaefef367f9312c9d0b89b771b7d44a47ad0060753752522b79bd423ad239121db9c42c9860d5bc7179d962e6d6a99e8a285b975840aa761bfc7aaa835888a23dc4009621415763689ed0167b5573917a6010fdf97ddc047abd073efa733fa95574054571bd16988c6605381b73b9f023742a3f4c8b38ac702576e241a41987a1a4a128d2223125a4bdbc33ef65af4282c8bbea453ac86d612c6c9c26754efa6921941b5d2c09a020aff2d4a3bcd41a0959125e9b6261321a920c89658671db665e582bcc3d877b9d04c5c90680b11607beb1c1fb73a6a2903b1a9c3e2d0b36d45713b65199b3e85c74441b650cba37119b8219bf88688445c7336de1495705c2145883d1d25512b7478394039092242094345e2406d8c57cb7543481e27cafd749e8f8bbe900450ab9459fd58f06ab24ae5a522f8c510e0034bdf4cf46618e34fc57e9ccc124a203a985ca6aab7fcadac9023ca78303238ce2143a2ca4b97800eec0b0b2e27f56813fb1778f56e69684a53d10e63ff89bb8e0d908b1c72a2d2bb04d2562edd4a007bc1533795e77436667c5794bd2015f1805fe2c01ecaa1e3827b1b227b08b6115674157679697b1900dd03822abba0803bcc3d7644d2150b2c3974b9fa80ab82842aafa3691964837e43a56070e11da26b5dc97ac36028ba414a6c01844c3050d40b2636098a4d3a3d28741d358716ff8c1509cab01aa03c0f796ae92834440cd23f53c5d787cb8184a2a6b98f9e1bab3a8c5fe4b04b4fccf5e770a94677d91236fc06bccef73ad594456487a4547235e6b5811fb805b65b74eca47ac6d997e8896b15e5099891855bfc86e4f2967912b6c98398c05b70c590386f5f844e33a336d2b911b9923294393973389e05536a40751ee2910bfe373cc973509c9c093b1a3fc704e3273c6d4574ef3b1425aa56a026a2a0ff17d61164d3d8729f7b56da0805630d24dad8bbedef2186b0107762b86cd078def21b0e8e8b67ba8c301ab73d70325ac6b5654c058e5c01d1d6966f30b161fab8639c5608fbb8b590b4e5d4615814322b4e75ca7c2cfdbecc2c09c4d97608ffd5c239dd46b203c125db68771499f1b26a36deb7f46d7c98d4357de70a10e199036755eee93159dc247039bce6e729d9ef77574f2c02d2847f046105d646786b514daf7a57c935b7605361d01248d5b9b7e72516e78992a28030d553b8884c11765b3542a6dcd782c5a4a2278939b62b14979a968a9f9168eba89c19cb7bda956768b059fe8b8d6c080e1d590fb0a163f536b8c7988057c5d88357756dc9def5b8583823a0fc720d0dc646b9537eb776604eb2a93996a91e73b409a1552e78102a97201ac4da5ca547016ba0e6645c8d16b995338a366422a173da7851651d78b98e897ce23a253a09e8ce57b6779609ea204b24b13a44663ea4a17231895f898ceb2f915cd177efef3c88e6b41d2c3a74f40502c9350628a74c63b3673d4915f68349af7c9141c5f8dd906061c074bdb2d59f87ac5116cc84ba13c398ba203c6039c2bc4ac6a774160db218a1401714584b247235c8100463da3352fc566f12ab9fe387b62b0c269a628d31219b532a8d8f397ad455fee1c7647f612d129961c07b01960393c491a323b236be64b826a87c00bba4603cab7b2165ce869eda4ccca15bc98479409c09f1d491c0498aab2d29d29c51b6d784d07c86580251c822b26cfe1684c75422ffbcffad011528394e9bc63a827484fb05279ba06a0c7aab211aeb4e9c72af72a3e31ccb6d60bfbe03efdf41895a455f2199e9f4b7168f51f95932c2210bc1a197e7d991ea4111188717123d407960303b34613347443b885651c6038ea3686598813071a9f0f320fc1b94d96f56fb0a1587ea32ec7e86cc5793b412c4e33f770633c675e6288eb23c31b630ebd916b871b098e787e79fb3f7cacc8aa559196a4c6dfd3bb9fcc436a43491a66018d10b14cd219ac9c320c487c02c7a49b88b3fa1bb35172b9e79b42e6d2af7f8582853641a8f8a047f402cd17631a50c5a6d02d5df4236e421a880b8bd4749a01a4c70ef8bb8080301b828922e70f5dc05f10759e2f18096986301b52989a4552eaf67d1499a7fbe6298eb5b39a9750877c17d6e630fb9830cdca38a4c8b401a853f773a64738548989241926905f77a9f240b0393c4222286eaef145db2a7486593e8111b4f8c56507293ada2313e336847708a9c57213c83ccae273897efc6110205153d5189f823d8c744772c22d07e92709006a1e45614e431cee4aa3a2e4bff6c7796989ab5c81f61dd423624ae8595744f831e1f5b5c56e8ccde0384d1f312ea66a1cdfac9c8c2d698e58b5036ba871f4247d845fd97265bdef1ba1db360721d462bacd71c3bcfa015553f4dae1ed82b59a1e0b2af4acdd5039aed98f1e55f26a66b391ae";

        const EXPECTED_M1_HEX: &str = "a36b4d65737361676554797065624d3167454344485f504ba36363727665502d3235366178582072943a491acc09bd121d98e6f3699259d2deaf880d33fa103b193dee2679783a61795820137ada82d2d5b143eeec63b62f6a97b7315dd34739284b816100bb1cc333a8ab6d4d4c2d4b454d2d3736385f504b5904a0b5dc97ac36028ba414a6c01844c3050d40b2636098a4d3a3d28741d358716ff8c1509cab01aa03c0f796ae92834440cd23f53c5d787cb8184a2a6b98f9e1bab3a8c5fe4b04b4fccf5e770a94677d91236fc06bccef73ad594456487a4547235e6b5811fb805b65b74eca47ac6d997e8896b15e5099891855bfc86e4f2967912b6c98398c05b70c590386f5f844e33a336d2b911b9923294393973389e05536a40751ee2910bfe373cc973509c9c093b1a3fc704e3273c6d4574ef3b1425aa56a026a2a0ff17d61164d3d8729f7b56da0805630d24dad8bbedef2186b0107762b86cd078def21b0e8e8b67ba8c301ab73d70325ac6b5654c058e5c01d1d6966f30b161fab8639c5608fbb8b590b4e5d4615814322b4e75ca7c2cfdbecc2c09c4d97608ffd5c239dd46b203c125db68771499f1b26a36deb7f46d7c98d4357de70a10e199036755eee93159dc247039bce6e729d9ef77574f2c02d2847f046105d646786b514daf7a57c935b7605361d01248d5b9b7e72516e78992a28030d553b8884c11765b3542a6dcd782c5a4a2278939b62b14979a968a9f9168eba89c19cb7bda956768b059fe8b8d6c080e1d590fb0a163f536b8c7988057c5d88357756dc9def5b8583823a0fc720d0dc646b9537eb776604eb2a93996a91e73b409a1552e78102a97201ac4da5ca547016ba0e6645c8d16b995338a366422a173da7851651d78b98e897ce23a253a09e8ce57b6779609ea204b24b13a44663ea4a17231895f898ceb2f915cd177efef3c88e6b41d2c3a74f40502c9350628a74c63b3673d4915f68349af7c9141c5f8dd906061c074bdb2d59f87ac5116cc84ba13c398ba203c6039c2bc4ac6a774160db218a1401714584b247235c8100463da3352fc566f12ab9fe387b62b0c269a628d31219b532a8d8f397ad455fee1c7647f612d129961c07b01960393c491a323b236be64b826a87c00bba4603cab7b2165ce869eda4ccca15bc98479409c09f1d491c0498aab2d29d29c51b6d784d07c86580251c822b26cfe1684c75422ffbcffad011528394e9bc63a827484fb05279ba06a0c7aab211aeb4e9c72af72a3e31ccb6d60bfbe03efdf41895a455f2199e9f4b7168f51f95932c2210bc1a197e7d991ea4111188717123d407960303b34613347443b885651c6038ea3686598813071a9f0f320fc1b94d96f56fb0a1587ea32ec7e86cc5793b412c4e33f770633c675e6288eb23c31b630ebd916b871b098e787e79fb3f7cacc8aa559196a4c6dfd3bb9fcc436a43491a66018d10b14cd219ac9c320c487c02c7a49b88b3fa1bb35172b9e79b42e6d2af7f8582853641a8f8a047f402cd17631a50c5a6d02d5df4236e421a880b8bd4749a01a4c70ef8bb8080301b828922e70f5dc05f10759e2f18096986301b52989a4552eaf67d1499a7fbe6298eb5b39a9750877c17d6e630fb9830cdca38a4c8b401a853f773a64738548989241926905f77a9f240b0393c4222286eaef145db2a7486593e8111b4f8c56507293ada2313e336847708a9c57213c83ccae273897efc6110205153d5189f823d8c744772c22d07e92709006a1e45614e431cee4aa3a2e4bff6c7796989ab5c81f61dd423624ae8595744f831e1f5b5c56e8ccde0384d1f312ea66a1cdfac";

        let keys = HandshakeKeys {
            pk: PublicKeys {
                ecdh_pk: kem::PublicKey::decode(
                    kem::Algorithm::Secp256r1,
                    &hex::decode(CLIENT_PUB_EC_HEX).unwrap(),
                )
                .unwrap(),
                pqc_pk: libcrux_ml_kem::MlKemPublicKey::from(
                    &hex::decode(CLIENT_PUB_PQ_HEX).unwrap().try_into().unwrap(),
                ),
            },
            sk: PrivateKeys {
                ecdh_sk: kem::PrivateKey::decode(
                    kem::Algorithm::Secp256r1,
                    &hex::decode(CLIENT_PRIV_EC_HEX).unwrap(),
                )
                .unwrap(),
                pqc_sk: libcrux_ml_kem::MlKemPrivateKey::from(
                    &hex::decode(CLIENT_PRIV_PQ_HEX).unwrap().try_into().unwrap(),
                ),
            },
        };

        let result = initiate_handshake_with_keys(Environment::Testing, keys);
        assert!(result.is_ok());

        let (handshake, msg1) = result.unwrap();
        assert_eq!(
            handshake.ecdh_sk.encode(),
            hex::decode(CLIENT_PRIV_EC_HEX).unwrap()
        );
        assert_eq!(
            handshake.pqc_sk.as_slice().to_vec(),
            hex::decode(CLIENT_PRIV_PQ_HEX).unwrap()
        );

        assert!(msg1.len() >= 32 + PQC_PK_SIZE); // enough to contain both public keys
        assert_eq!(msg1, hex::decode(EXPECTED_M1_HEX).unwrap());
    }

    #[test]
    fn it_continues_handshake() {
        const CLIENT_ECDH_SK_HEX: &str =
            "3bdbaa604b9f5be68d938b543464f1515d24535974e0cbeb2c7779b35e9a6a93";
        const CLIENT_PQC_SK_HEX: &str = "fba750a955261d6b62972c4dcbd06182c7a355b946bfc0b44988337a15bcbd800b8a6a908b71437b5a8ca1e95b81288c8e2922078021d48a17e31247386352b5c99eed537b9560504a450dc2c6613b21a9567c3a8c9430099bcdbc9721ae8c82529ba05b6c349218bc96a9100ec59bd8e939b6116065a28ac3781db28ab366a47eb133c1b559310ec542ed6498eea99d28489090da001979c126439689f82da13ca711a5a9d1e36d77521b7bcb89e630035b7817d650c2d7f9a0d218bd2b570934f0618ae0ccc6c4cddd49cb15e214bb48483ee23d2089b81a377f24e21b63615825dc2789284149736c95e6b2c7c189c2733bf751c2abfa87d142b680091d0bc577161843a1573f47d70909f84ce0db3b0c670a55886b40955bb9fa408a433871432210666ffba6a0594937725626077222555681075c7c877251664a6ab2050a4417aa81d41edbc4585a8700501468f9c1adad39a0ca3b072a7b050048cc858385014ab4d5029bebc629a5a06092f2019920b1f019cddae12f49b796bab9b4d28bac89161b3180567efcca575a397775b76a591596446719a4384fa510cea861524b938d02b532d29cf803995db21847655cf03a3465a956d3d709f746c78ce91a2e628d4938abb9c332d1e49e132a93f9362b8b734e386ab5db3a7e2109c5ada23354317852aa7f03b13b6cb2b00480b1ad589e2f007292f9054af86ba13a9d627497930210bdf5479ce339f6008def86637893581a1abd31f01b9dc630f905caae7113421816a547c97a42632ba67581685ff6777c993ac781d151555b6806d1b2b47ccd4c971e4c75a4e1b9112c9163ccb4a9a5d6734c113ea4e8ba73384c7572cb9d3b1c97a0be3f4b037fc28b248cce5ae2017c57c2b9d61dce206c939204adec1555a186194067bde76248eb1f57855a070c1118a327a850bbf201648eac02ee8b7367355b48964168f81150ca64fc709033a8ae93d111930927f54bb75764c5e353cd7114b14a42cbda6c42daa0471b975618ac9e0e07b794d01a28301037b90553ba045c264cd5f2a264e98cf6ea34ed55498bd26b57a88b2ba7629751aa34f8c6d7e6c04c583bdfa41d2eab0636f7bd67e709268821110a2633470d4abcad59c1693873b8442301d9a09ea3870bcfb68bbbb44bb1dc66ff26c392495f475010759c3940a71af401c731f6a5d85cabb0597c9cf6b265e28a20c81d6ac83cb0babbcab4779f267cd53928d7faa7f3736ce96958bbc75d4215b2691370ffc35565135726202a7859485af1ce08bcc8aef0729cbb3de590ccaf3622a5e333f8b06e551b26980a9e26b5ae4de65f2fe14456603236c5585d7ccb0696936ab9c09cf73465b0b7ddf05df170421e5828f48aa993734363cb8d03b13ef173659d2767bdf5a1dbc87101117c4a04159cec3cbb64c9866c4b54431658d00a182c355616c6980511574c959815657099b5c1bb7222680aa610bdd5e5241df32ce03406df20588c582da9452c43a97a76d51bc25185773c327e327f64db9e7d640bfab7c6de17660744727da764e2a02d710190f827a6fdd950ad0674af5723eee50b7343653138aa858a69643a5975b314cce6826ba03ca21a8ca3356f6f5b12d9e5be87854b4b4b41efa89a84698f9d968dd9ac40d818c7853aaa19a7c29a30667f5a6a158b69293bad8fe388825b829348ce171a8a2768a37fac97f36b7320493a74b9cf032abd3460bc00a4cac0715f1813878328123ae537ebfb1ce278b9bd5a09c36a90ada07b40c818be86c039fc7dcdfaa5d2373726a153cc901a8d8b3906988370d731c83c923d094028329617a103b28122d0962b5847a5d4ebb12e5951f5891d31696d5ff2a2bd5a1ff6c101c55971f7b31b0ef7c0f71814289b97c6670a3d173dd61cb399a61fc94142340421274cb40f450f5881096979826be463aca1a5e8eca073b1cc44bacea6ec9b6896cf7f8b50c86647e6f2b2f43a83d316b079237901424db9441e7ee6cb0e5a29c0595d63602e3e5b062ad35ff936b071d00b93733c51d0a966cc141d715f21d8b61209adee3362cb08ca570361ae138ba3291d5bc22030e369dd47c4309c39e8e64111f446bfb585e82b6ea2627c00fd4e8625a19c82af60bb945cd11530149eb2f44075f98ddd893b0a81686f8847d95749a8daa2e2ccb6909b99e73001f1115c65491c66865cb47ab53c9435655780caa8026040452c52595a72794b426422cc3798358dd2470e91f69a7bc601d3956c437b4c32f602b6437adc229583554c69644d359a461a2b60b22734544963c927705bd1900ad30f4b749e8d0322e9708069e550700587565837d1c15adaa1ca2df43c580cb12bcb531137065a509a5901c606a6734af8cf5b5aa7b6a66332b4172efccd7a062cfe1ca68ed3138a6c1beb9a2e391accdc041fe3a4a3a5eccd069a3b84528338e5c4ca8b2d01e3b8c562a848a70f096b18931355a941ccf6576af5246cbb17359cc245c7db708f5a65a3331237746a23bc5662e15339630decba951270568b8083a0387a99448be199af14712dbd27a1ed08a66ab08edbe2c4e772cabed6b9f2589f74d44a8ac594886418a6675371c4a96e10a2cd36916594b5fa71478073827571999c8859c1a449ea4aab6bf2a759500d3d725a81868bad4c5cbb64b5b676c951614b55e694ac011275eab761f6c74feb780c1cc6db32505665115c2119cb2b44d4a9cf756c3905336136b9898723b82876b0ce49c98bb082e8fbc3fb1a71b8b02bee8475e4cb6b67700ade0315580c4922ca61d251a6123a8e921384e463af99fa4792fb3591a694f5bb0df4624de8b61fcb403022a12af5f88ba4a900b79cc9b1bb21d7034ed03b675920141744c9b55c08f5c76af5056d2a09a1e85962cf03483b863aeda91f7018b135b70de9765184719daa2136b28c1b1be7c4c510aeb0882f3e3aba33f12c25c334d36961769b3c8c62b75bf33d30246e532134ac332d1483b1ababbd7a03797c054635c76bd0bbc4bf287523e23958a0bb3ec652ce961f60143167462a8bdb02960b5d3e8a80bfb74320411a06e204e81907b701a1cdf88fc84784fc45313ca27a31226662cc424450361191b32ee24aafe69cae4602f4ca15fc3bcd80295268a72d6bbb0bf04c785fb3492da6c8e51ca283ac6b627b28c50c0c0b88ada9679750cb158bb9275999823b3c512573b825b1214ea4cdbeb3a66014857ec3b5716688b5629c8d05844775cd302c846e5a64322d4a1aaca3040604ad548a1b9e30d0c9b677b3fb04980d7c42ab141c672e2d7207254813dd0d0b85ec7ac50eb4fba09e2b40c11ee17d940f293857a840b3976bf27e452f59695578cd52c99edc4e7e867ff0ee15f658fa26399b028d";
        const MESSAGE1_HEX: &str = "a36b4d65737361676554797065624d3167454344485f504ba36363727665502d32353661785820be58f717ff585fd57a21ceaa17f9153180e379048947ad22820e1f359b52019f61795820b9a8dfce2b054f426db806387f3e918a8daa9d286caf54e8ff37e1165ead5cd86d4d4c2d4b454d2d3736385f504b5904a0d9e5be87854b4b4b41efa89a84698f9d968dd9ac40d818c7853aaa19a7c29a30667f5a6a158b69293bad8fe388825b829348ce171a8a2768a37fac97f36b7320493a74b9cf032abd3460bc00a4cac0715f1813878328123ae537ebfb1ce278b9bd5a09c36a90ada07b40c818be86c039fc7dcdfaa5d2373726a153cc901a8d8b3906988370d731c83c923d094028329617a103b28122d0962b5847a5d4ebb12e5951f5891d31696d5ff2a2bd5a1ff6c101c55971f7b31b0ef7c0f71814289b97c6670a3d173dd61cb399a61fc94142340421274cb40f450f5881096979826be463aca1a5e8eca073b1cc44bacea6ec9b6896cf7f8b50c86647e6f2b2f43a83d316b079237901424db9441e7ee6cb0e5a29c0595d63602e3e5b062ad35ff936b071d00b93733c51d0a966cc141d715f21d8b61209adee3362cb08ca570361ae138ba3291d5bc22030e369dd47c4309c39e8e64111f446bfb585e82b6ea2627c00fd4e8625a19c82af60bb945cd11530149eb2f44075f98ddd893b0a81686f8847d95749a8daa2e2ccb6909b99e73001f1115c65491c66865cb47ab53c9435655780caa8026040452c52595a72794b426422cc3798358dd2470e91f69a7bc601d3956c437b4c32f602b6437adc229583554c69644d359a461a2b60b22734544963c927705bd1900ad30f4b749e8d0322e9708069e550700587565837d1c15adaa1ca2df43c580cb12bcb531137065a509a5901c606a6734af8cf5b5aa7b6a66332b4172efccd7a062cfe1ca68ed3138a6c1beb9a2e391accdc041fe3a4a3a5eccd069a3b84528338e5c4ca8b2d01e3b8c562a848a70f096b18931355a941ccf6576af5246cbb17359cc245c7db708f5a65a3331237746a23bc5662e15339630decba951270568b8083a0387a99448be199af14712dbd27a1ed08a66ab08edbe2c4e772cabed6b9f2589f74d44a8ac594886418a6675371c4a96e10a2cd36916594b5fa71478073827571999c8859c1a449ea4aab6bf2a759500d3d725a81868bad4c5cbb64b5b676c951614b55e694ac011275eab761f6c74feb780c1cc6db32505665115c2119cb2b44d4a9cf756c3905336136b9898723b82876b0ce49c98bb082e8fbc3fb1a71b8b02bee8475e4cb6b67700ade0315580c4922ca61d251a6123a8e921384e463af99fa4792fb3591a694f5bb0df4624de8b61fcb403022a12af5f88ba4a900b79cc9b1bb21d7034ed03b675920141744c9b55c08f5c76af5056d2a09a1e85962cf03483b863aeda91f7018b135b70de9765184719daa2136b28c1b1be7c4c510aeb0882f3e3aba33f12c25c334d36961769b3c8c62b75bf33d30246e532134ac332d1483b1ababbd7a03797c054635c76bd0bbc4bf287523e23958a0bb3ec652ce961f60143167462a8bdb02960b5d3e8a80bfb74320411a06e204e81907b701a1cdf88fc84784fc45313ca27a31226662cc424450361191b32ee24aafe69cae4602f4ca15fc3bcd80295268a72d6bbb0bf04c785fb3492da6c8e51ca283ac6b627b28c50c0c0b88ada9679750cb158bb9275999823b3c512573b825b1214ea4cdbeb3a66014857ec3b5716688b5629c8d05844775cd302c846e5a64322d4a1aaca3040604ad548a1b9e30d0c9b677b3fb04980d7c42ab141c";
        const MESSAGE2_HEX: &str = "a46b4d65737361676554797065624d3267454344485f6374a36363727665502d32353661785820195ad65c4e6f097925619b525a018648b8481c11fb0f8b2dc5e0df50c1f0c75f617958200104663a1bd204c4b42ef3d4f1a4c7accc6457dfd7809143f52d00cfb65ee2656d4d4c2d4b454d2d3736385f6374590440abe51943161fd9f6662fb5622a389633c33e98d7a9d02847b427263490db2a3def73b6de8b1f6f392fcdd3af9f9c1fc0641811b133784b43b22cf8dc60cdc166284286630662845ae44e2bbf5ab6ccb739a08cbbea1be0a0a266b5674c1ba35d0d6615ac1d389eceb2e5e5e2bc4966d8f3ac554b23734a8bda89031bad983410d4b58961f68d47f714bfa32e253e702b48279d06128a7d60ac002807d9079b9ec52baf3bca7c87f9350327e13f9fee1a25ba0bd36e5315445505ca188fec78d63f394c4fb60e99e5af0dcf67c59766b10b244313a5c833a56b4e3d12d16604da5c02bf85fbc57c0948aa6306b31a76b69b82ec4f5c4ef7ccdd05dc3492bd83974d76cd8f3299aa72ea67bde9deb64adf3687c0b4829d10e74617a31ad53982b2b6f3e9bb02de1e034c3c68b3c2b348caa22467541170f115d46e9d9846aefacecd7aea36f79730835344a0c4791e47cb9913e83470f07d8578391e7a2e6f8e3b663ab909115933b4b13f10225a7fc177545ce24972999656a4d228ea63b02f93e62a1f16996fb51efc555b812ece96f89704b4d92e720d6759fbb0754c3c6dd8b22b829123d78a6e621d86c8eb9da7406f2b6e6bbcfd82518962633656c8d912d4ae73d2533c6beaacb4b53350789b721afbbd1d6ab2478b559ac32cc5c25c6b0c3453695e29efc905f487a9d56057e49ca177b657010966e1049ef2d8284cf6327ce95e21dfe7d42523b47aad81355ecf22b9d5b5fda9d8f1b180e7f4347e1d075b8c58493062cf54a2f948b1709ebb678fc842dbba9aef764f791d44fc110cbccd169709ac1dcb5487770e3e3723f55826a88b5ce6b7f9edbb4ea2eb5935ef181f71e9870c9737cd2dc12e60ea348395dd1e700c17911849bb4833e8a711966fee6f48faa8d525753aeb81d6d1c314e769372c78de9b7c3214da9d5bf631b5441be27f9ff5c8c1f0e69fae041ef692b2a7694fd45f6d82daf6938afc67ee41661ec2e92d4eb5dbc1ddf81d45478e25fbca4bc10ba16a69ed487c598873fc6ef1669d8054cb1b573d6854883982996c9a0e92356b088a4d1c9353a8edae5ff4200be5689cfa5b87d3256a0519189360ac7a68c681dc26d386cba427ef6ae4d4b9c531aa4b47810373a0cdb209354b951a075f6319da42bc3060f0964c974f167d60a2c80d4575c063dadf8b23f816af0acfeb132573d88274401d20e3634e63ce01ed7650f635b57214392a1abf28f4d5029949bc19d10ecc597c8066253dae173427b50acff05269b352f1c07c6171c0bec7f3defc3b73ff35642708992fbd4b45703394308b372095713717c3078bebcebf960aef4d866907997c7bd1d2082aa238faec27c41c85ebe1f3d99a8102f794946a2afb27d2c4d445b3be8639b92265d9514b610c35b2d12744c0cd826709ea1188b854b389bda0a69dfc728443d9aa88effd77bf9e5b558c356f08c4af0747134e4db654e77ca85648c9fe5bc0651660ae5bd5688a6205e7cf2145e0cd1222a0fb20e38d539b99c413e15d468467414541445f6374590588e21d696f91ced9072e13c809a98f78c16a33000f5c96652d5f28f9eda9db4417a42421d6fe756d20711b8375fb486ec74795234d43e04c8048305defd79e8d47e0252a887d3244e190394c11ab7ed0616ac151da692b1870073e9a9aa72897735284f0f824a4da61ca58616cc3a77d3b049aedd1e0778c3cb652db3a22218fc8488c478574fd022ce3874b806f234b4fb84cea3fd1955b494c64912fba2c059a2cfe52bdb7b968de7fa8803153bf23f0aeaa0cf3c63ec5d64b41c0f2ba8fc7bf08fd1c4cefd01e7be653f35aad39ec00310691b42e2503cb9efb8f3f689e749af7adc47a9349c1def90c25a0aa64c7873dff01b1d1194cf88ae1a3799ce571bbfbf7157de0833f6a32f2a66f8cde59321d87535636d39139e5cad102fa2eaa9324a122e03fea6f9f5bf400c9542c0ba37316f907dd6479920f1d21f76b743b75cf6db0696d71b5aa881646564e84d288a5d3f4556fd5665dd7e1abe9c8915d8661689a13252c243a932d37a5efa9f106932c0a3ea323e487aa6c91754fff4f1f8165925e87a48a278cd35e8b0bad2a123204cfcb462b4f4a429355d9778f557734fa0f96294528719d20e8aace62fa83e5e668f45524e7c12bd81a5664d499da752246ed2df83e197e770bd83078b7d75e9d2631455a6786021724bdfd042f8c1ac6c410e50dc15b36af0e8be242369a07cad3a937c714ca5d394c5e0819823c0b10775832fd030513df3bc038da7dcb755174eb74ded3eb1d83fc96c69b7dd7afee00f07562f77dbab245b2ae351aaaf538973b9bcc2b8b0bf3dcc3162a71dfb5a3ee848907cce0112e78b5efb5f79f357886f35ee5d4b2671ec4b52416bbebed12304b4f06a259530280c4257a4752e8d96d68d342a16ca6cc98e7ce889f764960192a1cedca2aaa6aad04a3b6911b8a78d75330360a145bbcfa1ae0e3f7ce9560bbc7d087a00951a4f94c371ccf2deb559f32e02f2cdff2940eeaababec0dc8c9a77f8a9dab4f61ed553fca051fea5e7d187152c52718fb409c98e04b4c7fd8d6f33e1fe14e25fd1e442b51ff1c2d702068b615661115674aca25305bb93fcde9c10e8aa16745fe3ce7264edc9519348b92c88be383b4d803063665b52106b0d6e05e32001f3aaf3f738c2c8edaf1eee3f001fabd53b58a4b9ead954e6719730084777ab62911672e24fdfa471108caa6df3b828609ac44f6073f85651699cfff35ae1c2d4618a5600053091ed22940bf915ba2085b0ebd90c7c405d6b162878de3fa3bbd93d57b42f7de9f2ceabac849bcc4ff874b0494b7f86ac6fbb567efa8c736024a73a89a119409e888cb8ce19470d9a035020de7baa60c96bf4cafc67bb936228938d7d97999f4019e75c7454671fd994632b5e7f6bb4875ec1d3b62b3971aadb3ccdd8052d1060891f5aa13d9adfcb526c9e444e47cc133f9e417031b456a1f58c93cc627723333fe0024e2f2ba41b100a7c0b5860714a5b9d99b83ac2fe16c6235511f3630765b1f8c20570745261793c378ac64a20166d4a3bf3cd1dcfd5556e6a04cde7eec5332a64a077553eaa3c242888053b21c957f6cfa2555e19856b74cffe6806157420dc4edc920d8e212968e206b4fb7001e3d129b2800796b4e5f22bdab7f8063b1cac2316af608b57cb939fb386f3437e58494987e85f22c1f7a0521033b0143922eb643f5ad3f338b5506d85caf40e5ae8a9f0311dc3e8a65fd3371a4f43e6335a657ad3f5a20a4fecfd624b16fd758ac2993acdc1bd130b8e657edcb3682e8d82d620596908e46c461d8259e78353d4f0a4864a227054ed085bf44deb71053b1c3e6e0f5fbcd920b71c12cfc8f566b21ea3f669cc253a78073dd2ef5418ebca733dca910b30cab480a1835b4894fc0c232a78f34f1a80d27bac9d525423ff852abb5f5ac4c281e93c49bab5857b2c2a7b4dcba8a9babd3874b42f8c1eb639ce75f78671955765d3a1c61681463c113a94df792ea289452b78f652f";

        const EXPECTED_KEY_ID: &str =
            "12f7d9166a0a2a238daa23e1460e27aed4f50e68311144c35ca8da81e742a600";
        const EXPECTED_C2S_KEY: &str =
            "476992a033724b61d62f9f6be22a068cf38b9ad19760d548e71dc30cdd6f7120";
        const EXPECTED_S2C_KEY: &str =
            "fa4162cdf06f5fae8cd577f45da9ec486216d5a7bd93fab5f1096253b03c2ff7";
        const EXPECTED_S2C_KEY_CONFIRM: &str =
            "4af17a95fed83bc975eaefbf4bd94de958349f3d6ccdb3946b5aeefdb007d884";
        const EXPECTED_HASH: &str =
            "f102630b966c46af5aa90b521da8495e3bc284b85d619b1295356b2601a3cbf8";
        const EXPECTED_MESSAGE_3: &str = "a36b4d65737361676554797065624d3367414541445f63745904d34c4b508293ff209988b4bfd2fdc199605ca46800065aaab6b79882494505ba22d13e01fa05177bb742f432831601571ebb210c1fe1a978ac48ccc3efa7ac3253e983d5ef7acd8c408ca1e8314c2fdf006de55a810ec6d49061c44c0708f8a8f7c3e3b0d5950a2fab00fd1777a1a21ccc8cd2769b5c04a51452c82fc08e7f4b4d75e1117fd2deb41f8bad7f62a105d09e207e758b0aea7843b7c6f184c378fd556ab4f2c5f5b3c58895dd73af341877117379de538726658c2a175c832e246eee3adc4fbc73e543b3a579fafbe1ca031ea7574c763c812af8458a4871b481ecf143a301b8e6a1c2aa1dfa0e3f4cd98e3bea3a33d6c00aeaed6c7cb982514cdb9f8b47d83f1e032f1ff0afe5e31af10d5ce3145e688a7231066c257275ef4d7521fdefec077fb2aa762dc00e22e656e3745a3f559526842cc9fa4d8755b4b23dda5bb1e432479aa84521399baa9890063d2402c44ce1544be7360dc80c600055cb6f268a6218130362402b944324ab8ced88198618a0be4fb3be6b7fff348b1d27770c5204a2f96b46c383251a38f50058495db45e9411ee7b20cb052c555322ee7c769456383499357dfe4f4a84aa4029517caae94d2a4feea045c387dd35ab768abd406e16f08aee3bd51cbb373c2cdd3933d9a43c469b2253e243b47fe4b2bc789629611a7f443edc69348700100741952070560b48042592d05313d21578b7a6b7e3deefa13f6a5a8f006adf94d9b147c813e95fca1b48b1ad5f4f17cdf96eb994c271183a4db5cfab2222e9c0c0ac3262c394ecb2dd1bb6b53171c9bf4b32f6b3fa2408c57d3295eca87f3eb19027da7bd0a2ec4e34dcc31a7d9fed11e0e73cf2100450ced242306273c74adf46fbfd09cf515de6a06059cdaaec6e6e668497d1c2bdd2885d46833cc28ad8be5845bd750494e2f6fafe76393ea866bb7e391a37ff9c6a384599aeabc4d0fd8adf827bde1c6cd2f4e926b3245277a08b351517c440da299be6ae33c5bce704ab0c89aa5511f24c0f08d9c1f5ab1beadf7af9f9224f0cacc94d5ea59fa9b0c3fa26799e3e3e3215c201847903d408baf3ec2e92efe01d7182e4d2ed058af4c1387baa9d2455c86705952932ffe73bb31f734ac6e3a7e091d4a88437d51168f42c7f0e3f2975c47747b7d024484888a569bac909337e65cde53830e5c6dc91b01d02631ced2c37852059719b03c998bb8313592edcb2c196bc7a5b7c5d5f2d099f0d7449691d3553f0398ab827edab9bcb07af95ce14c6fc708b9fdff303677a39b215c7da8e01d79d1fb1316f1cbe03978099f049b10ece4ef949e3d782554c205f187a95b8fed04f38dc6d2f45a3e8548517923fb4d700a98236264c2f6161bfb692987b67dcb3c2cbebcf6ade7c47cc7f43779bddce512f2ec0a0a25187f99535c39a5cf0bd3d687fb993c440971c27f0a55704fda8107a6b0a25535e59e1c5ce3acc4a8fc88ea3eb167b79f13d7edef433a2756073b985c97bb8d4b07a48b9eb00469d8a838067a30ca14c656b66ca7a6400f30053ed45f3bc3720aeb6b8164c5113887248323f444499d10c8bd14b55d72b73075060023796334d8f3534dde9dd38b70b4fc174f46b00c29a8515036e0771c0c9df60765430c8f48b74c411eb92ee4e46b3576d6358ac12c71f6028afa491c5803759abcabe925818948590587ab5f3c3a8723de04748b4c6dfab977c1437ef4a4d4bbeb0b352abc81104f39f11fca6787818414541445f63745f6b65795f636f6e6669726d6174696f6e583cd31b6a07b3024810f009b51878e6a2823935bd42d574646be9a3607f5cdc35d10a94100872f8a84f5cb96132856bde7579e74294a2f18ac89ba15156";

        let handshake = HandshakeState {
            env: Environment::Testing,
            ecdh_sk: kem::PrivateKey::decode(
                kem::Algorithm::Secp256r1,
                &hex::decode(CLIENT_ECDH_SK_HEX).unwrap(),
            )
            .unwrap(),
            pqc_sk: libcrux_ml_kem::MlKemPrivateKey::from(
                &hex::decode(CLIENT_PQC_SK_HEX).unwrap().try_into().unwrap(),
            ),
            msg1: hex::decode(MESSAGE1_HEX).unwrap(),
        };

        let msg2 = hex::decode(MESSAGE2_HEX).unwrap();

        let result = continue_handshake(handshake, &msg2);
        assert!(result.is_ok());

        let (continuation, msg3) = result.unwrap();
        assert_eq!(continuation.key_id, hex::decode(EXPECTED_KEY_ID).unwrap());
        assert_eq!(
            continuation.k2_c2s_app_data,
            hex::decode(EXPECTED_C2S_KEY).unwrap()
        );
        assert_eq!(
            continuation.k2_s2c_app_data,
            hex::decode(EXPECTED_S2C_KEY).unwrap()
        );
        assert_eq!(
            continuation.k2_s2c_key_confirmation,
            hex::decode(EXPECTED_S2C_KEY_CONFIRM).unwrap()
        );
        assert_eq!(
            continuation.expected_hash,
            hex::decode(EXPECTED_HASH).unwrap()
        );
        assert!(msg3.len() >= 32 + 1088 + 32); // enough to contain both ct parameters and hash
        assert_eq!(msg3, hex::decode(EXPECTED_MESSAGE_3).unwrap());
    }

    #[test]
    fn it_finishes_handshake() {
        const KEY_ID: &str = "062f1873787311d017de56d12751af016cb61e5bbf4ea94d5bdbae4d7045e9ba";
        const C2S_KEY: &str = "39b357fb5ec83760a36d78a422878dbff8835efb4d22a7b0220b72c366083ffa";
        const S2C_KEY: &str = "990c4da873c114edc636dd488a2f7e287365231892c89d8c7dbf4935de98545a";
        const S2C_KEY_CONFIRM: &str =
            "c3037acb146fb68a96fbe6a77de72be919208f78305f778695c3bcf49c154cc8";
        const EXPECTED_HASH: &str =
            "057e3123c9a583e609958c5f2240bc451635d7d3d927175775b3dd7b5e65f122";

        const MESSAGE4_HEX: &str = "bf6b4d65737361676554797065624d347818414541445f63745f6b65795f636f6e6669726d6174696f6e583c07fb703bf65fdb1fe619dbebea620894b0416f2559db06e31e2b328698a406a10c1f7a9e0251e18c1a50e82e729ca9f84aa0dd35b7cdc4a20229d510ff";

        let key_id = hex::decode(KEY_ID).unwrap();
        let k2_c2s_app_data = hex::decode(C2S_KEY).unwrap();
        let k2_s2c_app_data = hex::decode(S2C_KEY).unwrap();

        let continuation = ContinuationState {
            env: Environment::Testing,
            key_id: key_id.clone(),
            k2_c2s_app_data: k2_c2s_app_data.clone(),
            k2_s2c_app_data: k2_s2c_app_data.clone(),
            k2_s2c_key_confirmation: hex::decode(S2C_KEY_CONFIRM).unwrap(),
            expected_hash: hex::decode(EXPECTED_HASH).unwrap(),
        };

        let msg4 = hex::decode(MESSAGE4_HEX).unwrap();

        let result = finish_handshake(continuation, &msg4);
        assert!(result.is_ok());

        let session = result.unwrap();
        assert_eq!(session.key_id, key_id);
        assert_eq!(session.k2_c2s_app_data, k2_c2s_app_data);
        assert_eq!(session.k2_s2c_app_data, k2_s2c_app_data);
    }

    #[test]
    fn it_encrypts_request() {
        const KEY_ID_HEX: &str = "062f1873787311d017de56d12751af016cb61e5bbf4ea94d5bdbae4d7045e9ba";
        const C2S_KEY_HEX: &str =
            "39b357fb5ec83760a36d78a422878dbff8835efb4d22a7b0220b72c366083ffa";
        const MESSAGE_HEX: &str = "48656c6c6f20576f726c64"; // "Hello World"

        const EXPECTED_REQUEST_HEX: &str = "0200010000000000000001062f1873787311d017de56d12751af016cb61e5bbf4ea94d5bdbae4d7045e9ba3ff8c36d0000000000000001e12afd34f14e4d0383c26aa402dafe738fb7e69b0dd6a465084042";

        let mut session = SessionState {
            env: Environment::Testing,
            key_id: hex::decode(KEY_ID_HEX).unwrap(),
            k2_c2s_app_data: hex::decode(C2S_KEY_HEX).unwrap(),
            k2_s2c_app_data: vec![], // unused
            enc_ctr: 0,
        };

        let msg = hex::decode(MESSAGE_HEX).unwrap();

        let result = encrypt_request(&mut session, 1, &msg);
        assert!(result.is_ok());

        let request = result.unwrap();
        assert!(request.len() > 72); // enough for header, iv, mac, plus at least 1 byte message
        assert_eq!(request, hex::decode(EXPECTED_REQUEST_HEX).unwrap());
    }

    #[test]
    fn it_decrypts_response() {
        const KEY_ID_HEX: &str = "062f1873787311d017de56d12751af016cb61e5bbf4ea94d5bdbae4d7045e9ba";
        const S2C_KEY_HEX: &str =
            "990c4da873c114edc636dd488a2f7e287365231892c89d8c7dbf4935de98545a";
        const MESSAGE_HEX: &str = "0200020000000000000001062f1873787311d017de56d12751af016cb61e5bbf4ea94d5bdbae4d7045e9badba00c010000000000000001a2269632e2c82216797e1706ebb683f655df12b73656592368a7d3aaab4faa81ec";

        const EXPECTED_RESPONSE_HEX: &str = "5269676874206261636b20617420796121"; // "Right back at ya!"

        let session = SessionState {
            env: Environment::Testing,
            key_id: hex::decode(KEY_ID_HEX).unwrap(),
            k2_c2s_app_data: vec![], // unused
            k2_s2c_app_data: hex::decode(S2C_KEY_HEX).unwrap(),
            enc_ctr: 0, // unused
        };

        let msg = hex::decode(MESSAGE_HEX).unwrap();

        let result = decrypt_response(&session, 1, &msg);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response, hex::decode(EXPECTED_RESPONSE_HEX).unwrap());
    }
}
