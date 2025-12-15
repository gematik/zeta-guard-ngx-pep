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

use asl::client::HandshakeKeys;
use asl::{
    Config, Environment, MemorySessionCache, SessionCache, client, decrypt_request,
    encrypt_response, finish_handshake, generate_asl_keys, initiate_handshake, raw_keys_from_bytes,
};

#[test]
fn it_performs_roundtrip() {
    const SERVER_SIG_SK_HEX: &str = "30770201010420bd37298383eb3d620da1ed367a9a0898e02443fadff0af783e1fbbfdf8250d95a00a06082a8648ce3d030107a144034200048bf54a359336ad068fc57282552526875f0884a8d5b3bc09716edcaa7e0b4443084eea5f2445fea6cfe558edf4a9efea2732efa2d5888b66be9b5b08101448c2";
    const SERVER_SIG_CERT_HEX: &str = "3082017330820119a003020102021450fe87e05a3c00463e0a18387c3dbda92f4828fd300a06082a8648ce3d040302300f310d300b06035504030c0474657374301e170d3235313033303039333430395a170d3335313032383039333430395a300f310d300b06035504030c04746573743059301306072a8648ce3d020106082a8648ce3d030107034200048bf54a359336ad068fc57282552526875f0884a8d5b3bc09716edcaa7e0b4443084eea5f2445fea6cfe558edf4a9efea2732efa2d5888b66be9b5b08101448c2a3533051301d0603551d0e0416041461dd7c90fc9bdf91f8b4c3eaa0ceda715bd523f5301f0603551d2304183016801461dd7c90fc9bdf91f8b4c3eaa0ceda715bd523f5300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020348003045022100d0621bf50aee3ff00713393825f2993adc88a091d1f227e8a2319bc7a33b0e4302201a0276dcceabbf9e7dae50669d9186663f3f00a954e1d9eb87b844bd8733cfe4";

    const CLIENT_ECDH_SK_HEX: &str =
        "3bdbaa604b9f5be68d938b543464f1515d24535974e0cbeb2c7779b35e9a6a93";
    const CLIENT_ECDH_PK_HEX: &str = "be58f717ff585fd57a21ceaa17f9153180e379048947ad22820e1f359b52019fb9a8dfce2b054f426db806387f3e918a8daa9d286caf54e8ff37e1165ead5cd8";
    const CLIENT_PQC_SK_HEX: &str = "fba750a955261d6b62972c4dcbd06182c7a355b946bfc0b44988337a15bcbd800b8a6a908b71437b5a8ca1e95b81288c8e2922078021d48a17e31247386352b5c99eed537b9560504a450dc2c6613b21a9567c3a8c9430099bcdbc9721ae8c82529ba05b6c349218bc96a9100ec59bd8e939b6116065a28ac3781db28ab366a47eb133c1b559310ec542ed6498eea99d28489090da001979c126439689f82da13ca711a5a9d1e36d77521b7bcb89e630035b7817d650c2d7f9a0d218bd2b570934f0618ae0ccc6c4cddd49cb15e214bb48483ee23d2089b81a377f24e21b63615825dc2789284149736c95e6b2c7c189c2733bf751c2abfa87d142b680091d0bc577161843a1573f47d70909f84ce0db3b0c670a55886b40955bb9fa408a433871432210666ffba6a0594937725626077222555681075c7c877251664a6ab2050a4417aa81d41edbc4585a8700501468f9c1adad39a0ca3b072a7b050048cc858385014ab4d5029bebc629a5a06092f2019920b1f019cddae12f49b796bab9b4d28bac89161b3180567efcca575a397775b76a591596446719a4384fa510cea861524b938d02b532d29cf803995db21847655cf03a3465a956d3d709f746c78ce91a2e628d4938abb9c332d1e49e132a93f9362b8b734e386ab5db3a7e2109c5ada23354317852aa7f03b13b6cb2b00480b1ad589e2f007292f9054af86ba13a9d627497930210bdf5479ce339f6008def86637893581a1abd31f01b9dc630f905caae7113421816a547c97a42632ba67581685ff6777c993ac781d151555b6806d1b2b47ccd4c971e4c75a4e1b9112c9163ccb4a9a5d6734c113ea4e8ba73384c7572cb9d3b1c97a0be3f4b037fc28b248cce5ae2017c57c2b9d61dce206c939204adec1555a186194067bde76248eb1f57855a070c1118a327a850bbf201648eac02ee8b7367355b48964168f81150ca64fc709033a8ae93d111930927f54bb75764c5e353cd7114b14a42cbda6c42daa0471b975618ac9e0e07b794d01a28301037b90553ba045c264cd5f2a264e98cf6ea34ed55498bd26b57a88b2ba7629751aa34f8c6d7e6c04c583bdfa41d2eab0636f7bd67e709268821110a2633470d4abcad59c1693873b8442301d9a09ea3870bcfb68bbbb44bb1dc66ff26c392495f475010759c3940a71af401c731f6a5d85cabb0597c9cf6b265e28a20c81d6ac83cb0babbcab4779f267cd53928d7faa7f3736ce96958bbc75d4215b2691370ffc35565135726202a7859485af1ce08bcc8aef0729cbb3de590ccaf3622a5e333f8b06e551b26980a9e26b5ae4de65f2fe14456603236c5585d7ccb0696936ab9c09cf73465b0b7ddf05df170421e5828f48aa993734363cb8d03b13ef173659d2767bdf5a1dbc87101117c4a04159cec3cbb64c9866c4b54431658d00a182c355616c6980511574c959815657099b5c1bb7222680aa610bdd5e5241df32ce03406df20588c582da9452c43a97a76d51bc25185773c327e327f64db9e7d640bfab7c6de17660744727da764e2a02d710190f827a6fdd950ad0674af5723eee50b7343653138aa858a69643a5975b314cce6826ba03ca21a8ca3356f6f5b12d9e5be87854b4b4b41efa89a84698f9d968dd9ac40d818c7853aaa19a7c29a30667f5a6a158b69293bad8fe388825b829348ce171a8a2768a37fac97f36b7320493a74b9cf032abd3460bc00a4cac0715f1813878328123ae537ebfb1ce278b9bd5a09c36a90ada07b40c818be86c039fc7dcdfaa5d2373726a153cc901a8d8b3906988370d731c83c923d094028329617a103b28122d0962b5847a5d4ebb12e5951f5891d31696d5ff2a2bd5a1ff6c101c55971f7b31b0ef7c0f71814289b97c6670a3d173dd61cb399a61fc94142340421274cb40f450f5881096979826be463aca1a5e8eca073b1cc44bacea6ec9b6896cf7f8b50c86647e6f2b2f43a83d316b079237901424db9441e7ee6cb0e5a29c0595d63602e3e5b062ad35ff936b071d00b93733c51d0a966cc141d715f21d8b61209adee3362cb08ca570361ae138ba3291d5bc22030e369dd47c4309c39e8e64111f446bfb585e82b6ea2627c00fd4e8625a19c82af60bb945cd11530149eb2f44075f98ddd893b0a81686f8847d95749a8daa2e2ccb6909b99e73001f1115c65491c66865cb47ab53c9435655780caa8026040452c52595a72794b426422cc3798358dd2470e91f69a7bc601d3956c437b4c32f602b6437adc229583554c69644d359a461a2b60b22734544963c927705bd1900ad30f4b749e8d0322e9708069e550700587565837d1c15adaa1ca2df43c580cb12bcb531137065a509a5901c606a6734af8cf5b5aa7b6a66332b4172efccd7a062cfe1ca68ed3138a6c1beb9a2e391accdc041fe3a4a3a5eccd069a3b84528338e5c4ca8b2d01e3b8c562a848a70f096b18931355a941ccf6576af5246cbb17359cc245c7db708f5a65a3331237746a23bc5662e15339630decba951270568b8083a0387a99448be199af14712dbd27a1ed08a66ab08edbe2c4e772cabed6b9f2589f74d44a8ac594886418a6675371c4a96e10a2cd36916594b5fa71478073827571999c8859c1a449ea4aab6bf2a759500d3d725a81868bad4c5cbb64b5b676c951614b55e694ac011275eab761f6c74feb780c1cc6db32505665115c2119cb2b44d4a9cf756c3905336136b9898723b82876b0ce49c98bb082e8fbc3fb1a71b8b02bee8475e4cb6b67700ade0315580c4922ca61d251a6123a8e921384e463af99fa4792fb3591a694f5bb0df4624de8b61fcb403022a12af5f88ba4a900b79cc9b1bb21d7034ed03b675920141744c9b55c08f5c76af5056d2a09a1e85962cf03483b863aeda91f7018b135b70de9765184719daa2136b28c1b1be7c4c510aeb0882f3e3aba33f12c25c334d36961769b3c8c62b75bf33d30246e532134ac332d1483b1ababbd7a03797c054635c76bd0bbc4bf287523e23958a0bb3ec652ce961f60143167462a8bdb02960b5d3e8a80bfb74320411a06e204e81907b701a1cdf88fc84784fc45313ca27a31226662cc424450361191b32ee24aafe69cae4602f4ca15fc3bcd80295268a72d6bbb0bf04c785fb3492da6c8e51ca283ac6b627b28c50c0c0b88ada9679750cb158bb9275999823b3c512573b825b1214ea4cdbeb3a66014857ec3b5716688b5629c8d05844775cd302c846e5a64322d4a1aaca3040604ad548a1b9e30d0c9b677b3fb04980d7c42ab141c672e2d7207254813dd0d0b85ec7ac50eb4fba09e2b40c11ee17d940f293857a840b3976bf27e452f59695578cd52c99edc4e7e867ff0ee15f658fa26399b028d";
    const CLIENT_PQC_PK_HEX: &str = "d9e5be87854b4b4b41efa89a84698f9d968dd9ac40d818c7853aaa19a7c29a30667f5a6a158b69293bad8fe388825b829348ce171a8a2768a37fac97f36b7320493a74b9cf032abd3460bc00a4cac0715f1813878328123ae537ebfb1ce278b9bd5a09c36a90ada07b40c818be86c039fc7dcdfaa5d2373726a153cc901a8d8b3906988370d731c83c923d094028329617a103b28122d0962b5847a5d4ebb12e5951f5891d31696d5ff2a2bd5a1ff6c101c55971f7b31b0ef7c0f71814289b97c6670a3d173dd61cb399a61fc94142340421274cb40f450f5881096979826be463aca1a5e8eca073b1cc44bacea6ec9b6896cf7f8b50c86647e6f2b2f43a83d316b079237901424db9441e7ee6cb0e5a29c0595d63602e3e5b062ad35ff936b071d00b93733c51d0a966cc141d715f21d8b61209adee3362cb08ca570361ae138ba3291d5bc22030e369dd47c4309c39e8e64111f446bfb585e82b6ea2627c00fd4e8625a19c82af60bb945cd11530149eb2f44075f98ddd893b0a81686f8847d95749a8daa2e2ccb6909b99e73001f1115c65491c66865cb47ab53c9435655780caa8026040452c52595a72794b426422cc3798358dd2470e91f69a7bc601d3956c437b4c32f602b6437adc229583554c69644d359a461a2b60b22734544963c927705bd1900ad30f4b749e8d0322e9708069e550700587565837d1c15adaa1ca2df43c580cb12bcb531137065a509a5901c606a6734af8cf5b5aa7b6a66332b4172efccd7a062cfe1ca68ed3138a6c1beb9a2e391accdc041fe3a4a3a5eccd069a3b84528338e5c4ca8b2d01e3b8c562a848a70f096b18931355a941ccf6576af5246cbb17359cc245c7db708f5a65a3331237746a23bc5662e15339630decba951270568b8083a0387a99448be199af14712dbd27a1ed08a66ab08edbe2c4e772cabed6b9f2589f74d44a8ac594886418a6675371c4a96e10a2cd36916594b5fa71478073827571999c8859c1a449ea4aab6bf2a759500d3d725a81868bad4c5cbb64b5b676c951614b55e694ac011275eab761f6c74feb780c1cc6db32505665115c2119cb2b44d4a9cf756c3905336136b9898723b82876b0ce49c98bb082e8fbc3fb1a71b8b02bee8475e4cb6b67700ade0315580c4922ca61d251a6123a8e921384e463af99fa4792fb3591a694f5bb0df4624de8b61fcb403022a12af5f88ba4a900b79cc9b1bb21d7034ed03b675920141744c9b55c08f5c76af5056d2a09a1e85962cf03483b863aeda91f7018b135b70de9765184719daa2136b28c1b1be7c4c510aeb0882f3e3aba33f12c25c334d36961769b3c8c62b75bf33d30246e532134ac332d1483b1ababbd7a03797c054635c76bd0bbc4bf287523e23958a0bb3ec652ce961f60143167462a8bdb02960b5d3e8a80bfb74320411a06e204e81907b701a1cdf88fc84784fc45313ca27a31226662cc424450361191b32ee24aafe69cae4602f4ca15fc3bcd80295268a72d6bbb0bf04c785fb3492da6c8e51ca283ac6b627b28c50c0c0b88ada9679750cb158bb9275999823b3c512573b825b1214ea4cdbeb3a66014857ec3b5716688b5629c8d05844775cd302c846e5a64322d4a1aaca3040604ad548a1b9e30d0c9b677b3fb04980d7c42ab141c";

    // Step 0: Configure Server
    // Note: Normally should load keys/config from file
    let (server_keys, private_keys) = generate_asl_keys(30, "").unwrap();
    let signed_keys = server_keys
        .sign(
            &hex::decode(SERVER_SIG_CERT_HEX).unwrap(),
            &hex::decode(SERVER_SIG_SK_HEX).unwrap(),
            1,
        )
        .unwrap();
    let server_config =
        Config::new_with_keys(Environment::Testing, signed_keys, private_keys).unwrap();
    let server_cache = MemorySessionCache::new();

    // Step 1: Client initiates Handshake with M1 to generic /ASL endpoint
    // Note: Normally should use random keys via client::initiate_handshake(env)
    // let client_keys = client::generate_handshake_keys().unwrap();
    let (client_raw_pk, client_raw_sk) = raw_keys_from_bytes(
        &hex::decode(CLIENT_ECDH_SK_HEX).unwrap(),
        &hex::decode(CLIENT_ECDH_PK_HEX).unwrap(),
        &hex::decode(CLIENT_PQC_SK_HEX).unwrap(),
        &hex::decode(CLIENT_PQC_PK_HEX).unwrap(),
    )
    .unwrap();
    let client_keys = HandshakeKeys {
        pk: client_raw_pk,
        sk: client_raw_sk,
    };
    let maybe_m1 = client::initiate_handshake_with_keys(Environment::Testing, client_keys);
    assert!(maybe_m1.is_ok());
    let (client_handshake, m1) = maybe_m1.unwrap();
    println!("M1: {}", hex::encode(&m1));

    // Step 2: Server processes initial Handshake M1 from /ASL, produces M2 and ZETA-ASL-CID header
    let ocsp_response = &[]; // TODO ignored for now
    let maybe_m2 = initiate_handshake(&server_config, &m1, ocsp_response);
    assert!(maybe_m2.is_ok());
    let (server_handshake1, m2) = maybe_m2.unwrap();
    let cid = server_cache.init_handshake(server_handshake1);
    println!("CID: {}", cid);
    println!("M2: {}", hex::encode(&m2));

    // Step 3: Client continues Handshake with M2, sends M3 to endpoint from ZETA-ASL-CID header
    let maybe_m3 = client::continue_handshake(client_handshake, &m2);
    assert!(maybe_m3.is_ok());
    let (client_continuation, m3) = maybe_m3.unwrap();
    println!("M3: {}", hex::encode(&m3));

    // Step 4: Server finishes Handshake with M3, produces M4
    let maybe_server_handshake = server_cache.finish_handshake(&cid);
    assert!(maybe_server_handshake.is_some());
    let server_handshake2 = maybe_server_handshake.unwrap();
    let maybe_m4 = finish_handshake(&server_config, server_handshake2, &m3);
    assert!(maybe_m4.is_ok());
    let (server_session, m4) = maybe_m4.unwrap();
    server_cache.start_session(&cid, server_session);
    println!("M4: {}", hex::encode(&m4));

    // Step 5: Client finishes Handshake with M4
    let maybe_client_session = client::finish_handshake(client_continuation, &m4);
    assert!(maybe_client_session.is_ok());
    let mut client_session = maybe_client_session.unwrap();
    println!("key_id: {}", hex::encode(&client_session.key_id));
    println!(
        "k2_c2s_app_data: {}",
        hex::encode(&client_session.k2_c2s_app_data)
    );
    println!(
        "k2_s2_s2c_app_data: {}",
        hex::encode(&client_session.k2_s2c_app_data)
    );

    // Step 6: Client sends a request to the server at endpoint from ZETA-ASL-CID header
    let client_plain_request = "Hello World".as_bytes();
    let client_req_ctr = 1;
    let maybe_client_request =
        client::encrypt_request(&mut client_session, client_req_ctr, client_plain_request);
    assert!(maybe_client_request.is_ok());
    let client_request = maybe_client_request.unwrap();
    println!("request: {}", hex::encode(&client_request));

    // Step 7: Server processes request
    let maybe_server_session = server_cache.continue_session(&cid);
    assert!(maybe_server_session.is_some());
    let server_session = maybe_server_session.unwrap();
    let maybe_inner_request = decrypt_request(&server_config, &server_session, &client_request);
    assert!(maybe_inner_request.is_ok());
    let (server_req_ctr, inner_request) = maybe_inner_request.unwrap();
    assert_eq!(server_req_ctr, client_req_ctr);
    assert_eq!(inner_request, client_plain_request);

    // (Server forwards inner_request to resource server, receives server_plain_response)

    // Step 8: Server sends a response
    let server_plain_response = "Right back at ya!".as_bytes();
    let maybe_server_response = encrypt_response(
        &server_config,
        &server_session,
        server_req_ctr,
        server_plain_response,
    );
    assert!(maybe_server_response.is_ok());
    let server_response = maybe_server_response.unwrap();
    println!("response: {}", hex::encode(&server_response));

    // Step 9: Client processes response
    let maybe_plain_response =
        client::decrypt_response(&client_session, client_req_ctr, &server_response);
    assert!(maybe_plain_response.is_ok());
    let plain_response = maybe_plain_response.unwrap();
    assert_eq!(plain_response, server_plain_response);
}
