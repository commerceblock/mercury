#[cfg(test)]
mod tests {
    extern crate shared_lib;
    use super::super::routes::ecdsa;
    use super::super::server;
    use shared_lib::structs::{DepositMsg1,PrepareSignTxMessage};
    use rocket::http::{ContentType,Status};
    use rocket::local::Client;
    use curv::arithmetic::traits::Converter;
    use curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::*;
    use curv::BigInt;
    use kms::chain_code::two_party as chain_code;
    use kms::ecdsa::two_party::*;
    use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;

    use serde_json;
    use floating_duration::TimeFormat;
    use std::time::Instant;
    use std::env;

    fn key_gen(client: &Client) -> (String, MasterKey2) {
        time_test!();

        /*************** START: FIRST MESSAGE ***************/
        let start = Instant::now();

        // get ID
        let deposit_msg1 = DepositMsg1{proof_key: String::from("proof key")};
        let body = serde_json::to_string(&deposit_msg1).unwrap();
        let mut response = client
            .post("/deposit/init")
            .body(body)
            .header(ContentType::JSON)
            .dispatch();
        let id: String = serde_json::from_str(&response.body_string().unwrap()).unwrap();

        println!("{} id generated: {:?}", TimeFormat(start.elapsed()), id);

        let mut response = client
            .post(format!("/ecdsa/keygen/{}/first",id))
            .header(ContentType::JSON)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        println!("{} Network/Server: party1 first message", TimeFormat(start.elapsed()));

        let res_body = response.body_string().unwrap();
        let (id, kg_party_one_first_message): (String, party_one::KeyGenFirstMsg) =
            serde_json::from_str(&res_body).unwrap();

        let start = Instant::now();

        let (kg_party_two_first_message, kg_ec_key_pair_party2) =
            MasterKey2::key_gen_first_message();

        println!("{} Client: party2 first message", TimeFormat(start.elapsed()));
        /*************** END: FIRST MESSAGE ***************/

        /*************** START: SECOND MESSAGE ***************/
        let body = serde_json::to_string(&kg_party_two_first_message.d_log_proof).unwrap();

        let start = Instant::now();

        let mut response = client
            .post(format!("/ecdsa/keygen/{}/second", id))
            .body(body)
            .header(ContentType::JSON)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        println!("{} Network/Server: party1 second message", TimeFormat(start.elapsed()));

        let res_body = response.body_string().unwrap();
        let kg_party_one_second_message: party1::KeyGenParty1Message2 =
            serde_json::from_str(&res_body).unwrap();

        let start = Instant::now();

        let key_gen_second_message = MasterKey2::key_gen_second_message(
            &kg_party_one_first_message,
            &kg_party_one_second_message,
        );
        assert!(key_gen_second_message.is_ok());

        println!("{} Client: party2 second message", TimeFormat(start.elapsed()));

        let (party_two_second_message, party_two_paillier, party_two_pdl_chal) =
            key_gen_second_message.unwrap();
        /*************** END: SECOND MESSAGE ***************/

        /*************** START: THIRD MESSAGE ***************/
        let body = serde_json::to_string(&party_two_second_message.pdl_first_message).unwrap();

        let start = Instant::now();

        let mut response = client
            .post(format!("/ecdsa/keygen/{}/third", id))
            .body(body)
            .header(ContentType::JSON)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        println!("{} Network/Server: party1 third message", TimeFormat(start.elapsed()));

        let res_body = response.body_string().unwrap();
        let party_one_third_message: party_one::PDLFirstMessage =
            serde_json::from_str(&res_body).unwrap();

        let start = Instant::now();

        let pdl_decom_party2 = MasterKey2::key_gen_third_message(&party_two_pdl_chal);

        println!("{} Client: party2 third message", TimeFormat(start.elapsed()));
        /*************** END: THIRD MESSAGE ***************/

        /*************** START: FOURTH MESSAGE ***************/

        let party_2_pdl_second_message = pdl_decom_party2;
        let request = party_2_pdl_second_message;
        let body = serde_json::to_string(&request).unwrap();

        let start = Instant::now();

        let mut response = client
            .post(format!("/ecdsa/keygen/{}/fourth", id))
            .body(body)
            .header(ContentType::JSON)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        println!("{} Network/Server: party1 fourth message", TimeFormat(start.elapsed()));

        let res_body = response.body_string().unwrap();
        let party_one_pdl_second_message: party_one::PDLSecondMessage =
            serde_json::from_str(&res_body).unwrap();

        let start = Instant::now();

        MasterKey2::key_gen_fourth_message(
            &party_two_pdl_chal,
            &party_one_third_message,
            &party_one_pdl_second_message,
        )
        .expect("pdl error party1");

        println!("{} Client: party2 fourth message", TimeFormat(start.elapsed()));
        /*************** END: FOURTH MESSAGE ***************/

        /*************** START: CHAINCODE FIRST MESSAGE ***************/
        let start = Instant::now();

        let mut response = client
            .post(format!("/ecdsa/keygen/{}/chaincode/first", id))
            .header(ContentType::JSON)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        println!(
            "{} Network/Server: party1 chain code first message",
            TimeFormat(start.elapsed())
        );

        let res_body = response.body_string().unwrap();
        let cc_party_one_first_message: Party1FirstMessage =
            serde_json::from_str(&res_body).unwrap();

        let start = Instant::now();
        let (cc_party_two_first_message, cc_ec_key_pair2) =
            chain_code::party2::ChainCode2::chain_code_first_message();

        println!("{} Client: party2 chain code first message", TimeFormat(start.elapsed()));
        /*************** END: CHAINCODE FIRST MESSAGE ***************/

        /*************** START: CHAINCODE SECOND MESSAGE ***************/
        let body = serde_json::to_string(&cc_party_two_first_message.d_log_proof).unwrap();

        let start = Instant::now();

        let mut response = client
            .post(format!("/ecdsa/keygen/{}/chaincode/second", id))
            .body(body)
            .header(ContentType::JSON)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        println!(
            "{} Network/Server: party1 chain code second message",
            TimeFormat(start.elapsed())
        );

        let res_body = response.body_string().unwrap();
        let cc_party_one_second_message: Party1SecondMessage =
            serde_json::from_str(&res_body).unwrap();

        let start = Instant::now();
        let _cc_party_two_second_message =
            chain_code::party2::ChainCode2::chain_code_second_message(
                &cc_party_one_first_message,
                &cc_party_one_second_message,
            );

        println!("{} Client: party2 chain code second message", TimeFormat(start.elapsed()));
        /*************** END: CHAINCODE SECOND MESSAGE ***************/

        let start = Instant::now();
        let party2_cc = chain_code::party2::ChainCode2::compute_chain_code(
            &cc_ec_key_pair2,
            &cc_party_one_second_message.comm_witness.public_share,
        )
        .chain_code;

        println!("{} Client: party2 chain code second message", TimeFormat(start.elapsed()));
        /*************** END: CHAINCODE COMPUTE MESSAGE ***************/

        let start = Instant::now();
        let party_two_master_key = MasterKey2::set_master_key(
            &party2_cc,
            &kg_ec_key_pair_party2,
            &kg_party_one_second_message
                .ecdh_second_message
                .comm_witness
                .public_share,
            &party_two_paillier,
        );

        println!("{} Client: party2 master_key", TimeFormat(start.elapsed()));
        /*************** END: MASTER KEYS MESSAGE ***************/

        (id, party_two_master_key)
    }

    fn sign(
        client: &Client,
        id: String,
        master_key_2: MasterKey2,
        message: BigInt,
    ) -> party_one::SignatureRecid {
        time_test!();
        let (eph_key_gen_first_message_party_two, eph_comm_witness, eph_ec_key_pair_party2) =
            MasterKey2::sign_first_message();

        let request: party_two::EphKeyGenFirstMsg = eph_key_gen_first_message_party_two;

        let body = serde_json::to_string(&request).unwrap();

        let start = Instant::now();

        let mut response = client
            .post(format!("/ecdsa/sign/{}/first", id))
            .body(body)
            .header(ContentType::JSON)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        println!(
            "{} Network/Server: party1 sign first message",
            TimeFormat(start.elapsed())
        );

        let res_body = response.body_string().unwrap();
        let sign_party_one_first_message: party_one::EphKeyGenFirstMsg =
            serde_json::from_str(&res_body).unwrap();

        let x_pos = BigInt::from(0);
        let y_pos = BigInt::from(21);

        let child_party_two_master_key = master_key_2.get_child(vec![x_pos.clone(), y_pos.clone()]);

        let start = Instant::now();

        let party_two_sign_message = child_party_two_master_key.sign_second_message(
            &eph_ec_key_pair_party2,
            eph_comm_witness.clone(),
            &sign_party_one_first_message,
            &message,
        );

        println!("{} Client: party2 sign second message", TimeFormat(start.elapsed()));

        let request: ecdsa::SignSecondMsgRequest = ecdsa::SignSecondMsgRequest {
            message,
            party_two_sign_message,
            x_pos_child_key: x_pos,
            y_pos_child_key: y_pos,
        };

        let body = serde_json::to_string(&request).unwrap();

        let start = Instant::now();

        let mut response = client
            .post(format!("/ecdsa/sign/{}/second", id))
            .body(body)
            .header(ContentType::JSON)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        println!(
            "{} Network/Server: party1 sign second message",
            TimeFormat(start.elapsed())
        );

        let res_body = response.body_string().unwrap();

        let signature_recid: party_one::SignatureRecid = serde_json::from_str(&res_body).unwrap();

        signature_recid
    }

    #[test]
    fn deposit_key_gen_and_sign() {
        // Passthrough mode
        env::set_var("region", "");
        env::set_var("pool_id", "");
        env::set_var("issuer", "");
        env::set_var("audience", "");

        time_test!();

        let client = Client::new(server::get_server()).expect("valid rocket instance");

        // key gen
        let (id, master_key_2): (String, MasterKey2) = key_gen(&client);

        // prepare sign message
        let tx_b_prepare_sign_msg = PrepareSignTxMessage {
            spending_addr: String::from("bcrt1qjtsfty6z7v5jrj7s9qn4x9gv0np6h8273k3cy9"),
            input_txid: String::from("a60c61baf75c3f01e82a4880310cb4c7bdec95aee1e50ca7293d2233d5d35cab"),
            input_vout: 0,
            address: String::from("bcrt1qz3rcytulyfvkwje88q4a7nvzuj3td9crhlvqnl"),
            amount: 100000000,
            transfer: false
        };
        let body = serde_json::to_string(&tx_b_prepare_sign_msg).unwrap();

        let start = Instant::now();
        let response = client
            .post(format!("/prepare-sign/{}", id))
            .body(body)
            .header(ContentType::JSON)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        println!(
            "{} Network/Server: prepare sign message",
            TimeFormat(start.elapsed())
        );

        let message = BigInt::from(12345);

        let signature: party_one::SignatureRecid = sign(&client, id, master_key_2, message);

        println!(
            "s = (r: {}, s: {}, recid: {})",
            signature.r.to_hex(),
            signature.s.to_hex(),
            signature.recid
        );
    }

    // test ecdsa::sign can be performed only by authorised user
    #[test]
    fn test_auth_token() {
        let client = Client::new(server::get_server()).expect("valid rocket instance");
        // get ID
        let deposit_msg1 = DepositMsg1{proof_key: String::from("proof key")};
        let body = serde_json::to_string(&deposit_msg1).unwrap();
        let mut response = client
            .post("/deposit/init")
            .body(body)
            .header(ContentType::JSON)
            .dispatch();
        let id: String = serde_json::from_str(&response.body_string().unwrap()).unwrap();

        let mut response = client
            .post(format!("/ecdsa/keygen/{}/first",id))
            .header(ContentType::JSON)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let (res, _): (String, party_one::KeyGenFirstMsg) = serde_json::from_str(&response.body_string().unwrap()).unwrap();
        assert_eq!(res, id);

        // use incorrect ID
        let mut response = client
            .post(format!("/ecdsa/keygen/{}/first","invalidID".to_string()))
            .header(ContentType::JSON)
            .dispatch();

        let res = response.body_string().unwrap();
        assert_eq!(res, "User authorisation failed".to_string());
    }
}
