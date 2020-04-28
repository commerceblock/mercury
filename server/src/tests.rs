// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//
#[cfg(test)]
mod tests {

    use super::super::routes::ecdsa;
    use super::super::server;
    use rocket;
    use rocket::http::ContentType;
    use rocket::http::Status;
    use rocket::local::Client;
    use serde_json;
    use std::env;
    use std::time::Instant;
    use floating_duration::TimeFormat;

    use curv::arithmetic::traits::Converter;
    use curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::*;
    use curv::BigInt;
    use kms::chain_code::two_party as chain_code;
    use kms::ecdsa::two_party::*;
    use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;

    fn key_gen(client: &Client) -> (String, MasterKey2) {
        time_test!();

        /*************** START: FIRST MESSAGE ***************/
        let start = Instant::now();

        // get ID
        let mut response = client
            .post("/init")
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
    fn key_gen_and_sign() {
        // Passthrough mode
        env::set_var("region", "");
        env::set_var("pool_id", "");
        env::set_var("issuer", "");
        env::set_var("audience", "");

        time_test!();

        let client = Client::new(server::get_server()).expect("valid rocket instance");

        let (id, master_key_2): (String, MasterKey2) = key_gen(&client);

        let message = BigInt::from(12345);

        let signature: party_one::SignatureRecid = sign(&client, id, master_key_2, message);

        println!(
            "s = (r: {}, s: {}, recid: {})",
            signature.r.to_hex(),
            signature.s.to_hex(),
            signature.recid
        );
    }

    // #[test]
    // fn test_db() {
    //     let client = Client::new(server::get_server()).expect("valid rocket instance");
    //
    //     let mut response = client
    //         .post("/tester")
    //         .header(ContentType::JSON)
    //         .dispatch();
    //
    //     let output: String = serde_json::from_str(&response.body_string().unwrap()).unwrap();
    //     println!("response: {}",output);
    // }

    // test ecdsa::sign can be performed only by authorised user
    #[test]
    fn test_deposit_auth_token() {
        let client = Client::new(server::get_server()).expect("valid rocket instance");

        let mut response = client
            .post("/init")
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

        let mut response = client
            .post(format!("/ecdsa/keygen/{}/first","invalidID".to_string()))
            .header(ContentType::JSON)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let (res, _): (String, party_one::KeyGenFirstMsg) = serde_json::from_str(&response.body_string().unwrap()).unwrap();
        assert_eq!(res, "Err".to_string());

    }
}
