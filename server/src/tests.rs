#[cfg(test)]
mod tests {
    extern crate shared_lib;
    use super::super::server;
    use shared_lib::Root;
    use shared_lib::structs::{DepositMsg1, SmtProofMsgAPI, StateEntityFeeInfoAPI}
    ;
    use rocket::http::{ContentType,Status};
    use rocket::local::Client;
    use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;

    use serde_json;

    // test ecdsa::sign can be performed only by authorised user
    #[test]
    #[serial]
    fn test_auth_token() {
        let client = Client::new(server::get_server().unwrap()).expect("valid rocket instance");
        // get ID
        let deposit_msg1 = DepositMsg1{
            auth: String::from("auth"),
            proof_key: String::from("proof key")
        };
        let body = serde_json::to_string(&deposit_msg1).unwrap();
        let mut response = client
            .post("/deposit/init")
            .body(body)
            .header(ContentType::JSON)
            .dispatch();
        let id: String = serde_json::from_str(&response.body_string().unwrap()).unwrap();

        let mut response = client
            .post(format!("/ecdsa/keygen/{}/first/deposit",id))
            .header(ContentType::JSON)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let (res, _): (String, party_one::KeyGenFirstMsg) = serde_json::from_str(&response.body_string().unwrap()).unwrap();
        assert_eq!(res, id);

        // use incorrect ID
        let mut response = client
            .post(format!("/ecdsa/keygen/{}/first/deposit","invalidID".to_string()))
            .header(ContentType::JSON)
            .dispatch();

        let res = response.body_string().unwrap();
        assert_eq!(res, "Authentication Error: User authorisation failed".to_string());
    }

    #[test]
    #[serial]
    fn test_err_get_statechain() {
        let client = Client::new(server::get_server().unwrap()).expect("valid rocket instance");

        // get_statechain invalid id
        let mut response = client
            .post(format!("/info/statechain/{}","invalidID".to_string()))
            .header(ContentType::JSON)
            .dispatch();
        let res = response.body_string().unwrap();
        assert_eq!(res, "DB Error: No data for such identifier. (value: invalidID)".to_string());

        // get_statechain no ID
        let mut response = client
            .post(format!("/info/statechain/"))
            .header(ContentType::JSON)
            .dispatch();
        let res = response.body_string().unwrap();
        assert_eq!(res, "Unknown route \'/info/statechain/\'.".to_string());
    }

    #[test]
    #[serial]
    fn test_err_get_smt_proof() {
        let client = Client::new(server::get_server().unwrap()).expect("valid rocket instance");

        // None root
        let smt_proof_msg = SmtProofMsgAPI {
            root: Root::from(Some(0), None, &None).unwrap(),
            funding_txid: String::from("c1562f7f15d6b8a51ea2e7035b9cdb8c6c0c41fecb62d459a3a6bf738ff0db0e")
        };
        let body = serde_json::to_string(&smt_proof_msg).unwrap();
        let mut response = client
            .post(format!("/info/proof"))
            .body(body)
            .header(ContentType::JSON)
            .dispatch();
        let res = response.body_string().unwrap();
        assert_eq!(res, format!("DB Error: No data for such identifier. (value: Root id: {:?})",smt_proof_msg.root.id()));

        // invalid root for tree
        // first push a random root to tree

        //update_root(db, mc);


        let mut response = client   // first grab current root id
        .post(format!("/info/root"))
            .header(ContentType::JSON)
            .dispatch();
        let res = response.body_string().unwrap();
        let current_root: Option<Root> = serde_json::from_str(&res).expect(&format!("Error from body string {}",&res));
            
        let id = match current_root{
            Some(r) => r.id().unwrap(),
            None => 0
        };

        let proof_msg_id = Some(id+1);

        let smt_proof_msg = SmtProofMsgAPI {
            root: Root::from(proof_msg_id, Some([1;32]), &None).unwrap(),// alter ID to become invalid
            funding_txid: String::from("c1562f7f15d6b8a51ea2e7035b9cdb8c6c0c41fecb62d459a3a6bf738ff0db0e")
        };
        let body = serde_json::to_string(&smt_proof_msg).unwrap();
        let mut response = client
            .post(format!("/info/proof"))
            .body(body)
            .header(ContentType::JSON)
            .dispatch();
        let res = response.body_string().unwrap();
        assert_eq!(res, format!("DB Error: No data for such identifier. (value: Root id: {:?})",smt_proof_msg.root.id()));

        // Invalid data sent in body - should be of type SmtProofMsgAPI
        let body = String::from("Body String");
        let mut response = client
            .post(format!("/info/proof"))
            .body(body)
            .header(ContentType::JSON)
            .dispatch();
        let res = response.body_string().unwrap();
        assert_eq!(res, format!("Bad request"));
    }

    #[test]
    #[serial]
    fn test_err_get_transfer_batch_status() {
        let client = Client::new(server::get_server().unwrap()).expect("valid rocket instance");

        // get_transfer_batch_status invalid id
        let mut response = client
            .post(format!("/info/transfer-batch/{}","invalidID".to_string()))
            .header(ContentType::JSON)
            .dispatch();
        let res = response.body_string().unwrap();
        assert_eq!(res, "DB Error: No data for such identifier. (value: invalidID)".to_string());

        // get_transfer_batch_status no ID
        let mut response = client
            .post(format!("/info/transfer-batch/"))
            .header(ContentType::JSON)
            .dispatch();
        let res = response.body_string().unwrap();
        assert_eq!(res, "Unknown route \'/info/transfer-batch/\'.".to_string());
    }

    #[test]
    #[serial]
    fn test_get_state_entity_fees() {
        let client = Client::new(server::get_server().unwrap()).expect("valid rocket instance");

        let mut response = client
            .post("/info/fee")
            .header(ContentType::JSON)
            .dispatch();

        let resp: StateEntityFeeInfoAPI = serde_json::from_str(&response.body_string().unwrap()).unwrap();
        assert_eq!(resp.address, "bcrt1qjjwk2rk7nuxt6c79tsxthf5rpnky0sdhjr493x".to_string());
        assert_eq!(resp.deposit, 300);
        assert_eq!(resp.withdraw, 300);
    }

}
