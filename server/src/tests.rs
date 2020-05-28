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
    fn test_auth_token() {
        let client = Client::new(server::get_server()).expect("valid rocket instance");
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
    fn test_api_errs() {
        let client = Client::new(server::get_server()).expect("valid rocket instance");

        // get_statechin
        let mut response = client
            .post(format!("/api/statechain/{}","invalidID".to_string()))
            .header(ContentType::JSON)
            .dispatch();

        let res = response.body_string().unwrap();
        assert_eq!(res, "DB Error: No data for such identifier. (value: invalidID)".to_string());

        // get_smt_proof
        // None root
        let smt_proof_msg = SmtProofMsgAPI {
            root: Root {id:0, value: None},
            funding_txid: String::from("c1562f7f15d6b8a51ea2e7035b9cdb8c6c0c41fecb62d459a3a6bf738ff0db0e")
        };
        let body = serde_json::to_string(&smt_proof_msg).unwrap();
        let mut response = client
            .post(format!("/api/proof"))
            .body(body)
            .header(ContentType::JSON)
            .dispatch();

        let res = response.body_string().unwrap();
        assert_eq!(res, format!("DB Error: No data for such identifier. (value: Root id: {})",smt_proof_msg.root.id));

        // invalid root for tree
        // first grab current root id
        let mut response = client
        .post(format!("/api/root"))
            .header(ContentType::JSON)
            .dispatch();
        let res = response.body_string().unwrap();
        let current_root: Root = serde_json::from_str(&res).unwrap();

        let smt_proof_msg = SmtProofMsgAPI {
            root: Root {id: current_root.id+1, value: Some([1;32])},
            funding_txid: String::from("c1562f7f15d6b8a51ea2e7035b9cdb8c6c0c41fecb62d459a3a6bf738ff0db0e")
        };
        let body = serde_json::to_string(&smt_proof_msg).unwrap();
        let mut response = client
            .post(format!("/api/proof"))
            .body(body)
            .header(ContentType::JSON)
            .dispatch();

        let res = response.body_string().unwrap();
        assert_eq!(res, format!("DB Error: No data for such identifier. (value: Root id: {})",smt_proof_msg.root.id));
    }

    #[test]
    fn test_get_state_entity_fees() {
        let client = Client::new(server::get_server()).expect("valid rocket instance");

        let mut response = client
            .post("/api/fee")
            .header(ContentType::JSON)
            .dispatch();

        let resp: StateEntityFeeInfoAPI = serde_json::from_str(&response.body_string().unwrap()).unwrap();
        assert_eq!(resp.address, "bcrt1qjjwk2rk7nuxt6c79tsxthf5rpnky0sdhjr493x".to_string());
        assert_eq!(resp.deposit, 100);
        assert_eq!(resp.withdraw, 100);

    }

}
