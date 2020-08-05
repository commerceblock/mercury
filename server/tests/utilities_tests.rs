use shared_lib::Root;
mod tools;
use tools::{spawn_test_server, test_server_post, test_server_get};

use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use rocket::http::ContentType;
use shared_lib::structs::{
    DepositMsg1, KeyGenMsg1, Protocol, SmtProofMsgAPI, StateEntityFeeInfoAPI,
};
use serde_json;
use uuid::Uuid;

#[test]
fn test_auth_token() {
    let client = spawn_test_server();
    // get ID
    let deposit_msg1 = DepositMsg1 {
        auth: String::from("auth"),
        proof_key: String::from("proof key"),
    };
    let id = test_server_post::<DepositMsg1>(&client, "/deposit/init", &deposit_msg1);
    let id: Uuid = serde_json::from_str(&id).unwrap();

    let mut key_gen_msg1 = KeyGenMsg1 {
        shared_key_id: id.clone(),
        protocol: Protocol::Deposit,
    };
    let res: String = test_server_post(&client, "/ecdsa/keygen/first", &key_gen_msg1);
    assert_eq!(serde_json::from_str::<(Uuid, party_one::KeyGenFirstMsg)>(&res).unwrap().0, id);

    // use incorrect ID
    key_gen_msg1.shared_key_id = Uuid::new_v4();
    let res = test_server_post(&client, "/ecdsa/keygen/first", &key_gen_msg1);
    assert_eq!(
        res,
        "Authentication Error: User authorisation failed".to_string()
    );
}

#[test]
fn test_err_get_statechain() {
    let client = spawn_test_server();

    // get_statechain invalid id
    let invalid_id = Uuid::new_v4();
    let res = test_server_get(&client, &format!("/info/statechain/{}", invalid_id));

    assert_eq!(
        res,
        format!("DB Error: No data for identifier. (id: {})", invalid_id)
    );

    // get_statechain no ID
    let res = test_server_get(&client, &format!("/info/statechain/"));
    assert_eq!(res, "Unknown route \'/info/statechain/\'.".to_string());
}

#[test]
fn test_err_get_smt_proof() {
    let client = spawn_test_server();

    // None root
    let smt_proof_msg = SmtProofMsgAPI {
        root: Root::from(Some(0), None, &None).unwrap(),
        funding_txid: String::from(
            "c1562f7f15d6b8a51ea2e7035b9cdb8c6c0c41fecb62d459a3a6bf738ff0db0e",
        ),
    };

    let res = test_server_post(&client, "/info/proof", &smt_proof_msg);
    assert_eq!(
        res,
        format!(
            "DB Error: No data for identifier. (id: Root id: {})",
            smt_proof_msg.root.id().unwrap()
        )
    );

    // invalid root for tree
    // first push a random root to tree

    //update_root(db, mc);
    let mut response = client // first grab current root id
        .get(format!("/info/root"))
        .header(ContentType::JSON)
        .dispatch();
    let res = response.body_string().unwrap();
    let current_root: Option<Root> =
        serde_json::from_str(&res).expect(&format!("Error from body string {}", &res));

    let id = match current_root {
        Some(r) => r.id().unwrap(),
        None => 0,
    };

    let proof_msg_id = Some(id + 1);

    let smt_proof_msg = SmtProofMsgAPI {
        root: Root::from(proof_msg_id, Some([1; 32]), &None).unwrap(), // alter ID to become invalid
        funding_txid: String::from(
            "c1562f7f15d6b8a51ea2e7035b9cdb8c6c0c41fecb62d459a3a6bf738ff0db0e",
        ),
    };
    let res = test_server_post(&client, "/info/proof", &smt_proof_msg);
    assert_eq!(
        res,
        format!(
            "DB Error: No data for identifier. (id: Root id: {})",
            smt_proof_msg.root.id().unwrap()
        )
    );

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
fn test_err_get_transfer_batch_status() {
    let client = spawn_test_server();

    // get_transfer_batch_status invalid id
    let invalid_id = Uuid::new_v4();
    let res = test_server_get(&client, &format!("/info/transfer-batch/{}", invalid_id));
    assert_eq!(
        res,
        format!("DB Error: No data for identifier. (id: {})", invalid_id)
    );

    // get_transfer_batch_status no ID
    let res = test_server_get(&client, &format!("/info/transfer-batch/"));
    assert_eq!(res, "Unknown route \'/info/transfer-batch/\'.".to_string());
}

#[test]
fn test_get_state_entity_fees() {
    let client = spawn_test_server();

    let res = test_server_get(&client,"/info/fee");
    let fee_info: StateEntityFeeInfoAPI =
        serde_json::from_str(&res).unwrap();
    assert_eq!(
        fee_info.address,
        "bcrt1qjjwk2rk7nuxt6c79tsxthf5rpnky0sdhjr493x".to_string()
    );
    assert_eq!(fee_info.deposit, 300);
    assert_eq!(fee_info.withdraw, 300);
}
