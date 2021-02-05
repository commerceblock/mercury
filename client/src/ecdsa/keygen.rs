use curv::{BigInt, FE};
use kms::ecdsa::two_party::*;

use super::super::utilities::requests;
use super::super::ClientShim;
use super::super::Result;
use crate::wallet::shared_key::SharedKey;
use shared_lib::structs::{KeyGenMsg1, KeyGenMsg2, Protocol, KeyGenReply1, KeyGenReply2};
use uuid::Uuid;

const KG_PATH_PRE: &str = "ecdsa/keygen";

pub fn get_master_key(
    shared_key_id: &Uuid,
    client_shim: &ClientShim,
    secret_key: &FE,
    value: &u64,
    protocol: Protocol,
) -> Result<SharedKey> {
    let key_gen_reply_1: KeyGenReply1  = requests::postb(
        client_shim,
        &format!("{}/first", KG_PATH_PRE),
        KeyGenMsg1 {
            shared_key_id: *shared_key_id,
            protocol,
        },
    )?;

    let (kg_party_two_first_message, kg_ec_key_pair_party2) =
        MasterKey2::key_gen_first_message_predefined(secret_key);

    let key_gen_msg2 = KeyGenMsg2 {
        shared_key_id: *shared_key_id,
        dlog_proof: kg_party_two_first_message.d_log_proof,
    };

    let kg_party_one_second_message: KeyGenReply2 = requests::postb(
        client_shim,
        &format!("{}/second", KG_PATH_PRE),
        key_gen_msg2,
    )
    .unwrap();

    let key_gen_second_message = MasterKey2::key_gen_second_message(
        &key_gen_reply_1.msg,
        &kg_party_one_second_message.msg,
    );

    let (_, party_two_paillier) = key_gen_second_message.unwrap();

    let master_key = MasterKey2::set_master_key(
        &BigInt::from(0),
        &kg_ec_key_pair_party2,
        &kg_party_one_second_message.msg
            .ecdh_second_message
            .comm_witness
            .public_share,
        &party_two_paillier,
    );

    Ok(SharedKey {
        id: key_gen_reply_1.user_id,
        share: master_key,
        value: value.to_owned(),
        statechain_id: None,
        tx_backup_psm: None,
        proof_key: None,
        smt_proof: None,
        unspent: true,
        funding_txid: String::default(),
    })
}
