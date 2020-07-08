use curv::{FE,BigInt};
use kms::ecdsa::two_party::*;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;

use crate::wallet::shared_key::SharedKey;
use super::super::utilities::requests;
use super::super::ClientShim;
use super::super::Result;
use uuid::Uuid;


const KG_PATH_PRE: &str = "ecdsa/keygen";

pub fn get_master_key(id: &Uuid, client_shim: &ClientShim, secret_key: &FE, value: &u64, is_transfer: bool) -> Result<SharedKey> {
    let (id, kg_party_one_first_message): (Uuid, party_one::KeyGenFirstMsg)
        = if is_transfer {
            requests::post(client_shim, &format!("{}/{}/first/transfer", KG_PATH_PRE, id))?
        } else {
            requests::post(client_shim, &format!("{}/{}/first/deposit", KG_PATH_PRE, id))?
        };

    let (kg_party_two_first_message, kg_ec_key_pair_party2) = MasterKey2::key_gen_first_message_predefined(secret_key);

    let body = &kg_party_two_first_message.d_log_proof;

    let kg_party_one_second_message: party1::KeyGenParty1Message2 =
        requests::postb(client_shim, &format!("{}/{}/second", KG_PATH_PRE, id), body).unwrap();

    let key_gen_second_message = MasterKey2::key_gen_second_message(
        &kg_party_one_first_message,
        &kg_party_one_second_message,
    );

    let (party_two_second_message, party_two_paillier, party_two_pdl_chal) =
        key_gen_second_message.unwrap();

    let body = &party_two_second_message.pdl_first_message;

    let party_one_third_message: party_one::PDLFirstMessage =
        requests::postb(client_shim, &format!("{}/{}/third", KG_PATH_PRE, id), body).unwrap();

    let pdl_decom_party2 = MasterKey2::key_gen_third_message(&party_two_pdl_chal);

    let party_2_pdl_second_message = pdl_decom_party2;

    let body = &party_2_pdl_second_message;

    let party_one_pdl_second_message: party_one::PDLSecondMessage =
        requests::postb(client_shim, &format!("{}/{}/fourth", KG_PATH_PRE, id), body).unwrap();

    MasterKey2::key_gen_fourth_message(
        &party_two_pdl_chal,
        &party_one_third_message,
        &party_one_pdl_second_message,
    )
    .expect("pdl error party1");

    let master_key = MasterKey2::set_master_key(
        &BigInt::from(0),
        &kg_ec_key_pair_party2,
        &kg_party_one_second_message
            .ecdh_second_message
            .comm_witness
            .public_share,
        &party_two_paillier,
    );

    Ok(SharedKey {
        id,
        share: master_key,
        value: value.to_owned(),
        state_chain_id: None,
        tx_backup_psm: None,
        proof_key: None,
        smt_proof: None,
        unspent: true,
    })
}
