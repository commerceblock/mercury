use super::super::Result;

use crate::error::{DBErrorType, SEError};
use crate::{
    routes::util::check_user_auth,
    storage::db::{
        db_deser, db_get_1, db_get_2, db_get_3, db_get_4, db_insert, db_ser, db_update, Column,
        Table,
    },
    DatabaseR, DatabaseW,
};
use shared_lib::{
    structs::{Protocol, SignSecondMsgRequest},
    util::reverse_hex_str,
};

use bitcoin::{hashes::sha256d, secp256k1::Signature, Transaction};
use curv::{
    arithmetic::traits::Converter,
    cryptographic_primitives::proofs::sigma_dlog::*,
    elliptic::curves::traits::ECPoint,
    {BigInt, FE, GE},
};

use kms::ecdsa::two_party::*;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use rocket_contrib::json::Json;

use std::str::FromStr;
use std::string::ToString;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct HDPos {
    pos: u32,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct Alpha {
    value: BigInt,
}

#[post("/ecdsa/keygen/<id>/first/<protocol>", format = "json")]
pub fn first_message(
    db_read: DatabaseR,
    db_write: DatabaseW,
    id: String,
    protocol: String,
) -> Result<Json<(Uuid, party_one::KeyGenFirstMsg)>> {
    let user_id = Uuid::from_str(&id).unwrap();
    check_user_auth(&db_read, &user_id)?;

    // Create new entry in ecdsa table if key not already in table.
    match db_get_1::<Option<String>>(
        &db_read,
        &user_id,
        Table::Ecdsa,
        vec![Column::Party1MasterKey],
    ) {
        Ok(data) => match data {
            Some(_) => {
                return Err(SEError::Generic(format!(
                    "Key Generation already completed for ID {}",
                    user_id
                )))
            }
            None => {} // Key exists but key gen not complete. Carry on without writing user_id.
        },
        Err(e) => match e {
            SEError::DBError(DBErrorType::NoDataForID, _) =>
            // If no item has ID, create new item
            {
                let _ = db_insert(&db_write, &user_id, Table::Ecdsa)?;
            }
            _ => return Err(e),
        },
    };

    // Generate shared key
    let (key_gen_first_msg, comm_witness, ec_key_pair) = if protocol == String::from("deposit") {
        MasterKey1::key_gen_first_message()
    } else {
        let s2: FE = db_deser(db_get_1(
            &db_read,
            &user_id,
            Table::UserSession,
            vec![Column::S2],
        )?)?;
        MasterKey1::key_gen_first_message_predefined(s2)
    };

    db_update(
        &db_write,
        &user_id,
        Table::Ecdsa,
        vec![
            Column::POS,
            Column::KeyGenFirstMsg,
            Column::CommWitness,
            Column::EcKeyPair,
        ],
        vec![
            &db_ser(HDPos { pos: 0u32 })?,
            &db_ser(key_gen_first_msg.to_owned())?,
            &db_ser(comm_witness)?,
            &db_ser(ec_key_pair)?,
        ],
    )?;

    Ok(Json((user_id, key_gen_first_msg)))
}

#[post("/ecdsa/keygen/<id>/second", format = "json", data = "<dlog_proof>")]
pub fn second_message(
    db_read: DatabaseR,
    db_write: DatabaseW,
    id: String,
    dlog_proof: Json<DLogProof>,
) -> Result<Json<party1::KeyGenParty1Message2>> {
    let user_id = Uuid::from_str(&id).unwrap();

    let party2_public: GE = dlog_proof.0.pk.clone();

    let (comm_witness_str, ec_key_pair_str) = db_get_2::<String, String>(
        &db_read,
        &user_id,
        Table::Ecdsa,
        vec![Column::CommWitness, Column::EcKeyPair],
    )?;
    let comm_witness: party_one::CommWitness = db_deser(comm_witness_str)?;
    let ec_key_pair: party_one::EcKeyPair = db_deser(ec_key_pair_str)?;

    let (kg_party_one_second_message, paillier_key_pair, party_one_private) =
        MasterKey1::key_gen_second_message(comm_witness, &ec_key_pair, &dlog_proof.0);

    db_update(
        &db_write,
        &user_id,
        Table::Ecdsa,
        vec![
            Column::Party2Public,
            Column::PaillierKeyPair,
            Column::Party1Private,
        ],
        vec![
            &db_ser(party2_public)?,
            &db_ser(paillier_key_pair)?,
            &db_ser(party_one_private)?,
        ],
    )?;

    Ok(Json(kg_party_one_second_message))
}

#[post(
    "/ecdsa/keygen/<id>/third",
    format = "json",
    data = "<party_two_pdl_first_message>"
)]
pub fn third_message(
    db_read: DatabaseR,
    db_write: DatabaseW,
    id: String,
    party_two_pdl_first_message: Json<party_two::PDLFirstMessage>,
) -> Result<Json<party_one::PDLFirstMessage>> {
    let user_id = Uuid::from_str(&id).unwrap();

    let party_one_private: party_one::Party1Private = db_deser(db_get_1(
        &db_read,
        &user_id,
        Table::Ecdsa,
        vec![Column::Party1Private],
    )?)?;

    let (party_one_third_message, party_one_pdl_decommit, alpha) =
        MasterKey1::key_gen_third_message(&party_two_pdl_first_message.0, &party_one_private);

    db_update(
        &db_write,
        &user_id,
        Table::Ecdsa,
        vec![
            Column::PDLDecommit,
            Column::Alpha,
            Column::Party2PDLFirstMsg,
        ],
        vec![
            &db_ser(party_one_pdl_decommit)?,
            &db_ser(Alpha { value: alpha })?,
            &db_ser(party_two_pdl_first_message.0)?,
        ],
    )?;

    Ok(Json(party_one_third_message))
}

#[post(
    "/ecdsa/keygen/<id>/fourth",
    format = "json",
    data = "<party_two_pdl_second_message>"
)]
pub fn fourth_message(
    db_read: DatabaseR,
    db_write: DatabaseW,
    id: String,
    party_two_pdl_second_message: Json<party_two::PDLSecondMessage>,
) -> Result<Json<party_one::PDLSecondMessage>> {
    let user_id = Uuid::from_str(&id).unwrap();

    let (
        party_one_private_str,
        party_one_pdl_decommit_str,
        party_two_pdl_first_message_str,
        alpha_str,
    ) = db_get_4::<String, String, String, String>(
        &db_read,
        &user_id,
        Table::Ecdsa,
        vec![
            Column::Party1Private,
            Column::PDLDecommit,
            Column::Party2PDLFirstMsg,
            Column::Alpha,
        ],
    )?;

    let party_one_private: party_one::Party1Private = db_deser(party_one_private_str)?;
    let party_one_pdl_decommit: party_one::PDLdecommit = db_deser(party_one_pdl_decommit_str)?;
    let party_two_pdl_first_message: party_two::PDLFirstMessage =
        db_deser(party_two_pdl_first_message_str)?;
    let alpha: Alpha = db_deser(alpha_str)?;

    let res = MasterKey1::key_gen_fourth_message(
        &party_two_pdl_first_message,
        &party_two_pdl_second_message.0,
        party_one_private,
        party_one_pdl_decommit,
        alpha.value,
    );

    assert!(res.is_ok());

    master_key(db_read, db_write, id)?;

    Ok(Json(res.unwrap()))
}

pub fn master_key(db_read: DatabaseR, db_write: DatabaseW, id: String) -> Result<()> {
    let user_id = Uuid::from_str(&id).unwrap();

    let (party2_public_str, paillier_key_pair_str, party_one_private_str, comm_witness_str) =
        db_get_4::<String, String, String, String>(
            &db_read,
            &user_id,
            Table::Ecdsa,
            vec![
                Column::Party2Public,
                Column::PaillierKeyPair,
                Column::Party1Private,
                Column::CommWitness,
            ],
        )?;

    let party2_public: GE = db_deser(party2_public_str)?;
    let paillier_key_pair: party_one::PaillierKeyPair = db_deser(paillier_key_pair_str)?;
    let party_one_private: party_one::Party1Private = db_deser(party_one_private_str)?;
    let comm_witness: party_one::CommWitness = db_deser(comm_witness_str)?;

    let master_key = MasterKey1::set_master_key(
        &BigInt::from(0),
        party_one_private,
        &comm_witness.public_share,
        &party2_public,
        paillier_key_pair,
    );

    db_update(
        &db_write,
        &user_id,
        Table::Ecdsa,
        vec![Column::Party1MasterKey],
        vec![&db_ser(master_key)?],
    )
}

#[post(
    "/ecdsa/sign/<id>/first",
    format = "json",
    data = "<eph_key_gen_first_message_party_two>"
)]
pub fn sign_first(
    db_read: DatabaseR,
    db_write: DatabaseW,
    id: String,
    eph_key_gen_first_message_party_two: Json<party_two::EphKeyGenFirstMsg>,
) -> Result<Json<party_one::EphKeyGenFirstMsg>> {
    let user_id = Uuid::from_str(&id).unwrap();
    check_user_auth(&db_read, &user_id)?;

    let (sign_party_one_first_message, eph_ec_key_pair_party1) = MasterKey1::sign_first_message();

    db_update(
        &db_write,
        &user_id,
        Table::Ecdsa,
        vec![Column::EphKeyGenFirstMsg, Column::EphEcKeyPair],
        vec![
            &db_ser(eph_key_gen_first_message_party_two.0)?,
            &db_ser(eph_ec_key_pair_party1)?,
        ],
    )?;

    Ok(Json(sign_party_one_first_message))
}

#[post("/ecdsa/sign/<id>/second", format = "json", data = "<request>")]
pub fn sign_second(
    db_read: DatabaseR,
    db_write: DatabaseW,
    id: String,
    request: Json<SignSecondMsgRequest>,
) -> Result<Json<Vec<Vec<u8>>>> {
    let user_id = Uuid::from_str(&id).unwrap();
    check_user_auth(&db_read, &user_id)?;

    // Get validated sig hash for this user
    let sig_hash: sha256d::Hash = db_deser(db_get_1(
        &db_read,
        &user_id,
        Table::UserSession,
        vec![Column::SigHash],
    )?)?;

    // Check sig hash is of corrcet length. Leading 0s are lost during BigInt conversion so add them
    // back here if necessary.
    let mut message_hex = request.message.to_hex();
    if message_hex.len() < 64 {
        let num_zeros = 64 - message_hex.len();
        let temp = message_hex.clone();
        message_hex = format!("{:0width$}", 0, width = num_zeros);
        message_hex.push_str(&temp);
    }

    // Check sighash matches message to be signed
    let message_sig_hash = reverse_hex_str(message_hex.clone())?;
    if sig_hash.to_string() != message_sig_hash {
        return Err(SEError::SigningError(format!(
            "Message to be signed does not match verified sig hash. \n{}, {}",
            sig_hash.to_string(),
            message_sig_hash
        )));
    }

    // Get 2P-Ecdsa data
    let (shared_key_str, eph_ec_key_pair_party1_str, eph_key_gen_first_message_party_two_str) =
        db_get_3::<String, String, String>(
            &db_read,
            &user_id,
            Table::Ecdsa,
            vec![
                Column::Party1MasterKey,
                Column::EphEcKeyPair,
                Column::EphKeyGenFirstMsg,
            ],
        )?;

    let shared_key: MasterKey1 = db_deser(shared_key_str)?;
    let eph_ec_key_pair_party1: party_one::EphEcKeyPair = db_deser(eph_ec_key_pair_party1_str)?;
    let eph_key_gen_first_message_party_two: party_two::EphKeyGenFirstMsg =
        db_deser(eph_key_gen_first_message_party_two_str)?;

    let signature;
    match shared_key.sign_second_message(
        &request.party_two_sign_message,
        &eph_key_gen_first_message_party_two,
        &eph_ec_key_pair_party1,
        &request.message,
    ) {
        Ok(sig) => signature = sig,
        Err(_) => {
            return Err(SEError::SigningError(String::from(
                "Signature validation failed.",
            )))
        }
    };

    // Get transaction which is being signed.
    let mut tx: Transaction = match request.protocol {
        Protocol::Withdraw => db_deser(db_get_1(
            &db_read,
            &user_id,
            Table::UserSession,
            vec![Column::TxWithdraw],
        )?)?,
        _ => {
            // despoit() and transfer() both sign tx_backup
            db_deser(db_get_1(
                &db_read,
                &user_id,
                Table::UserSession,
                vec![Column::TxBackup],
            )?)?
        }
    };

    // Make signature witness
    let mut r_vec = BigInt::to_vec(&signature.r);
    if r_vec.len() != 32 {
        // Check corrcet length of conversion to Signature
        let mut temp = vec![0; 32 - r_vec.len()];
        temp.extend(r_vec);
        r_vec = temp;
    }
    let mut s_vec = BigInt::to_vec(&signature.s);
    if s_vec.len() != 32 {
        // Check corrcet length of conversion to Signature
        let mut temp = vec![0; 32 - s_vec.len()];
        temp.extend(s_vec);
        s_vec = temp;
    }
    let mut v = r_vec;
    v.extend(s_vec);
    let mut sig_vec = Signature::from_compact(&v[..])?.serialize_der().to_vec();
    sig_vec.push(01);
    let pk_vec = shared_key.public.q.get_element().serialize().to_vec();
    let mut witness = vec![sig_vec, pk_vec];

    // Add signature to tx
    tx.input[0].witness = witness.clone();

    match request.protocol {
        Protocol::Withdraw => {
            // Store signed withdraw tx in UserSession DB object
            db_update(
                &db_write,
                &user_id,
                Table::UserSession,
                vec![Column::TxWithdraw],
                vec![&db_ser(tx)?],
            )?;

            info!("WITHDRAW: Tx signed and stored. User ID: {}", user_id);
            // Do not return withdraw tx witness until /withdraw/confirm is complete
            witness = vec![];
        }
        _ => {
            // Store signed backup tx in UserSession DB object
            db_update(
                &db_write,
                &user_id,
                Table::UserSession,
                vec![Column::TxBackup],
                vec![&db_ser(tx)?],
            )?;
            info!(
                "DEPOSIT/TRANSFER: Backup Tx signed and stored. User: {}",
                user_id
            );
        }
    };

    Ok(Json(witness))
}
