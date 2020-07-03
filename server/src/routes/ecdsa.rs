use super::super::{{Result,Config},
    auth::jwt::Claims,
    storage::db};

use crate::error::{DBErrorType::NoDataForID, SEError};
use crate::{storage::db_postgres::{db_ecdsa_update, db_ecdsa_new, db_ecdsa_get, db_ecdsa_get_complete}, routes::util::{check_user_auth, StateEntityStruct, UserSession}, DataBase};
use shared_lib::{
    structs::{Protocol, SignSecondMsgRequest},
    util::reverse_hex_str,
};

use bitcoin::{secp256k1::Signature, Transaction};
use curv::{{BigInt, GE},
    cryptographic_primitives::proofs::sigma_dlog::*,
    elliptic::curves::traits::ECPoint,
    arithmetic::traits::Converter};

use kms::ecdsa::two_party::*;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use rocket::State;
use rocket_contrib::json::Json;

use std::string::ToString;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct HDPos {
    pos: u32,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct Alpha {
    value: BigInt,
}

#[derive(Debug)]
pub enum EcdsaStruct {
    KeyGenFirstMsg,
    CommWitness,
    EcKeyPair,
    PaillierKeyPair,
    Party1Private,
    Party2Public,

    PDLProver,
    PDLDecommit,
    Alpha,
    Party2PDLFirstMsg,

    CCKeyGenFirstMsg,
    CCCommWitness,
    CCEcKeyPair,
    CC,

    Party1MasterKey,

    EphEcKeyPair,
    EphKeyGenFirstMsg,

    RotateCommitMessage1M,
    RotateCommitMessage1R,
    RotateRandom1,
    RotateFirstMsg,
    RotatePrivateNew,
    RotatePdlDecom,
    RotateParty2First,
    RotateParty1Second,

    POS
}

impl db::MPCStruct for EcdsaStruct {
    fn to_string(&self) -> String {
        format!("{:?}", self)
    }
}

#[post("/ecdsa/keygen/<id>/first/<protocol>", format = "json")]
pub fn first_message(
    state: State<Config>,
    claim: Claims,
    conn: DataBase,
    id: String,
    protocol: String,
) -> Result<Json<(String, party_one::KeyGenFirstMsg)>> {
    let user_id = Uuid::from_str(&id).unwrap();
    // Check authorisation id is in DB (and check password?)
    let user_session = check_user_auth(&state, &claim, &id)?;

    // Create new entry in ecdsa table if key not already in table.
    match db_ecdsa_get_complete(&conn, user_id) {
        Ok(is_complete) => match is_complete {
            true =>  { return Err(SEError::Generic(format!("Key Generation already completed for ID {}",user_id)))},
            false => {} // Key exists but key gen not complete. Carry on without writing user_id.
        },
        Err(_) => {
            db_ecdsa_new(&conn, &user_id)?;
        }
    }

    // Generate shared key
    let (key_gen_first_msg, comm_witness, ec_key_pair) = if protocol == String::from("deposit") {
        MasterKey1::key_gen_first_message()
    } else {
        MasterKey1::key_gen_first_message_predefined(user_session.s2.unwrap())
    };

    db_ecdsa_update(&conn, user_id, &HDPos{pos:0u32}, &EcdsaStruct::POS)?;
    db_ecdsa_update(&conn, user_id, &key_gen_first_msg, &EcdsaStruct::KeyGenFirstMsg)?;
    db_ecdsa_update(&conn, user_id, &comm_witness, &EcdsaStruct::CommWitness)?;
    db_ecdsa_update(&conn, user_id, &ec_key_pair, &EcdsaStruct::EcKeyPair)?;

    Ok(Json((id, key_gen_first_msg)))
}

#[post("/ecdsa/keygen/<id>/second", format = "json", data = "<dlog_proof>")]
pub fn second_message(
    conn: DataBase,
    id: String,
    dlog_proof: Json<DLogProof>,
) -> Result<Json<party1::KeyGenParty1Message2>> {
    let user_id = Uuid::from_str(&id).unwrap();

    let party2_public: GE = dlog_proof.0.pk.clone();
    db_ecdsa_update(&conn, user_id, &party2_public, &EcdsaStruct::Party2Public)?;

    let comm_witness: party_one::CommWitness =
        db_ecdsa_get(&conn, user_id, &EcdsaStruct::CommWitness)?;

    let ec_key_pair: party_one::EcKeyPair =
        db_ecdsa_get(&conn, user_id, &EcdsaStruct::EcKeyPair)?;

    let (kg_party_one_second_message, paillier_key_pair, party_one_private) =
        MasterKey1::key_gen_second_message(comm_witness, &ec_key_pair, &dlog_proof.0);

    db_ecdsa_update(&conn, user_id, &paillier_key_pair, &EcdsaStruct::PaillierKeyPair)?;
    db_ecdsa_update(&conn, user_id, &party_one_private, &EcdsaStruct::Party1Private)?;

    Ok(Json(kg_party_one_second_message))
}

#[post(
    "/ecdsa/keygen/<id>/third",
    format = "json",
    data = "<party_2_pdl_first_message>"
)]
pub fn third_message(
    conn: DataBase,
    id: String,
    party_2_pdl_first_message: Json<party_two::PDLFirstMessage>,
) -> Result<Json<party_one::PDLFirstMessage>> {
    let user_id = Uuid::from_str(&id).unwrap();

    let party_one_private: party_one::Party1Private =
        db_ecdsa_get(&conn, user_id, &EcdsaStruct::Party1Private)?;

    let (party_one_third_message, party_one_pdl_decommit, alpha) =
        MasterKey1::key_gen_third_message(&party_2_pdl_first_message.0, &party_one_private);

    db_ecdsa_update(&conn, user_id, &party_one_pdl_decommit, &EcdsaStruct::PDLDecommit)?;
    db_ecdsa_update(&conn, user_id, &Alpha{value:alpha}, &EcdsaStruct::Alpha)?;
    db_ecdsa_update(&conn, user_id, &party_2_pdl_first_message.0, &EcdsaStruct::Party2PDLFirstMsg)?;

    Ok(Json(party_one_third_message))
}

#[post(
    "/ecdsa/keygen/<id>/fourth",
    format = "json",
    data = "<party_two_pdl_second_message>"
)]
pub fn fourth_message(
    conn: DataBase,
    id: String,
    party_two_pdl_second_message: Json<party_two::PDLSecondMessage>,
) -> Result<Json<party_one::PDLSecondMessage>> {
    let user_id = Uuid::from_str(&id).unwrap();

    let party_one_private: party_one::Party1Private =
        db_ecdsa_get(&conn, user_id, &EcdsaStruct::Party1Private)?;

    let party_one_pdl_decommit: party_one::PDLdecommit =
        db_ecdsa_get(&conn, user_id, &EcdsaStruct::PDLDecommit)?;

    let party_2_pdl_first_message: party_two::PDLFirstMessage =
        db_ecdsa_get(&conn, user_id, &EcdsaStruct::Party2PDLFirstMsg)?;

    let alpha: Alpha =
        db_ecdsa_get(&conn, user_id, &EcdsaStruct::Alpha)?;

    let res = MasterKey1::key_gen_fourth_message(
        &party_2_pdl_first_message,
        &party_two_pdl_second_message.0,
        party_one_private,
        party_one_pdl_decommit,
        alpha.value,
    );

    assert!(res.is_ok());

    master_key(conn, id)?;

    Ok(Json(res.unwrap()))
}

pub fn master_key(conn: DataBase, id: String) -> Result<()> {
    let user_id = Uuid::from_str(&id).unwrap();

    let party2_public: GE =
        db_ecdsa_get(&conn, user_id, &EcdsaStruct::Party2Public)?;

    let paillier_key_pair: party_one::PaillierKeyPair =
        db_ecdsa_get(&conn, user_id, &EcdsaStruct::PaillierKeyPair)?;

    let party_one_private: party_one::Party1Private =
        db_ecdsa_get(&conn, user_id, &EcdsaStruct::Party1Private)?;

    let comm_witness: party_one::CommWitness =
        db_ecdsa_get(&conn, user_id, &EcdsaStruct::CommWitness)?;

    let master_key = MasterKey1::set_master_key(
        &BigInt::from(0),
        party_one_private,
        &comm_witness.public_share,
        &party2_public,
        paillier_key_pair,
    );

    db_ecdsa_update(&conn, user_id, &master_key, &EcdsaStruct::Party1MasterKey)
}

#[post(
    "/ecdsa/sign/<id>/first",
    format = "json",
    data = "<eph_key_gen_first_message_party_two>"
)]
pub fn sign_first(
    state: State<Config>,
    claim: Claims,
    conn: DataBase,
    id: String,
    eph_key_gen_first_message_party_two: Json<party_two::EphKeyGenFirstMsg>,
) -> Result<Json<party_one::EphKeyGenFirstMsg>> {
    let user_id = Uuid::from_str(&id).unwrap();
    // Check authorisation id is in DB (and check password?)
    check_user_auth(&state, &claim, &id)?;

    let (sign_party_one_first_message, eph_ec_key_pair_party1) = MasterKey1::sign_first_message();

    db_ecdsa_update(&conn, user_id, &eph_key_gen_first_message_party_two.0, &EcdsaStruct::EphKeyGenFirstMsg)?;
    db_ecdsa_update(&conn, user_id, &eph_ec_key_pair_party1, &EcdsaStruct::EphEcKeyPair)?;

    Ok(Json(sign_party_one_first_message))
}

#[post("/ecdsa/sign/<id>/second", format = "json", data = "<request>")]
pub fn sign_second(
    state: State<Config>,
    claim: Claims,
    conn: DataBase,
    id: String,
    request: Json<SignSecondMsgRequest>,
) -> Result<Json<Vec<Vec<u8>>>> {
    let user_id = Uuid::from_str(&id).unwrap();
    // Check authorisation id is in DB (and check password?)
    check_user_auth(&state, &claim, &id)?;

    // Get UserSession for this user and check sig hash, backup tx and state chain id exists
    let mut user_session: UserSession =
        db::get(&state.db, &claim.sub, &id, &StateEntityStruct::UserSession)?
            .ok_or(SEError::DBError(NoDataForID, id.clone()))?;
    if user_session.sig_hash.is_none() {
        return Err(SEError::SigningError(String::from(
            "No sig_hash found for this user's session.",
        )));
    }
    if user_session.tx_backup.is_none() {
        return Err(SEError::SigningError(String::from(
            "No tx_backup found for this user's session.",
        )));
    }

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
    if user_session.sig_hash.unwrap().to_string() != message_sig_hash {
        return Err(SEError::SigningError(format!(
            "Message to be signed does not match verified sig hash. \n{}, {}",
            user_session.sig_hash.unwrap().to_string(), message_sig_hash
        )));
    }

    let shared_key: MasterKey1 =
        db_ecdsa_get(&conn, user_id, &EcdsaStruct::Party1MasterKey)?;

    let eph_ec_key_pair_party1: party_one::EphEcKeyPair =
        db_ecdsa_get(&conn, user_id, &EcdsaStruct::EphEcKeyPair)?;

    let eph_key_gen_first_message_party_two: party_two::EphKeyGenFirstMsg =
        db_ecdsa_get(&conn, user_id, &EcdsaStruct::EphKeyGenFirstMsg)?;

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
        Protocol::Withdraw => user_session.tx_withdraw.clone().unwrap().to_owned(),
        _ => {
            // despoit() and transfer() both sign tx_backup
            user_session.tx_backup.clone().unwrap().to_owned()
        }
    };

    // Make signature witness
    let mut r_vec = BigInt::to_vec(&signature.r);
    if r_vec.len() != 32 { // Check corrcet length of conversion to Signature
        let mut temp = vec![0;32-r_vec.len()];
        temp.extend(r_vec);
        r_vec = temp;
    }
    let mut s_vec = BigInt::to_vec(&signature.s);
    if s_vec.len() != 32 { // Check corrcet length of conversion to Signature
        let mut temp = vec![0;32-s_vec.len()];
        temp.extend(s_vec);
        s_vec = temp;
    }
    let mut v = r_vec;
    v.extend(s_vec);
    let mut sig_vec = Signature::from_compact(&v[..])?
        .serialize_der()
        .to_vec();
    sig_vec.push(01);
    let pk_vec = shared_key.public.q.get_element().serialize().to_vec();
    let mut witness = vec![sig_vec, pk_vec];

    // Add signature to tx
    tx.input[0].witness = witness.clone();

    match request.protocol {
        Protocol::Withdraw => {
            // Store signed withdraw tx in UserSession DB object
            user_session.tx_withdraw = Some(tx);
            info!("WITHDRAW: Tx signed and stored. User ID: {}", user_session.id);
            // Do not return withdraw tx witness until /withdraw/confirm is complete
            witness = vec![];
        }
        _ => {
            // Store signed backup tx in UserSession DB object
            user_session.tx_backup = Some(tx.to_owned());
            info!("DEPOSIT/TRANSFER: Backup Tx signed and stored. User: {}", user_session.id);
        }
    };

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &StateEntityStruct::UserSession,
        &user_session,
    )?;

    Ok(Json(witness))
}


#[post("/ecdsa/<id>/recover", format = "json")]
pub fn recover(state: State<Config>, claim: Claims, id: String) -> Result<Json<u32>> {
    let pos_old: u32 = db::get(&state.db, &claim.sub, &id, &EcdsaStruct::POS)?
        .ok_or(SEError::DBError(NoDataForID, id.clone()))?;
    Ok(Json(pos_old))
}
