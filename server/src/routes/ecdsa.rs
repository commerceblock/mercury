use super::super::Result;
use super::super::auth::jwt::Claims;
use super::super::storage::db;
use super::super::Config;

use shared_lib::util::reverse_hex_str;
use shared_lib::structs::{Protocol,SignSecondMsgRequest};
use shared_lib::{Root, state_chain::{update_statechain_smt, StateChain}};

use crate::routes::state_entity::{ check_user_auth, StateEntityStruct, UserSession };
use crate::error::{SEError,DBErrorType::NoDataForID};

use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::{
    CommWitness, EcKeyPair, Party1FirstMessage, Party1SecondMessage,
};
use curv::elliptic::curves::traits::ECPoint;
use curv::{BigInt, GE};
use kms::chain_code::two_party as chain_code;
use kms::ecdsa::two_party::*;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use curv::arithmetic::traits::Converter;
use rocket::State;
use rocket_contrib::json::Json;
use bitcoin::{Transaction, secp256k1::Signature, consensus};
use std::string::ToString;
use db::{update_root, get_current_root, DB_SC_LOC};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct HDPos {
    pos: u32,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct Alpha {
    value: BigInt
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

    POS,
}

impl db::MPCStruct for EcdsaStruct {
    fn to_string(&self) -> String {
        format!("{:?}", self)
    }

    // backward compatibility
    fn to_table_name(&self, env: &str) -> String {
        if self.to_string() == "Party1MasterKey" {
            format!("{}_{}", env, self.to_string())
        } else {
            format!("{}-gotham-{}", env, self.to_string())
        }
    }

    fn require_customer_id(&self) -> bool {
        self.to_string() == "Party1MasterKey"
    }
}

#[post("/ecdsa/keygen/<id>/first/<protocol>", format="json")]
pub fn first_message(
    state: State<Config>,
    claim: Claims,
    id: String,
    protocol: String,
) -> Result<Json<(String, party_one::KeyGenFirstMsg)>> {
    // check authorisation id is in DB (and check password?)
    let user_session = check_user_auth(&state, &claim, &id)?;

    // Generate shared key
    let (key_gen_first_msg, comm_witness, ec_key_pair) =
        if protocol == String::from("deposit") {
            MasterKey1::key_gen_first_message()
        } else {
            MasterKey1::key_gen_first_message_predefined(user_session.s2.unwrap())
        };

    //save pos 0
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::POS,
        &HDPos { pos: 0u32 },
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::KeyGenFirstMsg,
        &key_gen_first_msg,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::CommWitness,
        &comm_witness,
    )?;
    db::insert(&state.db, &claim.sub, &id, &EcdsaStruct::EcKeyPair, &ec_key_pair)?;

    Ok(Json((id, key_gen_first_msg)))
}


#[post("/ecdsa/keygen/<id>/second", format = "json", data = "<dlog_proof>")]
pub fn second_message(
    state: State<Config>,
    claim: Claims,
    id: String,
    dlog_proof: Json<DLogProof>,
) -> Result<Json<party1::KeyGenParty1Message2>> {
    let party2_public: GE = dlog_proof.0.pk.clone();
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::Party2Public,
        &party2_public,
    )?;

    let comm_witness: party_one::CommWitness =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::CommWitness)?
            .ok_or(SEError::DBError(NoDataForID, id.clone()))?;
    let ec_key_pair: party_one::EcKeyPair = db::get(&state.db, &claim.sub, &id, &EcdsaStruct::EcKeyPair)?
        .ok_or(SEError::DBError(NoDataForID, id.clone()))?;

    let (kg_party_one_second_message, paillier_key_pair, party_one_private) =
        MasterKey1::key_gen_second_message(comm_witness, &ec_key_pair, &dlog_proof.0);

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::PaillierKeyPair,
        &paillier_key_pair,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::Party1Private,
        &party_one_private,
    )?;

    Ok(Json(kg_party_one_second_message))
}

#[post(
    "/ecdsa/keygen/<id>/third",
    format = "json",
    data = "<party_2_pdl_first_message>"
)]
pub fn third_message(
    state: State<Config>,
    claim: Claims,
    id: String,
    party_2_pdl_first_message: Json<party_two::PDLFirstMessage>,
) -> Result<Json<party_one::PDLFirstMessage>> {
    let party_one_private: party_one::Party1Private =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::Party1Private)?
            .ok_or(SEError::DBError(NoDataForID, id.clone()))?;

    let (party_one_third_message, party_one_pdl_decommit, alpha) =
        MasterKey1::key_gen_third_message(&party_2_pdl_first_message.0, &party_one_private);

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::PDLDecommit,
        &party_one_pdl_decommit,
    )?;

    db::insert(&state.db, &claim.sub, &id, &EcdsaStruct::Alpha, &Alpha { value: alpha })?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::Party2PDLFirstMsg,
        &party_2_pdl_first_message.0,
    )?;

    Ok(Json(party_one_third_message))
}

#[post(
    "/ecdsa/keygen/<id>/fourth",
    format = "json",
    data = "<party_two_pdl_second_message>"
)]
pub fn fourth_message(
    state: State<Config>,
    claim: Claims,
    id: String,
    party_two_pdl_second_message: Json<party_two::PDLSecondMessage>,
) -> Result<Json<party_one::PDLSecondMessage>> {
    let party_one_private: party_one::Party1Private =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::Party1Private)?
            .ok_or(SEError::DBError(NoDataForID, id.clone()))?;

    let party_one_pdl_decommit: party_one::PDLdecommit =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::PDLDecommit)?
            .ok_or(SEError::DBError(NoDataForID, id.clone()))?;

    let party_2_pdl_first_message: party_two::PDLFirstMessage =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::Party2PDLFirstMsg)?
            .ok_or(SEError::DBError(NoDataForID, id.clone()))?;

    let alpha: Alpha = db::get(&state.db, &claim.sub, &id, &EcdsaStruct::Alpha)?
        .ok_or(SEError::DBError(NoDataForID, id.clone()))?;

    let res = MasterKey1::key_gen_fourth_message(
        &party_2_pdl_first_message,
        &party_two_pdl_second_message.0,
        party_one_private,
        party_one_pdl_decommit,
        alpha.value,
    );

    assert!(res.is_ok());

    Ok(Json(res.unwrap()))
}

#[post("/ecdsa/keygen/<id>/chaincode/first", format = "json")]
pub fn chain_code_first_message(
    state: State<Config>,
    claim: Claims,
    id: String,
) -> Result<Json<Party1FirstMessage>> {
    let (cc_party_one_first_message, cc_comm_witness, cc_ec_key_pair1) =
        chain_code::party1::ChainCode1::chain_code_first_message();

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::CCKeyGenFirstMsg,
        &cc_party_one_first_message,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::CCCommWitness,
        &cc_comm_witness,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::CCEcKeyPair,
        &cc_ec_key_pair1,
    )?;

    Ok(Json(cc_party_one_first_message))
}

#[post(
    "/ecdsa/keygen/<id>/chaincode/second",
    format = "json",
    data = "<cc_party_two_first_message_d_log_proof>"
)]
pub fn chain_code_second_message(
    state: State<Config>,
    claim: Claims,
    id: String,
    cc_party_two_first_message_d_log_proof: Json<DLogProof>,
) -> Result<Json<Party1SecondMessage>> {
    let cc_comm_witness: CommWitness = db::get(&state.db, &claim.sub, &id, &EcdsaStruct::CCCommWitness)?
        .ok_or(SEError::DBError(NoDataForID, id.clone()))?;

    let party1_cc = chain_code::party1::ChainCode1::chain_code_second_message(
        cc_comm_witness,
        &cc_party_two_first_message_d_log_proof.0,
    );

    let party2_pub = &cc_party_two_first_message_d_log_proof.pk;
    chain_code_compute_message(state, claim, id, party2_pub)?;

    Ok(Json(party1_cc))
}

pub fn chain_code_compute_message(
    state: State<Config>,
    claim: Claims,
    id: String,
    cc_party2_public: &GE,
) -> Result<Json<()>> {
    let cc_ec_key_pair_party1: EcKeyPair =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::CCEcKeyPair)?
            .ok_or(SEError::DBError(NoDataForID, id.clone()))?;
    let party1_cc = chain_code::party1::ChainCode1::compute_chain_code(
        &cc_ec_key_pair_party1,
        &cc_party2_public,
    );

    db::insert(&state.db, &claim.sub, &id, &EcdsaStruct::CC, &party1_cc)?;
    master_key(state, claim, id)?;
    Ok(Json(()))
}

pub fn master_key(state: State<Config>, claim: Claims, id: String) -> Result<()> {
    let party2_public: GE = db::get(&state.db, &claim.sub, &id, &EcdsaStruct::Party2Public)?
        .ok_or(SEError::DBError(NoDataForID, id.clone()))?;

    let paillier_key_pair: party_one::PaillierKeyPair =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::PaillierKeyPair)?
            .ok_or(SEError::DBError(NoDataForID, id.clone()))?;

    let party1_cc: chain_code::party1::ChainCode1 =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::CC)?
            .ok_or(SEError::DBError(NoDataForID, id.clone()))?;

    let party_one_private: party_one::Party1Private =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::Party1Private)?
            .ok_or(SEError::DBError(NoDataForID, id.clone()))?;

    let comm_witness: party_one::CommWitness =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::CommWitness)?
            .ok_or(SEError::DBError(NoDataForID, id.clone()))?;

    let master_key = MasterKey1::set_master_key(
        &party1_cc.chain_code,
        party_one_private,
        &comm_witness.public_share,
        &party2_public,
        paillier_key_pair,
    );

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::Party1MasterKey,
        &master_key,
    )
}

#[post(
    "/ecdsa/sign/<id>/first",
    format = "json",
    data = "<eph_key_gen_first_message_party_two>"
)]
pub fn sign_first(
    state: State<Config>,
    claim: Claims,
    id: String,
    eph_key_gen_first_message_party_two: Json<party_two::EphKeyGenFirstMsg>,
) -> Result<Json<party_one::EphKeyGenFirstMsg>> {
    // check authorisation id is in DB (and check password?)
    check_user_auth(&state, &claim, &id)?;

    let (sign_party_one_first_message, eph_ec_key_pair_party1) = MasterKey1::sign_first_message();

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::EphKeyGenFirstMsg,
        &eph_key_gen_first_message_party_two.0,
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::EphEcKeyPair,
        &eph_ec_key_pair_party1,
    )?;

    Ok(Json(sign_party_one_first_message))
}

#[post("/ecdsa/sign/<id>/second", format = "json", data = "<request>")]
pub fn sign_second(
    state: State<Config>,
    claim: Claims,
    id: String,
    request: Json<SignSecondMsgRequest>,
) -> Result<Json<Vec<Vec<u8>>>> {
    // check authorisation id is in DB (and check password?)
    check_user_auth(&state, &claim, &id)?;

    // Get UserSession for this user and check sig hash, backup tx and state chain id exists
    let mut user_session: UserSession = db::get(&state.db, &claim.sub, &id, &StateEntityStruct::UserSession)?
        .ok_or(SEError::DBError(NoDataForID, id.clone()))?;
    if user_session.sig_hash.is_none() {
        return Err(SEError::SigningError(String::from("No sig_hash found for state chain session.")));
    }
    if user_session.backup_tx.is_none() {
        return Err(SEError::SigningError(String::from("No backup_tx found for state chain session.")));
    }
    if user_session.state_chain_id.is_none() {
        return Err(SEError::SigningError(String::from("No state_chain_id found for state chain session.")));
    }

    // check sighash matches message to be signed
    let mut message_hex = request.message.to_hex();
    let message_sig_hash;
    match reverse_hex_str(message_hex.clone()) {
        Ok(res) => message_sig_hash = res,
        Err(e) => {
            // Try for case in which sighash begins with 0's and so conversion to hex from
            // BigInt is too short
            let num_zeros = 64 - message_hex.len();
            if num_zeros < 1 { return Err(SEError::from(e)) };
            let temp = message_hex.clone();
            message_hex = format!("{:0width$}",0 ,width = num_zeros);
            message_hex.push_str(&temp);
            // try reverse again
            message_sig_hash = reverse_hex_str(message_hex.clone())?;
        }
    }

    if user_session.sig_hash.unwrap().to_string() != message_sig_hash {
        return Err(SEError::SigningError(String::from("Message to be signed does not match verified sig hash.")))
    }

    let shared_key: MasterKey1 = db::get(&state.db, &claim.sub, &id, &EcdsaStruct::Party1MasterKey)?
        .ok_or(SEError::DBError(NoDataForID, id.clone()))?;

    let eph_ec_key_pair_party1: party_one::EphEcKeyPair =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::EphEcKeyPair)?
            .ok_or(SEError::DBError(NoDataForID, id.clone()))?;

    let eph_key_gen_first_message_party_two: party_two::EphKeyGenFirstMsg =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::EphKeyGenFirstMsg)?
            .ok_or(SEError::DBError(NoDataForID, id.clone()))?;

    let signature;
    match shared_key.sign_second_message(
        &request.party_two_sign_message,
        &eph_key_gen_first_message_party_two,
        &eph_ec_key_pair_party1,
        &request.message,
    ) {
        Ok(sig) => signature = sig,
        Err(_) => return Err(SEError::SigningError(String::from("Signature validation failed.")))
    };

    // Get transaction which is being signed.
    let mut tx: Transaction = match request.protocol {
        Protocol::Withdraw => {
            user_session.withdraw_tx.clone().unwrap().to_owned()
        },
        _ => { // despoit() and transfer() both sign backup_tx
            user_session.backup_tx.clone().unwrap().to_owned()
        }
    };

    // Add signature to tx
    let mut v = BigInt::to_vec(&signature.r);     // make signature witness
    v.extend(BigInt::to_vec(&signature.s));
    let mut sig_vec = Signature::from_compact(&v[..])
    .unwrap().serialize_der().to_vec();
    sig_vec.push(01);
    let pk_vec = shared_key.public.q.get_element().serialize().to_vec();
    let witness = vec![sig_vec, pk_vec];
    tx.input[0].witness = witness.clone();

    match request.protocol {
        Protocol::Withdraw => {
            // store signed withdraw tx in UserSession DB object
            user_session.withdraw_tx = Some(tx);

            db::insert(
                &state.db,
                &claim.sub,
                &id,
                &StateEntityStruct::UserSession,
                &user_session
            )?;

            debug!("Withdraw: Tx signed and stored.");
        },
        _ => { // despoit() and transfer() both sign backup_tx

            // store signed backup tx in UserSession DB object
            user_session.backup_tx = Some(tx.to_owned());

            db::insert(
                &state.db,
                &claim.sub,
                &id,
                &StateEntityStruct::UserSession,
                &user_session
            )?;

            // Store backup tx in State Chain DB object
            let state_chain_id = user_session.state_chain_id.unwrap();
            let mut state_chain: StateChain =
            db::get(&state.db, &claim.sub, &state_chain_id, &StateEntityStruct::StateChain)?
                .ok_or(SEError::DBError(NoDataForID, state_chain_id.clone()))?;

            state_chain.backup_tx = Some(tx.clone());

            db::insert(
                &state.db,
                &claim.sub,
                &state_chain_id,
                &StateEntityStruct::StateChain,
                &state_chain
            )?;

            // deposit() update sparse merkle tree
            if let Protocol::Deposit = request.protocol {
                // update sparse merkle tree with new StateChain entry
                let root = get_current_root::<Root>(&state.db)?;
                let new_root = update_statechain_smt(
                    DB_SC_LOC,
                    &root.value,
                    &tx.input.get(0).unwrap().previous_output.txid.to_string(),
                    &user_session.proof_key
                )?;
                update_root(&state.db, new_root.unwrap())?;

                debug!("Deposit: Added to sparse merkle tree. State Chain: {}", state_chain_id);
            }

            debug!("Deposit/Transfer: Backup Tx signed and stored. State Chain: {}", state_chain_id);
        }
    };

    Ok(Json(witness))
}

pub fn get_mk(state: &State<Config>, claim: Claims, id: &String) -> Result<MasterKey1> {
    db::get(&state.db, &claim.sub, &id, &EcdsaStruct::Party1MasterKey)?
        .ok_or(SEError::DBError(NoDataForID, id.to_string()))?
}


#[post("/ecdsa/<id>/recover", format = "json")]
pub fn recover(state: State<Config>, claim: Claims, id: String) -> Result<Json<u32>> {
    let pos_old: u32 = db::get(&state.db, &claim.sub, &id, &EcdsaStruct::POS)?
        .ok_or(SEError::DBError(NoDataForID, id.clone()))?;
    Ok(Json(pos_old))
}
