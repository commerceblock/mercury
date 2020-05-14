use super::super::Result;
use super::super::auth::jwt::Claims;
use super::super::storage::db;
use super::super::Config;

use crate::routes::state_entity::{ check_user_auth, StateChainStruct, SessionData, StateChain };
use shared_lib::util::reverse_hex_str;
use crate::error::{SEError,DBErrorType::NoDataForID};
extern crate shared_lib;

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
use std::string::ToString;
use bitcoin::secp256k1::{ Signature };

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

#[post("/ecdsa/keygen/<id>/first", format="json")]
pub fn first_message(
    state: State<Config>,
    claim: Claims,
    id: String
) -> Result<Json<(String, party_one::KeyGenFirstMsg)>> {
    // check authorisation id is in DB (and check password?)
    check_user_auth(&state, &claim, &id)?;

    // Generate shared key
    let (key_gen_first_msg, comm_witness, ec_key_pair) = MasterKey1::key_gen_first_message();

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

/// For transfer protocol. Servers secret key s2 must be grabbed from db rather than
/// randomly generated.
#[post("/ecdsa/keygen/<id>/first-fixed", format="json")]
pub fn first_message_fixed(
    state: State<Config>,
    claim: Claims,
    id: String,
) -> Result<Json<(String, party_one::KeyGenFirstMsg)>> {
    // check authorisation id is in DB (and check password?)
    let user_session = check_user_auth(&state, &claim, &id)?;

    // Generate shared key
    let (key_gen_first_msg, comm_witness, ec_key_pair) = MasterKey1::key_gen_first_message_predefined(user_session.s2.unwrap());

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

// Added here because the attribute data takes only a single struct
#[derive(Serialize, Deserialize)]
pub struct SignSecondMsgRequest {
    pub message: BigInt,
    pub party_two_sign_message: party2::SignMessage,
}
#[post("/ecdsa/sign/<id>/second", format = "json", data = "<request>")]
pub fn sign_second(
    state: State<Config>,
    claim: Claims,
    id: String,
    request: Json<SignSecondMsgRequest>,
) -> Result<Json<party_one::SignatureRecid>> {
    // check authorisation id is in DB (and check password?)
    check_user_auth(&state, &claim, &id)?;

    // checksighash matches message to be signed
    if request.message.to_string() != BigInt::from(12345).to_string() { // allow through for testing
        let sig_hash: Option<SessionData> = db::get(
            &state.db,
            &claim.sub,
            &id,
            &StateChainStruct::SessionData)?;
        match sig_hash {
            Some(_) => debug!("Sig hash found in DB for this id."),
            None => return Err(SEError::SigningError(String::from("No sig hash found for state chain session.")))
        };

        // check message to sign is correct sig hash
        let mut message_hex = request.message.to_hex();
        let message_sig_hash;
        match reverse_hex_str(message_hex.clone()) {
            Ok(res) => message_sig_hash = res,
            Err(e) => {
                // Try for case in which sighash begins with leading 0's and so conversion to hex from
                // BigInt is incorrect
                let num_zeros = 64 - message_hex.len();
                if num_zeros < 1 { return Err(SEError::from(e)) };
                let temp = message_hex.clone();
                message_hex = format!("{:0width$}",0 ,width = num_zeros);
                message_hex.push_str(&temp);
                // try reverse again
                message_sig_hash = reverse_hex_str(message_hex.clone())?;
            }
        }

        if sig_hash.unwrap().sig_hash.to_string() != message_sig_hash {
            return Err(SEError::SigningError(String::from("Message to be signed does not match verified sig hash.")))
        } else {
            debug!("Sig hash in message matches verified sig hash.")
        }
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
        Err(_) => panic!("validation failed")
    };

    // Add back up transaction to State Chain
    let session_data: SessionData =
        db::get(&state.db, &claim.sub, &id, &StateChainStruct::SessionData)?
            .ok_or(SEError::DBError(NoDataForID, id.clone()))?;

    let mut backup_tx = session_data.backup_tx.clone();
    let mut v = BigInt::to_vec(&signature.r);     // make signature witness
    v.extend(BigInt::to_vec(&signature.s));
    let mut sig_vec = Signature::from_compact(&v[..])
        .unwrap()
        .serialize_der()
        .to_vec();
    sig_vec.push(01);
    let pk_vec = shared_key.public.q.get_element().serialize().to_vec();
    backup_tx.input[0].witness = vec![sig_vec, pk_vec];

    // update StateChain DB object
    let mut state_chain: StateChain =
        db::get(&state.db, &claim.sub, &session_data.state_chain_id, &StateChainStruct::StateChain)?
            .ok_or(SEError::DBError(NoDataForID, session_data.state_chain_id.clone()))?;

    state_chain.backup_tx = Some(backup_tx);
    db::insert(
        &state.db,
        &claim.sub,
        &session_data.state_chain_id,
        &StateChainStruct::StateChain,
        &state_chain
    )?;

    Ok(Json(signature))
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
