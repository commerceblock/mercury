//! state_entity
//!
//! State Entity implementation

use crate::error::SEError;
use crate::util::build_tx_b;
use bitcoin::{ Address, Amount, OutPoint, TxIn };
use bitcoin::hashes::sha256d;
use bitcoin::util::bip143::SighashComponents;

use super::super::Result;
use rocket_contrib::json::Json;
use rocket::State;
use std::str::FromStr;
use uuid::Uuid;

use super::super::auth::jwt::Claims;
use super::super::storage::db;
use super::super::Config;

/// contains state chain id and data
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct StateChain {
    pub id: String,
    /// chain of transitory key history (owners)
    pub chain: Vec<String>, // Chain of owners. String for now as unsure on data type at the moment.
}

/// user ID
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct UserSession {
    pub id: String,
    // pub pass: String
    pub proof_key: String // user's public proof key
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SessionData {
    pub sig_hash: sha256d::Hash,
    pub state_chain_id: String
}

#[derive(Debug)]
pub enum StateChainStruct {
    UserSession,
    SessionData,
    StateChain
}

impl db::MPCStruct for StateChainStruct {
    fn to_string(&self) -> String {
        format!("StateChain{:?}", self)
    }
}

/// Initiliase session
///     - Generate and return shared wallet ID
///     - Can do auth or other DDoS mitigation here
///     - Input
#[post("/init", format = "json", data = "<proof_key>")]
pub fn session_init(
    state: State<Config>,
    claim: Claims,
    proof_key: String,
) -> Result<Json<(String)>> {
    // generate shared wallet ID (user ID)
    let user_id = Uuid::new_v4().to_string();

    // Verification/PoW/authoriation falied
    // Err(SEError::AuthError)

    // create DB entry for newly generated ID signalling that user has passed some
    // verification. For now use ID as 'password' to interact with state entity
    db::insert(
        &state.db,
        &claim.sub,
        &user_id,
        &StateChainStruct::UserSession,
        &UserSession {
            id: user_id.clone(),
            proof_key: proof_key,
        }
    )?;
    Ok(Json(user_id))
}

/// check if user has passed authentication
pub fn check_user_auth(
    state: &State<Config>,
    claim: &Claims,
    id: &String
) -> Result<UserSession> {
    // check authorisation id is in DB (and check password?)
    db::get(
        &state.db,
        &claim.sub,
        &id,
        &StateChainStruct::UserSession).unwrap()
    .ok_or(SEError::AuthError)
}

/// struct contains data necessary to caluculate tx input sighash
#[derive(Serialize, Deserialize, Debug)]
pub struct PrepareSignTxMessage {
    spending_addr: String, // address which funding tx funds are sent to
    input_txid: String,
    input_vout: u32,
    input_seq: u32,
    address: String,
    amount: u64
}

/// prepare to sign a transaction input
///     - calculate and store tx sighash for validation before performing ecdsa::sign
#[post("/prepare-sign/<id>", format = "json", data = "<prepare_sign_msg>")]
pub fn prepare_sign(
    state: State<Config>,
    claim: Claims,
    id: String,
    prepare_sign_msg: Json<PrepareSignTxMessage>,
) -> Result<Json<()>> {
    // auth user
    check_user_auth(&state, &claim, &id)?;

    // rebuild tx_b sig hash to verify co-sign will be signing the correct data
    let txin = TxIn {
        previous_output: OutPoint {
            txid: sha256d::Hash::from_str(&prepare_sign_msg.input_txid).unwrap(),
            vout: prepare_sign_msg.input_vout
        },
        sequence: prepare_sign_msg.input_seq,
        witness: Vec::new(),
        script_sig: bitcoin::Script::default(),
    };

    let tx_b = build_tx_b(
        &txin,
        &Address::from_str(&prepare_sign_msg.address).unwrap(),
        &Amount::from_sat(prepare_sign_msg.amount)
    ).unwrap();

    let comp = SighashComponents::new(&tx_b);
    let sig_hash = comp.sighash_all(
        &txin,
        &Address::from_str(&prepare_sign_msg.spending_addr).unwrap().script_pubkey(),
        prepare_sign_msg.amount
    );

    // store sig_hash with state chain id
    let state_chain_id = Uuid::new_v4().to_string();
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &StateChainStruct::SessionData,
        &SessionData {
            sig_hash: sig_hash.clone(),
            state_chain_id: state_chain_id.clone()
        }
    )?;

    // create StateChain DB object
    db::insert(
        &state.db,
        &claim.sub,
        &state_chain_id,
        &StateChainStruct::StateChain,
        &StateChain {
            id: state_chain_id.clone(),
            chain: vec!(id)
        }
    )?;

    Ok(Json(()))
}
