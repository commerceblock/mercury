//! state_entity
//!
//! State Entity implementation

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
#[post("/init", format = "json")]
pub fn session_init(
    state: State<Config>,
    claim: Claims,
) -> Result<Json<(String)>> {
    // generate shared wallet ID (user ID)
    let user_id = Uuid::new_v4().to_string();

    // create DB entry for newly generated ID signalling that user has passed some
    // verification. For now use ID as 'password' to interact with state entity
    db::insert(
        &state.db,
        &claim.sub,
        &user_id,
        &StateChainStruct::UserSession,
        &UserSession {
            id: user_id.clone(),
        }
    )?;

    Ok(Json(user_id))
}

/// Authenticate User
pub fn check_user_auth(
    state: &State<Config>,
    claim: &Claims,
    id: &String
) -> Option<UserSession> {
    // check authorisation id is in DB (and check password?)
    db::get(
        &state.db,
        &claim.sub,
        &id,
        &StateChainStruct::UserSession).unwrap()
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DepositMessage1 {
    p_addr: String, // address which funding tx funds are sent to
    tx_b_input_txid: String,
    tx_b_input_vout: u32,
    tx_b_input_seq: u32,
    tx_b_address: String,
    tx_b_amount: u64
}

/// deposit first message
///     - calculate and store back up tx sighash for validation before performing ecdsa::sign
#[post("/deposit/<id>/first", format = "json", data = "<deposit_msg>")]
pub fn deposit_first(
    state: State<Config>,
    claim: Claims,
    id: String,
    deposit_msg: Json<DepositMessage1>,
) -> Result<Json<()>> {
    // auth user
    let auth_ed = check_user_auth(&state, &claim, &id);
    match auth_ed {
        Some(_) => println!("ECDSA Keygen first message: Id {} found in DB.", id),
        // fix to return Error. Currently return empty Result<Json<(String, party_one::KeyGenFirstMsg)>>
        None => println!("deposit_first() auth error")
    };
    // rebuild tx_b sig hash to verify co-sign will be signing the correct data
    let tx_b_txin = TxIn {
        previous_output: OutPoint {
            txid: sha256d::Hash::from_str(&deposit_msg.tx_b_input_txid).unwrap(),
            vout: deposit_msg.tx_b_input_vout
        },
        sequence: deposit_msg.tx_b_input_seq,
        witness: Vec::new(),
        script_sig: bitcoin::Script::default(),
    };

    let tx_b = build_tx_b(
        &tx_b_txin,
        &Address::from_str(&deposit_msg.tx_b_address).unwrap(),
        &Amount::from_sat(deposit_msg.tx_b_amount)
    ).unwrap();

    let comp = SighashComponents::new(&tx_b);
    let sig_hash = comp.sighash_all(
        &tx_b_txin,
        &Address::from_str(&deposit_msg.p_addr).unwrap().script_pubkey(),
        deposit_msg.tx_b_amount
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
