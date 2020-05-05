//! state_entity
//!
//! State Entity implementation

use crate::error::SEError;
use crate::util::build_tx_b;
use bitcoin::{ Address, Amount, OutPoint, TxIn, PublicKey, Transaction };
use bitcoin::hashes::sha256d;
use bitcoin::util::bip143::SighashComponents;

use curv::elliptic::curves::traits::ECScalar;
use curv::FE;

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
    /// current back-up transaction
    pub backup_tx: Option<Transaction>
}

/// User ID
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct UserSession {
    /// User's identification
    pub id: String,
    /// User's password
    // pub pass: String
    /// User's public proof key
    pub proof_key: String
}
/// User Session Data
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SessionData {
    /// back up tx's sig hash
    pub sig_hash: sha256d::Hash,
    /// back up tx
    pub backup_tx: Transaction,
    /// ID of state chain that this back up tx is for
    pub state_chain_id: String
}

/// TransferData provides new Owner's data for UserSession and SessionData structs
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct TransferData {
    pub state_chain_id: String,
    pub new_state_chain: Vec<String>,
    pub x1: FE
}

#[derive(Debug)]
pub enum StateChainStruct {
    UserSession,
    SessionData,
    StateChain,
    TransferData
}

impl db::MPCStruct for StateChainStruct {
    fn to_string(&self) -> String {
        format!("StateChain{:?}", self)
    }
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


#[post("/api/statechain/<id>", format = "json")]
pub fn get_statechain(
    state: State<Config>,
    claim: Claims,
    id: String,
) -> Result<Json<Vec<String>>> {
    let session_data: StateChain =
        db::get(&state.db, &claim.sub, &id, &StateChainStruct::StateChain)?
            .ok_or(SEError::Generic(format!("No data for such identifier: StateChain {}", id)))?;
    Ok(Json(session_data.chain))
}


#[derive(Serialize, Deserialize, Debug)]
pub struct DepositMsg1 {
    pub proof_key: String,
}

/// Initiliase deposit protocol
///     - Generate and return shared wallet ID
///     - Can do auth or other DoS mitigation here
///     - Input
#[post("/deposit/init", format = "json", data = "<msg1>")]
pub fn deposit_init(
    state: State<Config>,
    claim: Claims,
    msg1: Json<DepositMsg1>,
) -> Result<Json<String>> {
    // generate shared wallet ID (user ID)
    let user_id = Uuid::new_v4().to_string();

    // Verification/PoW/authoriation failed
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
            proof_key: msg1.proof_key.clone(),
        }
    )?;
    Ok(Json(user_id))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TransferMsg1 {
    id: String,
    new_state_chain: Vec<String>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct TransferMsg2 {
    x1: FE,
}
/// Initiliase transfer protocol
///     - Authorisation of Owner and DoS protection
///     - Validate transfer parameters
///     - Store transfer parameters
#[post("/transfer/init", format = "json", data = "<msg1>")]
pub fn transfer_init(
    state: State<Config>,
    claim: Claims,
    msg1: Json<TransferMsg1>,
) -> Result<Json<TransferMsg2>> {
    // auth user
    check_user_auth(&state, &claim, &msg1.id)?;

    // Verification/PoW/authoriation failed
    // Err(SEError::AuthError)

    // get state_chain id
    let session_data: SessionData =
        db::get(&state.db, &claim.sub, &msg1.id, &StateChainStruct::SessionData)?
            .ok_or(SEError::Generic(format!("No data for such identifier {}", msg1.id)))?;

    // Generate x1
    let x1: FE = ECScalar::new_random();

    // create TransferData DB entry
    db::insert(
        &state.db,
        &claim.sub,
        &msg1.id,
        &StateChainStruct::TransferData,
        &TransferData {
            state_chain_id: session_data.state_chain_id.clone(),
            new_state_chain: msg1.new_state_chain.clone(),
            x1
        }
    )?;

    // TODO encrypt x1 with Senders proof key
    Ok(Json(TransferMsg2{x1}))
}

/// struct contains data necessary to caluculate tx input sighash
#[derive(Serialize, Deserialize, Debug)]
pub struct PrepareSignTxMessage {
    pub spending_addr: String, // address which funding tx funds are sent to
    pub input_txid: String,
    pub input_vout: u32,
    pub address: String,
    pub amount: u64,
    pub transfer: bool // is transfer? (create new or update state chain?)
}

/// prepare to sign backup transaction input
///     - calculate and store tx sighash for validation before performing ecdsa::sign
#[post("/prepare-sign/<id>", format = "json", data = "<prepare_sign_msg>")]
pub fn prepare_sign_backup(
    state: State<Config>,
    claim: Claims,
    id: String,
    prepare_sign_msg: Json<PrepareSignTxMessage>,
) -> Result<Json<String>> {
    // auth user
    check_user_auth(&state, &claim, &id)?;

    // rebuild tx_b sig hash to verify co-sign will be signing the correct data
    let txin = TxIn {
        previous_output: OutPoint {
            txid: sha256d::Hash::from_str(&prepare_sign_msg.input_txid).unwrap(),
            vout: prepare_sign_msg.input_vout
        },
        sequence: 0xFFFFFFFF,
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


    // if deposit()
    if prepare_sign_msg.transfer == false {
        // store SessionData for user: sig_hash with back up tx and state chain id
        let state_chain_id = Uuid::new_v4().to_string();
        db::insert(
            &state.db,
            &claim.sub,
            &id,
            &StateChainStruct::SessionData,
            &SessionData {
                sig_hash: sig_hash.clone(),
                backup_tx: tx_b.clone(),
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
                chain: vec!(id),
                backup_tx: None
            }
        )?;

        return Ok(Json(state_chain_id));
    };

    // if transfer() get and update SessionData for this user
    let mut session_data: SessionData =
        db::get(&state.db, &claim.sub, &id, &StateChainStruct::SessionData)?
            .ok_or(SEError::Generic(format!("No data for such identifier: SessionData {}", id)))?;

    session_data.sig_hash = sig_hash;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &StateChainStruct::SessionData,
        &session_data
    )?;

    Ok(Json(String::from("")))
}

// #[derive(Serialize, Deserialize, Debug)]
// pub struct TransferMsg3 {
//     : FE,
// }
// /// Sign state chain to pass ownership to new owner
// #[post("/sign-sign_statechain/<id>", format = "json", data = "<prepare_sign_msg>")]
// pub fn sign_statechain() {
//
// }
