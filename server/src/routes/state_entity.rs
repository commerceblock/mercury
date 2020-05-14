//! state_entity
//!
//! State Entity implementation

use super::super::Result;
extern crate shared_lib;
use crate::error::{SEError,DBErrorType::NoDataForID};
use crate::routes::ecdsa;
use super::super::auth::jwt::Claims;
use super::super::storage::db;
use super::super::Config;

use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one::Party1Private;
use shared_lib::util::build_tx_b;
use shared_lib::structs::*;

use bitcoin::{ Address, Amount, OutPoint, TxIn, Transaction };
use bitcoin::hashes::sha256d;
use bitcoin::util::bip143::SighashComponents;

use curv::elliptic::curves::traits::{ ECScalar,ECPoint };
use curv::{BigInt,FE,GE};
use rocket_contrib::json::Json;
use rocket::State;
use std::str::FromStr;
use uuid::Uuid;



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
    pub proof_key: String,
    /// If transfer() then SE must know s2 value to create shared wallet
    pub s2: Option<FE>
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
            .ok_or(SEError::DBError(NoDataForID, id.clone()))?;
    Ok(Json(session_data.chain))
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
            s2: None
        }
    )?;
    Ok(Json(user_id))
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
    let user_session = check_user_auth(&state, &claim, &id)?;

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
                chain: vec!(user_session.proof_key.clone()),
                backup_tx: None
            }
        )?;

        return Ok(Json(state_chain_id));
    };

    // if transfer() get and update SessionData for this user
    let mut session_data: SessionData =
        db::get(&state.db, &claim.sub, &id, &StateChainStruct::SessionData)?
            .ok_or(SEError::DBError(NoDataForID, id.clone()))?;

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

/// Initiliase transfer protocol
///     - Authorisation of Owner and DoS protection
///     - Validate transfer parameters
///     - Store transfer parameters
#[post("/transfer/sender", format = "json", data = "<transfer_msg1>")]
pub fn transfer_sender(
    state: State<Config>,
    claim: Claims,
    transfer_msg1: Json<TransferMsg1>,
) -> Result<Json<TransferMsg2>> {
    // auth user
    check_user_auth(&state, &claim, &transfer_msg1.shared_key_id)?;

    // Verification/PoW/authoriation failed
    // Err(SEError::AuthError)

    // get state_chain id
    let session_data: SessionData =
        db::get(&state.db, &claim.sub, &transfer_msg1.shared_key_id, &StateChainStruct::SessionData)?
            .ok_or(SEError::DBError(NoDataForID, transfer_msg1.shared_key_id.clone()))?;

    // Generate x1
    let x1: FE = ECScalar::new_random();

    // create TransferData DB entry
    db::insert(
        &state.db,
        &claim.sub,
        &transfer_msg1.shared_key_id,
        &StateChainStruct::TransferData,
        &TransferData {
            state_chain_id: session_data.state_chain_id.clone(),
            new_state_chain: transfer_msg1.new_state_chain.clone(),
            x1
        }
    )?;

    // TODO encrypt x1 with Senders proof key
    Ok(Json(TransferMsg2{x1}))
}

/// Transfer shared wallet to new Owner
///     - check new Owner's state chain is correct
///     - perform 2P-ECDSA key rotation
///     - return new public shared key S2
#[post("/transfer/receiver", format = "json", data = "<transfer_msg4>")]
pub fn transfer_receiver(
    state: State<Config>,
    claim: Claims,
    transfer_msg4: Json<TransferMsg4>,
) -> Result<Json<TransferMsg5>> {
    let id = transfer_msg4.shared_key_id.clone();
    // Get TransferData for shared_key_id
    let transfer_data: TransferData =
        db::get(&state.db, &claim.sub, &id, &StateChainStruct::TransferData)?
            .ok_or(SEError::DBError(NoDataForID, id.clone()))?;
    let new_state_chain = transfer_data.new_state_chain;

    // ensure updated state chains are the same
    if new_state_chain != transfer_msg4.state_chain {
        debug!("Transfer protocol failed. Receiver state chain and State Entity state chain do not match.");
        return Err(SEError::Generic(format!("State chain provided does not match state chain at id {}",transfer_data.state_chain_id)));
    }

    // Get Party1 (State Entity) private share
    let party_1_private: Party1Private = db::get(&state.db, &claim.sub, &id, &ecdsa::EcdsaStruct::Party1Private)?
    .ok_or(SEError::DBError(NoDataForID, id.clone()))?;
    // Get Party2 (Owner 1) public share
    let party_2_public: GE = db::get(&state.db, &claim.sub, &id, &ecdsa::EcdsaStruct::Party2Public)?
        .ok_or(SEError::DBError(NoDataForID, id.clone()))?;

    // decrypt t2

    let x1 = transfer_data.x1;
    let t2 = transfer_msg4.t2;
    let s1 = party_1_private.get_private_key();

    // s2 = o1*o2_inv*s1
    // t2 = o1*x1*o2_inv
    let s2 = t2 * (x1.invert()) * s1;

    // check s2 is valid for Lindell protocol (s2<q/3)
    let sk_bigint = s2.to_big_int();
    let q_third = FE::q();
    if sk_bigint >= q_third.div_floor(&BigInt::from(3)) {
        return Err(SEError::Generic(format!("Invalid o2, try again.")));
    }

    let g: GE = ECPoint::generator();
    let s2_pub: GE = g * s2;

    let p1_pub = party_2_public * s1;
    let p2_pub = transfer_msg4.o2_pub * s2;

    // check P1 = o1_pub*s1 === p2 = o2_pub*s2
    if p1_pub != p2_pub {
        debug!("Transfer protocol failed. P1 != P2.");
        return Err(SEError::Generic(String::from("Transfer protocol error: P1 != P2")));
    }

    // create new UserSession to allow new owner to generate shared wallet
    let new_shared_key_id = Uuid::new_v4().to_string();
    db::insert(
        &state.db,
        &claim.sub,
        &new_shared_key_id,
        &StateChainStruct::UserSession,
        &UserSession {
            id: new_shared_key_id.clone(),
            proof_key: new_state_chain.last().unwrap().clone(),
            s2: Some(s2)
        }
    )?;

    // update state chain
    let mut state_chain: StateChain =
        db::get(&state.db, &claim.sub, &transfer_data.state_chain_id, &StateChainStruct::StateChain)?
            .ok_or(SEError::DBError(NoDataForID, transfer_data.state_chain_id.clone()))?;

    assert_eq!(state_chain.chain.len(), new_state_chain.len()-1);
    assert!(state_chain.backup_tx.is_some());
    state_chain.chain = new_state_chain;

    db::insert(
        &state.db,
        &claim.sub,
        &transfer_data.state_chain_id,
        &StateChainStruct::StateChain,
        &state_chain
    )?;

    Ok(Json(
        TransferMsg5 {
            new_shared_key_id,
            s2_pub,
        }
    ))
}
