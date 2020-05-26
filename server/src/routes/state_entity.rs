//! state_entity
//!
//! State Entity implementation

use super::super::Result;
extern crate shared_lib;

use shared_lib::util::rebuild_backup_tx;
use shared_lib::Root;
use shared_lib::structs::*;
use shared_lib::state_chain::StateChainSig;

use crate::error::{SEError,DBErrorType::NoDataForID};
use crate::routes::ecdsa;
use crate::storage::db::{get_root, get_current_root};
use super::super::auth::jwt::Claims;
use super::super::storage::db;
use super::super::Config;
use super::super::state_chain::{update_statechain_smt,gen_proof_smt, StateChain};

use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one::Party1Private;

use bitcoin::Transaction;
use bitcoin::hashes::sha256d;

use curv::elliptic::curves::traits::{ ECScalar,ECPoint };
use curv::{BigInt,FE,GE};
use monotree::Proof;
use rocket_contrib::json::Json;
use rocket::State;
use uuid::Uuid;

/// User ID
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct UserSession {
    /// User's identification
    pub id: String,
    /// User's password
    // pub pass: String
    /// User's authorisation
    pub auth: String,
    /// If transfer() then SE must know s2 value to create shared wallet
    pub s2: Option<FE>
}
/// User Session Data
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SessionData {
    /// users proof key
    pub proof_key: String,
    /// back up tx's sig hash
    pub sig_hash: sha256d::Hash,
    /// back up tx
    pub backup_tx: Transaction,
    /// ID of state chain that data is for
    pub state_chain_id: String
}

/// TransferData provides new Owner's data for UserSession and SessionData structs
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct TransferData {
    pub state_chain_id: String,
    pub state_chain_sig: StateChainSig,
    pub x1: FE
}

#[derive(Debug)]
pub enum StateEntityStruct {
    UserSession,
    SessionData,

    StateChain,

    TransferData
}

impl db::MPCStruct for StateEntityStruct {
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
        &StateEntityStruct::UserSession).unwrap()
    .ok_or(SEError::AuthError)
}

/// Api call for statechain info: return funding txid and state chain list of proof keys and signatures
#[post("/api/statechain/<state_chain_id>", format = "json")]
pub fn get_statechain(
    state: State<Config>,
    claim: Claims,
    state_chain_id: String,
) -> Result<Json<StateChainDataAPI>> {
    let state_chain: StateChain =
        db::get(&state.db, &claim.sub, &state_chain_id, &StateEntityStruct::StateChain)?
            .ok_or(SEError::DBError(NoDataForID, state_chain_id.clone()))?;
    Ok(Json({
        StateChainDataAPI {
            funding_txid: state_chain.backup_tx.unwrap().input.get(0).unwrap().previous_output.txid.to_string(),
            chain: state_chain.chain
        }
    }))
}

/// Api call for generating sparse merkle tree inclusion proof for some key in a tree with some root
#[post("/api/proof", format = "json", data = "<smt_proof_msg>")]
pub fn get_smt_proof(
    state: State<Config>,
    smt_proof_msg: Json<SmtProofMsgAPI>,
) -> Result<Json<Option<Proof>>> {
    // ensure root exists
    if get_root::<[u8;32]>(&state.db, &smt_proof_msg.root.id)?.is_none() {
        return Err(SEError::DBError(NoDataForID, format!("Root id: {}",smt_proof_msg.root.id.to_string())));
    }

    Ok(Json(gen_proof_smt(&smt_proof_msg.root.value, &smt_proof_msg.funding_txid)?))
}

/// Get root as API for now. Will be via Mainstay in the future.
#[post("/api/root", format = "json")]
pub fn get_smt_root(
    state: State<Config>,
) -> Result<Json<Root>> {
    Ok(Json(get_current_root::<Root>(&state.db)?))
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
    let (tx_b, sig_hash) = rebuild_backup_tx(&prepare_sign_msg)?;


    // if deposit()
    if prepare_sign_msg.transfer == false {
        if prepare_sign_msg.proof_key.is_none() {
            return Err(SEError::Generic(String::from("No proof key provided")));
        }
        let proof_key = prepare_sign_msg.proof_key.as_ref().unwrap().clone();

        // create StateChain and store
        let state_chain = StateChain::new(&proof_key);

        db::insert(
            &state.db,
            &claim.sub,
            &state_chain.id,
            &StateEntityStruct::StateChain,
            &state_chain
        )?;

        // store SessionData for user: sig_hash with back up tx and state chain id
        db::insert(
            &state.db,
            &claim.sub,
            &id,
            &StateEntityStruct::SessionData,
            &SessionData {
                proof_key: proof_key.clone(),
                sig_hash: sig_hash.clone(),
                backup_tx: tx_b.clone(),
                state_chain_id: state_chain.id.clone()
            }
        )?;

        // update sparse merkle tree with new StateChain entry
        let sc_smt_proof = update_statechain_smt(&state.db, &prepare_sign_msg.input_txid, &proof_key);
        debug!("deposit: added to statechain and sparse merkle tree. proof: {:?}", sc_smt_proof);

        return Ok(Json(state_chain.id));
    };

    // if transfer() get and update SessionData for this user
    let mut session_data: SessionData =
        db::get(&state.db, &claim.sub, &id, &StateEntityStruct::SessionData)?
            .ok_or(SEError::DBError(NoDataForID, id.clone()))?;

    session_data.sig_hash = sig_hash;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &StateEntityStruct::SessionData,
        &session_data
    )?;

    Ok(Json(String::from("")))
}


/// Initiliase deposit protocol
///     - Generate and return shared wallet ID
///     - Can do auth or other DoS mitigation here
///     - Input
#[post("/deposit/init", format = "json", data = "<deposit_msg1>")]
pub fn deposit_init(
    state: State<Config>,
    claim: Claims,
    deposit_msg1: Json<DepositMsg1>,
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
        &StateEntityStruct::UserSession,
        &UserSession {
            id: user_id.clone(),
            auth: deposit_msg1.auth.clone(),
            s2: None
        }
    )?;
    Ok(Json(user_id))
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
        db::get(&state.db, &claim.sub, &transfer_msg1.shared_key_id, &StateEntityStruct::SessionData)?
            .ok_or(SEError::DBError(NoDataForID, transfer_msg1.shared_key_id.clone()))?;

    // TODO: verify funding tx confirmation

    // Generate x1
    let x1: FE = ECScalar::new_random();

    // create TransferData DB entry
    db::insert(
        &state.db,
        &claim.sub,
        &transfer_msg1.shared_key_id,
        &StateEntityStruct::TransferData,
        &TransferData {
            state_chain_id: session_data.state_chain_id.clone(),
            state_chain_sig: transfer_msg1.state_chain_sig.clone(),
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
        db::get(&state.db, &claim.sub, &id, &StateEntityStruct::TransferData)?
            .ok_or(SEError::DBError(NoDataForID, id.clone()))?;
    let state_chain_sig = transfer_data.state_chain_sig;

    // ensure state_chain_sigs are the same
    if state_chain_sig != transfer_msg4.state_chain_sig {
        debug!("Transfer protocol failed. Receiver state chain siganture and State Entity state chain siganture do not match.");
        return Err(SEError::Generic(format!("State chain siganture provided does not match state chain at id {}",transfer_data.state_chain_id)));
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
        &StateEntityStruct::UserSession,
        &UserSession {
            id: new_shared_key_id.clone(),
            auth: String::from("auth"),
            s2: Some(s2)
        }
    )?;

    // update state chain
    let mut state_chain: StateChain =
        db::get(&state.db, &claim.sub, &transfer_data.state_chain_id, &StateEntityStruct::StateChain)?
            .ok_or(SEError::DBError(NoDataForID, transfer_data.state_chain_id.clone()))?;

    assert!(state_chain.backup_tx.is_some());
    state_chain.add(state_chain_sig)?;

    db::insert(
        &state.db,
        &claim.sub,
        &transfer_data.state_chain_id,
        &StateEntityStruct::StateChain,
        &state_chain
    )?;

    // update sparse merkle tree with new StateChain entry
    let funding_txid = state_chain.backup_tx.unwrap().input.get(0).unwrap().previous_output.txid.to_string();
    let proof_key = state_chain.chain.last()
        .ok_or(SEError::Generic(String::from("StateChain empty")))?
        .proof_key.clone();
    let sc_smt_proof = update_statechain_smt(&state.db, &funding_txid, &proof_key);
    debug!("transfer: added to statechain. proof: {:?}", sc_smt_proof);

    Ok(Json(
        TransferMsg5 {
            new_shared_key_id,
            s2_pub,
        }
    ))
}
