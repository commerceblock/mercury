//! StateEntity Utils
//!
//! StateEntity protocol utilities. DB structs, info api calls and other miscellaneous functions

use super::super::{{Result,Config},
    auth::jwt::Claims,
    storage::db};
extern crate shared_lib;
use shared_lib::{
    util::{tx_backup_verify, get_sighash, tx_withdraw_verify},
    structs::*,
    state_chain::*,
    Root};

use crate::routes::transfer::finalize_batch;
use crate::error::{SEError,DBErrorType::NoDataForID};
use crate::storage::db::{get_root, get_current_root};

use bitcoin::{Transaction,
    hashes::sha256d};

use curv::FE;
use monotree::Proof;
use rocket_contrib::json::Json;
use rocket::State;
use db::DB_SC_LOC;
use std::{collections::HashMap, time::{Duration, SystemTime}};


/// Structs for DB storage.
#[derive(Debug)]
pub enum StateEntityStruct {
    UserSession,
    StateChain, // struct def in shared_lib
    TransferData,
    TransferBatchData
}
impl db::MPCStruct for StateEntityStruct {
    fn to_string(&self) -> String {
        format!("StateChain{:?}", self)
    }
}

/// UserSession represents a User in a particular state chain session.
/// The same client co-owning 2 distinct UTXOs wth the state entity would have 2 unrelated UserSession's.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct UserSession {
    /// User's identification
    pub id: String,
    /// User's password
    // pub pass: String
    /// User's authorisation
    pub auth: String,
    /// users proof key
    pub proof_key: String,
    /// back up tx for this user session
    pub tx_backup: Option<Transaction>,
    /// withdraw tx for end of user session and end of state chain
    pub tx_withdraw: Option<Transaction>,
    /// ID of state chain that data is for
    pub state_chain_id: Option<String>,
    /// If UserSession created for transfer() then SE must know s2 value to create shared wallet
    pub s2: Option<FE>,
    /// sig hash of tx to be signed. This value is checked in co-signing to ensure that message being
    /// signed is the sig hash of a tx that SE has verified.
    /// Used when signing both backup and withdraw tx.
    pub sig_hash: Option<sha256d::Hash>,
    /// StateChain Signature for withdrawal. Presence of this data signals user has passed Authorisation
    /// for withdrawl.
    pub withdraw_sc_sig: Option<StateChainSig>
}

/// TransferData provides new Owner's data for their new UserSession struct created in transfer_receiver.
/// Key: state_chain_id
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct TransferData {
    pub state_chain_id: String,
    pub state_chain_sig: StateChainSig,
    pub x1: FE,
    pub archive: bool // Data no longer in use
}


/// TransferBatch stores list of StateChains involved in a batch transfer and their status in the potocol.
/// When all transfers in the batch are complete these transfers are finalized atomically.
#[derive(Serialize, Deserialize, Debug)]
pub struct TransferBatchData {
    pub id: String,
    pub start_time: SystemTime, // time batch transfer began
    pub state_chains: HashMap<String, bool>,
    pub finalized_data: Vec<TransferFinalizeData>,
    pub punished_state_chains: Vec<String>, // If transfer batch fails these state chain Id's were punished.
    pub finalized: bool
}

impl TransferBatchData {
    pub fn is_ended(&self, batch_lifetime: u64) -> bool {
        if SystemTime::now().duration_since(self.start_time).unwrap().as_secs() > batch_lifetime {
            return true
        }
        false
    }
}

/// Struct holds data when transfer is complete but not yet finalized
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferFinalizeData {
    pub new_shared_key_id: String,
    pub state_chain_id: String,
    pub state_chain_sig: StateChainSig,
    pub s2: FE,
    pub batch_data: Option<BatchData>,
}

/// Check if user has passed authentication.
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

// Set state chain time-out
pub fn punish_state_chain(
    state: &State<Config>,
    claim: &Claims,
    state_chain_id: String
) -> Result<()> {
    let mut state_chain: StateChain =
        db::get(&state.db, &claim.sub, &state_chain_id, &StateEntityStruct::StateChain)?
            .ok_or(SEError::DBError(NoDataForID, state_chain_id.clone()))?;

    if state_chain.is_locked().is_err() {
        return Err(SEError::Generic(String::from("State chain is already locked. This should not be possible.")));
    }

    // set punishment
    state_chain.locked_until = SystemTime::now() + Duration::from_secs(state.punishment_duration);
    db::insert(
        &state.db,
        &claim.sub,
        &state_chain_id,
        &StateEntityStruct::StateChain,
        &state_chain
    )?;

    info!("PUNISHMENT: State Chain ID: {} locked for {}s.", state_chain_id, state.punishment_duration);
    Ok(())
}

/// API: Return StateEntity fee information.
#[post("/info/fee", format = "json")]
pub fn get_state_entity_fees(
    state: State<Config>,
) -> Result<Json<StateEntityFeeInfoAPI>> {
    Ok(Json(StateEntityFeeInfoAPI {
        address: state.fee_address.clone(),
        deposit: state.fee_deposit,
        withdraw: state.fee_withdraw,
    }))
}

/// API: Return StateChain info: funding txid and state chain list of proof keys and signatures.
#[post("/info/statechain/<state_chain_id>", format = "json")]
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
            amount: state_chain.amount,
            utxo: state_chain.tx_backup.input.get(0).unwrap().previous_output,
            chain: state_chain.chain
        }
    }))
}

/// API: Generates sparse merkle tree inclusion proof for some key in a tree with some root.
#[post("/info/proof", format = "json", data = "<smt_proof_msg>")]
pub fn get_smt_proof(
    state: State<Config>,
    smt_proof_msg: Json<SmtProofMsgAPI>,
) -> Result<Json<Option<Proof>>> {
    // ensure root exists
    if get_root::<[u8;32]>(&state.db, &smt_proof_msg.root.id)?.is_none() {
        return Err(SEError::DBError(NoDataForID, format!("Root id: {}",smt_proof_msg.root.id.to_string())));
    }

    Ok(Json(gen_proof_smt(DB_SC_LOC, &smt_proof_msg.root.value, &smt_proof_msg.funding_txid)?))
}

/// API: Get root of sparse merkle tree. Will be via Mainstay in the future.
#[post("/info/root", format = "json")]
pub fn get_smt_root(
    state: State<Config>,
) -> Result<Json<Root>> {
    Ok(Json(get_current_root::<Root>(&state.db)?))
}


/// API: Return a TransferBatchData status.
/// Triggers check for all transfers complete - if so then finalize all.
/// Also triggers check for batch transfer lifetime. If passed then cancel all transfers and punish state chains.
#[post("/info/transfer-batch/<batch_id>", format = "json")]
pub fn get_transfer_batch_status(
    state: State<Config>,
    claim: Claims,
    batch_id: String,
) -> Result<Json<TransferBatchDataAPI>> {
    let mut transfer_batch_data: TransferBatchData =
        db::get(&state.db, &claim.sub, &batch_id, &StateEntityStruct::TransferBatchData)?
            .ok_or(SEError::DBError(NoDataForID, batch_id.clone()))?;

    // Check batch is still within lifetime
    if transfer_batch_data.is_ended(state.batch_lifetime) {
        if transfer_batch_data.punished_state_chains.len() == 0 { // Punishments not yet set
            info!("TRANSFER_BATCH: Lifetime reached. ID: {}.", batch_id);
            // Set punishments for all statechains involved in batch
            for (state_chain_id, _) in transfer_batch_data.state_chains {
                punish_state_chain(&state, &claim, state_chain_id.clone())?;
                transfer_batch_data.punished_state_chains.push(state_chain_id.clone());

                // Remove TransferData involved
                db::remove(&state.db, &claim.sub, &state_chain_id, &StateEntityStruct::TransferData)?;
                info!("TRANSFER_BATCH: Transfer data marked as archived. State Chain ID: {}.", state_chain_id);
            }
            info!("TRANSFER_BATCH: Punished all state chains in failed batch. ID: {}.",batch_id);
        }
        return Err(SEError::Generic(String::from("Transfer Batch ended.")))
    }

    // Check if all transfers are complete. If so then all transfers in batch can be finalized.
    if !transfer_batch_data.finalized {
        let mut state_chains_copy = transfer_batch_data.state_chains.clone();
        state_chains_copy.retain(|_, &mut v| v == false);
        if state_chains_copy.len() == 0 {
            finalize_batch(
                &state,
                &claim,
                &batch_id
            )?;
            info!("TRANSFER_BATCH: All transfers complete in batch. Finalized. ID: {}.", batch_id);
        }
    }

    // return status of transfers
    Ok(Json(TransferBatchDataAPI{
        state_chains: transfer_batch_data.state_chains,
        finalized: transfer_batch_data.finalized
    }))
}


/// Prepare to co-sign a transaction input. This is where SE checks that the tx to be signed is
/// honest and error free:
///     - Check tx data
///     - calculate and store tx sighash for validation before performing ecdsa::sign
#[post("/prepare-sign", format = "json", data = "<prepare_sign_msg>")]
pub fn prepare_sign_tx(
    state: State<Config>,
    claim: Claims,
    prepare_sign_msg: Json<PrepareSignTxMsg>,
) -> Result<Json<()>> {
    let shared_key_id = prepare_sign_msg.shared_key_id.clone();

    // Auth user
    check_user_auth(&state, &claim, &shared_key_id)?;

    let prepare_sign_msg: PrepareSignTxMsg = prepare_sign_msg.into_inner();

    // Get user session for this user
    let mut user_session: UserSession =
        db::get(&state.db, &claim.sub, &shared_key_id, &StateEntityStruct::UserSession)?
            .ok_or(SEError::DBError(NoDataForID, shared_key_id.clone()))?;

    // Which protocol are we signing for?
    match prepare_sign_msg.protocol {
        Protocol::Withdraw => {

            // Verify withdrawl has been authorised via presense of withdraw_sc_sig
            if user_session.withdraw_sc_sig.is_none() {
                return Err(SEError::Generic(String::from("Withdraw has not been authorised. /withdraw/init must be called first.")));
            }

            // Verify unsigned withdraw tx to ensure co-sign will be signing the correct data
            tx_withdraw_verify(&prepare_sign_msg, &state.fee_address, &state.fee_withdraw)?;

            // Check funding txid UTXO info
            let state_chain_id = user_session.state_chain_id.clone() // check exists
                .ok_or(SEError::Generic(String::from("No state chain session found for this user.")))?;
            let state_chain: StateChain =
                db::get(&state.db, &claim.sub, &state_chain_id, &StateEntityStruct::StateChain)?
                    .ok_or(SEError::DBError(NoDataForID, state_chain_id.clone()))?;
            let tx_backup_input = state_chain.tx_backup.input.get(0).unwrap().previous_output.to_owned();
            if prepare_sign_msg.tx.input.get(0).unwrap().previous_output.to_owned() != tx_backup_input {
                return Err(SEError::Generic(String::from("Incorrect withdraw transacton input.")));
            }

            // Update UserSession with withdraw tx info
            let sig_hash = get_sighash(
                &prepare_sign_msg.tx,
                &0,
                &prepare_sign_msg.input_addrs[0],
                &prepare_sign_msg.input_amounts[0],
                &state.network
            );

            user_session.sig_hash = Some(sig_hash);
            user_session.tx_withdraw = Some(prepare_sign_msg.tx);

            db::insert(
                &state.db,
                &claim.sub,
                &shared_key_id,
                &StateEntityStruct::UserSession,
                &user_session
            )?;

            info!("WITHDRAW: Withdraw tx ready for signing. Shared Key ID: {}. State Chain ID: {}.",shared_key_id, state_chain_id);
        }
        _ => {
            // Verify unsigned backup tx to ensure co-sign will be signing the correct data
            tx_backup_verify(&prepare_sign_msg)?;

            let sig_hash = get_sighash(
                &prepare_sign_msg.tx,
                &0,
                &prepare_sign_msg.input_addrs[0],
                &prepare_sign_msg.input_amounts[0],
                &state.network
            );

            user_session.sig_hash = Some(sig_hash.clone());
            // Only in deposit case add backup tx to UserSession
            if prepare_sign_msg.protocol == Protocol::Deposit {
                user_session.tx_backup = Some(prepare_sign_msg.tx.clone());
            }

            info!("DEPOSIT: Backup tx ready for signing. Shared Key ID: {}.", shared_key_id);
        }
    }

    // Update DB UserSession object
    db::insert(
        &state.db,
        &claim.sub,
        &shared_key_id,
        &StateEntityStruct::UserSession,
        &user_session
    )?;

    Ok(Json(()))
}
