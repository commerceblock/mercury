//! StateEntity Utils
//!
//! StateEntity protocol utilities. DB structs, info api calls and other miscellaneous functions

use super::super::{{Result,Config},
    storage::db};
extern crate shared_lib;
use shared_lib::{
    util::{tx_backup_verify, get_sighash, tx_withdraw_verify},
    structs::*,
    state_chain::*,
    Root};

use crate::routes::transfer::finalize_batch;
use crate::error::SEError;
use crate::storage::{
    db_postgres::{Table, Column, db_remove, db_deser, db_ser, db_update, db_get_1, db_get_3, db_get_2},
    db::{get_root, get_current_root}};
use crate::DataBase;

use bitcoin::{Transaction,
    hashes::sha256d};

use curv::FE;
use monotree::Proof;
use rocket_contrib::json::Json;
use rocket::State;
use db::DB_SC_LOC;
use std::{collections::HashMap, time::SystemTime, str::FromStr};
use uuid::Uuid;
use chrono::{Utc,NaiveDateTime};


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
    pub state_chain_id: Uuid,
    pub state_chain_sig: StateChainSig,
    pub x1: FE,
}


/// TransferBatch stores list of StateChains involved in a batch transfer and their status in the potocol.
/// When all transfers in the batch are complete these transfers are finalized atomically.
#[derive(Serialize, Deserialize, Debug)]
pub struct TransferBatchData {
    pub id: Uuid,
    pub start_time: SystemTime, // time batch transfer began
    pub state_chains: HashMap<Uuid, bool>,
    pub finalized_data: Vec<TransferFinalizeData>,
    pub punished_state_chains: Vec<Uuid>, // If transfer batch fails these state chain Id's were punished.
    pub finalized: bool
}

/// Check if Transfer Batch is out of time
pub fn transfer_batch_is_ended(start_time: NaiveDateTime, batch_lifetime: i64) -> bool {
    let current_time = Utc::now().naive_utc().timestamp();

    if current_time - start_time.timestamp() > batch_lifetime {
        return true
    }
    false
}

/// Struct holds data when transfer is complete but not yet finalized
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferFinalizeData {
    pub new_shared_key_id: Uuid,
    pub state_chain_id: Uuid,
    pub state_chain_sig: StateChainSig,
    pub s2: FE,
    pub new_tx_backup: Transaction,
    pub batch_data: Option<BatchData>,
}

/// Check if user has passed authentication.
pub fn check_user_auth(
    conn: &DataBase,
    user_id: &Uuid
) -> Result<()> {
    // check authorisation id is in DB (and check password?)
    if let Err(_) = db_get_1::<Uuid>(&conn, &user_id, Table::UserSession, vec!(Column::Id)) {
        return Err(SEError::AuthError)
    }
    Ok(())
}

// Set state chain time-out
pub fn state_chain_punish(
    state: &State<Config>,
    conn: &DataBase,
    state_chain_id: Uuid
) -> Result<()> {
    let (sc_locked_until) =
            db_get_1::<NaiveDateTime>(&conn, &state_chain_id, Table::StateChain,
            vec!(Column::LockedUntil))?;

    if is_locked(sc_locked_until).is_err() {
        return Err(SEError::Generic(String::from("State chain is already locked. This should not be possible.")));
    }

    db_update(&conn, &state_chain_id, Table::StateChain,
        vec!(Column::LockedUntil),
        vec!(&get_locked_until(state.punishment_duration as i64)?))?;

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
    conn: DataBase,
    state_chain_id: String,
) -> Result<Json<StateChainDataAPI>> {
    let state_chain_id = Uuid::from_str(&state_chain_id).unwrap();

    let (amount,
        state_chain_str) =
            db_get_2::<i64,String>(&conn, &state_chain_id, Table::StateChain,
            vec!(Column::Amount, Column::Chain))?;
    let state_chain: StateChain = db_deser(state_chain_str)?;

    let (tx_backup_str) = db_get_1::<String>(&conn, &state_chain_id, Table::BackupTxs,vec!(Column::TxBackup))?;
    let tx_backup: Transaction = db_deser(tx_backup_str)?;

    Ok(Json({
        StateChainDataAPI {
            amount: amount as u64,
            utxo: tx_backup.input.get(0).unwrap().previous_output,
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
        return Err(SEError::Generic(format!("DB Error: Could not find root. Root id: {}",smt_proof_msg.root.id.to_string())));
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
    conn: DataBase,
    batch_id: String,
) -> Result<Json<TransferBatchDataAPI>> {
    let batch_id = Uuid::from_str(&batch_id).unwrap();

    let (state_chains_str,start_time, finalized) =
        db_get_3::<String,NaiveDateTime,bool>(&conn, &batch_id, Table::TransferBatch,
            vec!(Column::StateChains, Column::StartTime, Column::Finalized))?;
    let state_chains: HashMap<Uuid, bool> = db_deser(state_chains_str)?;

    // Check if all transfers are complete. If so then all transfers in batch can be finalized.
    if !finalized {
        let mut state_chains_copy = state_chains.clone();
        state_chains_copy.retain(|_, &mut v| v == false);
        if state_chains_copy.len() == 0 {
            finalize_batch(
                &state,
                &conn,
                batch_id
            )?;
            info!("TRANSFER_BATCH: All transfers complete in batch. Finalized. ID: {}.", batch_id);
        }
        // Check batch is still within lifetime
        if transfer_batch_is_ended(start_time, state.batch_lifetime as i64) {
            let mut punished_state_chains: Vec<Uuid> =
                db_deser(db_get_1(&conn, &batch_id, Table::TransferBatch, vec!(Column::PunishedStateChains))?)?;

            if punished_state_chains.len() == 0 { // Punishments not yet set
                info!("TRANSFER_BATCH: Lifetime reached. ID: {}.", batch_id);
                // Set punishments for all statechains involved in batch
                for (state_chain_id, _) in state_chains {
                    state_chain_punish(&state, &conn, state_chain_id.clone())?;
                    punished_state_chains.push(state_chain_id.clone());

                    // Remove TransferData involved. Ignore failed update err since Transfer data may not exist.
                    let _ = db_remove(&conn, &state_chain_id, Table::Transfer);

                    info!("TRANSFER_BATCH: Transfer data deleted. State Chain ID: {}.", state_chain_id);
                }

                db_update(&conn, &batch_id, Table::TransferBatch,
                    vec!(Column::PunishedStateChains),
                    vec!(&db_ser(punished_state_chains)?))?;

                info!("TRANSFER_BATCH: Punished all state chains in failed batch. ID: {}.",batch_id);
            }
            return Err(SEError::Generic(String::from("Transfer Batch ended.")))
        }
    }

    // return status of transfers
    Ok(Json(TransferBatchDataAPI{
        state_chains,
        finalized
    }))
}


/// Prepare to co-sign a transaction input. This is where SE checks that the tx to be signed is
/// honest and error free:
///     - Check tx data
///     - Calculate and store tx sighash for validation before performing ecdsa::sign
#[post("/prepare-sign", format = "json", data = "<prepare_sign_msg>")]
pub fn prepare_sign_tx(
    state: State<Config>,
    conn: DataBase,
    prepare_sign_msg: Json<PrepareSignTxMsg>,
) -> Result<Json<()>> {
    let user_id = prepare_sign_msg.shared_key_id;
    check_user_auth(&conn, &user_id)?;

    let prepare_sign_msg: PrepareSignTxMsg = prepare_sign_msg.into_inner();

    // Which protocol are we signing for?
    match prepare_sign_msg.protocol {
        Protocol::Withdraw => {

            // Verify withdrawal has been authorised via presense of withdraw_sc_sig
            if let Err(_) = db_get_1::<String>(&conn, &user_id, Table::UserSession, vec!(Column::WithdrawScSig)) {
                return Err(SEError::Generic(String::from("Withdraw has not been authorised. /withdraw/init must be called first.")))
            }

            // Verify unsigned withdraw tx to ensure co-sign will be signing the correct data
            tx_withdraw_verify(&prepare_sign_msg, &state.fee_address, &state.fee_withdraw)?;

            let (tx_backup_str) =
                db_get_1::<String>(&conn, &user_id, Table::UserSession, vec!(Column::TxBackup))?;
            let tx_backup: Transaction = db_deser(tx_backup_str)?;

            // Check funding txid UTXO info
            let tx_backup_input = tx_backup.input.get(0).unwrap().previous_output.to_owned();
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

            db_update(&conn, &user_id, Table::UserSession,
                vec!(Column::SigHash, Column::TxWithdraw),
                vec!(&db_ser(sig_hash)?, &db_ser(prepare_sign_msg.tx)?))?;

            info!("WITHDRAW: Withdraw tx ready for signing. User ID: {:?}.",user_id);
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

            db_update(&conn, &user_id, Table::UserSession,
                vec!(Column::SigHash),vec!(&db_ser(sig_hash)?))?;

            // Only in deposit case add backup tx to UserSession
            if prepare_sign_msg.protocol == Protocol::Deposit {
                db_update(&conn, &user_id, Table::UserSession,
                    vec!(Column::TxBackup),vec!(&db_ser(prepare_sign_msg.tx)?))?;
            }

            info!("DEPOSIT: Backup tx ready for signing. Shared Key ID: {}.", user_id);
        }
    }

    Ok(Json(()))
}
