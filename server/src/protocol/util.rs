//! StateEntity Utilities
//!
//! StateChain Entity protocol Utilites API calls trait and implementat. Also other non-trait
//! utility functions.

use super::{
    super::Result,
    transfer_batch::{transfer_batch_is_ended, BatchTransfer},
};
extern crate shared_lib;
use shared_lib::{
    mocks::mock_electrum::MockElectrum,
    state_chain::*,
    structs::*,
    util::{get_sighash, tx_backup_verify, tx_withdraw_verify},
    Root,
};

use crate::error::{DBErrorType, SEError};
use crate::storage::db::{
    self, db_deser, db_get_1, db_get_2, db_get_3, db_remove, db_root_get, db_root_get_current_id,
    db_ser, db_update, Column, Table,
};
use crate::{DatabaseR, DatabaseW, server::StateChainEntity};

use bitcoin::Transaction;
use chrono::NaiveDateTime;
use db::root_update;
use electrumx_client::{electrumx_client::ElectrumxClient, interface::Electrumx};
use monotree::Proof;
use rocket::State;
use rocket_contrib::json::Json;
use std::{collections::HashMap, str::FromStr};
use std::{thread, time::Duration};
use uuid::Uuid;

/// StateChain Entity Utilities API calls. Includes Information GET requests and prepare_sign_tx which
/// is used in all Protocols
pub trait Utilities {
    /// API: Return StateChain Entity fee information.
    fn get_fees(&self) -> Result<StateEntityFeeInfoAPI>;

    /// API: Return StateChain info: funding txid and state chain list of proof keys and signatures.
    fn get_statechain(
        &self,
        db_read: DatabaseR,
        state_chain_id: String,
    ) -> Result<StateChainDataAPI>;

    /// API: Generates sparse merkle tree inclusion proof for some key in a tree with some root.
    fn get_smt_proof(
        &self,
        db_read: DatabaseR,
        smt_proof_msg: SmtProofMsgAPI,
    ) -> Result<Option<Proof>>;

    /// API: Get root of sparse merkle tree. Will be via Mainstay in the future.
    fn get_smt_root(&self, db_read: DatabaseR) -> Result<Option<Root>>;

    /// API: Get root of sparse merkle tree. Will be via Mainstay in the future.
    fn get_confirmed_smt_root(
        &self,
        db_read: DatabaseR,
        db_write: DatabaseW,
    ) -> Result<Option<Root>>;

    /// API: Return a TransferBatchData status.
    /// Triggers check for all transfers complete - if so then finalize all.
    /// Also triggers check for batch transfer lifetime. If passed then cancel all transfers and punish state chains.
    fn get_transfer_batch_status(
        &self,
        db_read: DatabaseR,
        db_write: DatabaseW,
        batch_id: String,
    ) -> Result<TransferBatchDataAPI>;

    /// API: Prepare to co-sign a transaction input. This is where SE checks that the tx to be signed is
    /// honest and error free:
    ///     - Check tx data
    ///     - Calculate and store tx sighash for validation before performing ecdsa::sign
    fn prepare_sign_tx(
        &self,
        db_read: DatabaseR,
        db_write: DatabaseW,
        prepare_sign_msg: PrepareSignTxMsg,
    ) -> Result<()>;
}

impl Utilities for StateChainEntity {
    fn get_fees(&self) -> Result<StateEntityFeeInfoAPI> {
        Ok(StateEntityFeeInfoAPI {
            address: self.config.fee_address.clone(),
            deposit: self.config.fee_deposit,
            withdraw: self.config.fee_withdraw,
        })
    }

    fn get_statechain(
        &self,
        db_read: DatabaseR,
        state_chain_id: String,
    ) -> Result<StateChainDataAPI> {
        let state_chain_id = Uuid::from_str(&state_chain_id).unwrap();

        let (amount, state_chain_str) = db_get_2::<i64, String>(
            &db_read,
            &state_chain_id,
            Table::StateChain,
            vec![Column::Amount, Column::Chain],
        )?;
        let state_chain: StateChain = db_deser(state_chain_str)?;

        let (tx_backup_str) = db_get_1::<String>(
            &db_read,
            &state_chain_id,
            Table::BackupTxs,
            vec![Column::TxBackup],
        )?;
        let tx_backup: Transaction = db_deser(tx_backup_str)?;

        Ok({
            StateChainDataAPI {
                amount: amount as u64,
                utxo: tx_backup.input.get(0).unwrap().previous_output,
                chain: state_chain.chain,
            }
        })
    }

    fn get_smt_proof(
        &self,
        db_read: DatabaseR,
        smt_proof_msg: SmtProofMsgAPI,
    ) -> Result<Option<Proof>> {
        // ensure root exists
        match &smt_proof_msg.root.id() {
            Some(id) => {
                if db_root_get(&db_read, &(id.clone() as i64))?.is_none() {
                    return Err(SEError::DBError(
                        DBErrorType::NoDataForID,
                        format!("Root id: {:?}", id),
                    ));
                }
            }
            None => {
                return Err(SEError::DBError(
                    DBErrorType::NoDataForID,
                    format!("Root does not have an id: {:?}", smt_proof_msg.root),
                ));
            }
        }

        Ok(gen_proof_smt(
            &self.config.smt_db_loc,
            &Some(smt_proof_msg.root.hash()),
            &smt_proof_msg.funding_txid,
        )?)
    }

    fn get_smt_root(&self, db_read: DatabaseR) -> Result<Option<Root>> {
        Ok(db_root_get(&db_read, &db_root_get_current_id(&db_read)?)?)
    }

    fn get_confirmed_smt_root(
        &self,
        db_read: DatabaseR,
        db_write: DatabaseW,
    ) -> Result<Option<Root>> {
        Ok(db::get_confirmed_root(
            &db_read,
            &db_write,
            &self.config.mainstay,
        )?)
    }

    fn get_transfer_batch_status(
        &self,
        db_read: DatabaseR,
        db_write: DatabaseW,
        batch_id: String,
    ) -> Result<TransferBatchDataAPI> {
        let batch_id = Uuid::from_str(&batch_id).unwrap();

        let (state_chains_str, start_time, finalized) = db_get_3::<String, NaiveDateTime, bool>(
            &db_read,
            &batch_id,
            Table::TransferBatch,
            vec![Column::StateChains, Column::StartTime, Column::Finalized],
        )?;
        let state_chains: HashMap<Uuid, bool> = db_deser(state_chains_str)?;

        // Check if all transfers are complete. If so then all transfers in batch can be finalized.
        if !finalized {
            let mut state_chains_copy = state_chains.clone();
            state_chains_copy.retain(|_, &mut v| v == false);
            if state_chains_copy.len() == 0 {
                self.finalize_batch(&db_read, &db_write, batch_id)?;
                info!(
                    "TRANSFER_BATCH: All transfers complete in batch. Finalized. ID: {}.",
                    batch_id
                );
            }
            // Check batch is still within lifetime
            if transfer_batch_is_ended(start_time, self.config.batch_lifetime as i64) {
                let mut punished_state_chains: Vec<Uuid> = db_deser(db_get_1(
                    &db_read,
                    &batch_id,
                    Table::TransferBatch,
                    vec![Column::PunishedStateChains],
                )?)?;

                if punished_state_chains.len() == 0 {
                    // Punishments not yet set
                    info!("TRANSFER_BATCH: Lifetime reached. ID: {}.", batch_id);
                    // Set punishments for all statechains involved in batch
                    for (state_chain_id, _) in state_chains {
                        self.state_chain_punish(&db_read, &db_write, state_chain_id.clone())?;
                        punished_state_chains.push(state_chain_id.clone());

                        // Remove TransferData involved. Ignore failed update err since Transfer data may not exist.
                        let _ = db_remove(&db_write, &state_chain_id, Table::Transfer);

                        info!(
                            "TRANSFER_BATCH: Transfer data deleted. State Chain ID: {}.",
                            state_chain_id
                        );
                    }

                    db_update(
                        &db_write,
                        &batch_id,
                        Table::TransferBatch,
                        vec![Column::PunishedStateChains],
                        vec![&db_ser(punished_state_chains)?],
                    )?;

                    info!(
                        "TRANSFER_BATCH: Punished all state chains in failed batch. ID: {}.",
                        batch_id
                    );
                }
                return Err(SEError::Generic(String::from("Transfer Batch ended.")));
            }
        }

        // return status of transfers
        Ok(TransferBatchDataAPI {
            state_chains,
            finalized,
        })
    }

    fn prepare_sign_tx(
        &self,
        db_read: DatabaseR,
        db_write: DatabaseW,
        prepare_sign_msg: PrepareSignTxMsg,
    ) -> Result<()> {
        let user_id = prepare_sign_msg.shared_key_id;
        self.check_user_auth(&db_read, &user_id)?;

        // Which protocol are we signing for?
        match prepare_sign_msg.protocol {
            Protocol::Withdraw => {
                // Verify withdrawal has been authorised via presense of withdraw_sc_sig
                if let Err(_) = db_get_1::<String>(
                    &db_read,
                    &user_id,
                    Table::UserSession,
                    vec![Column::WithdrawScSig],
                ) {
                    return Err(SEError::Generic(String::from(
                        "Withdraw has not been authorised. /withdraw/init must be called first.",
                    )));
                }

                // Verify unsigned withdraw tx to ensure co-sign will be signing the correct data
                tx_withdraw_verify(&prepare_sign_msg, &self.config.fee_address, &self.config.fee_withdraw)?;

                let (tx_backup_str) = db_get_1::<String>(
                    &db_read,
                    &user_id,
                    Table::UserSession,
                    vec![Column::TxBackup],
                )?;
                let tx_backup: Transaction = db_deser(tx_backup_str)?;

                // Check funding txid UTXO info
                let tx_backup_input = tx_backup.input.get(0).unwrap().previous_output.to_owned();
                if prepare_sign_msg
                    .tx
                    .input
                    .get(0)
                    .unwrap()
                    .previous_output
                    .to_owned()
                    != tx_backup_input
                {
                    return Err(SEError::Generic(String::from(
                        "Incorrect withdraw transacton input.",
                    )));
                }

                // Update UserSession with withdraw tx info
                let sig_hash = get_sighash(
                    &prepare_sign_msg.tx,
                    &0,
                    &prepare_sign_msg.input_addrs[0],
                    &prepare_sign_msg.input_amounts[0],
                    &self.config.network,
                );

                db_update(
                    &db_write,
                    &user_id,
                    Table::UserSession,
                    vec![Column::SigHash, Column::TxWithdraw],
                    vec![&db_ser(sig_hash)?, &db_ser(prepare_sign_msg.tx)?],
                )?;

                info!(
                    "WITHDRAW: Withdraw tx ready for signing. User ID: {:?}.",
                    user_id
                );
            }
            _ => {
                // Verify unsigned backup tx to ensure co-sign will be signing the correct data
                tx_backup_verify(&prepare_sign_msg)?;

                let sig_hash = get_sighash(
                    &prepare_sign_msg.tx,
                    &0,
                    &prepare_sign_msg.input_addrs[0],
                    &prepare_sign_msg.input_amounts[0],
                    &self.config.network,
                );

                db_update(
                    &db_write,
                    &user_id,
                    Table::UserSession,
                    vec![Column::SigHash],
                    vec![&db_ser(sig_hash)?],
                )?;

                // Only in deposit case add backup tx to UserSession
                if prepare_sign_msg.protocol == Protocol::Deposit {
                    db_update(
                        &db_write,
                        &user_id,
                        Table::UserSession,
                        vec![Column::TxBackup],
                        vec![&db_ser(prepare_sign_msg.tx)?],
                    )?;
                }

                info!(
                    "DEPOSIT: Backup tx ready for signing. Shared Key ID: {}.",
                    user_id
                );
            }
        }

        Ok(())
    }
}

#[get("/info/fee", format = "json")]
pub fn get_fees(sc_entity: State<StateChainEntity>) -> Result<Json<StateEntityFeeInfoAPI>> {
    match sc_entity.get_fees() {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[get("/info/statechain/<state_chain_id>", format = "json")]
pub fn get_statechain(
    sc_entity: State<StateChainEntity>,
    db_read: DatabaseR,
    state_chain_id: String,
) -> Result<Json<StateChainDataAPI>> {
    match sc_entity.get_statechain(db_read, state_chain_id) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[get("/info/root", format = "json")]
pub fn get_smt_root(
    sc_entity: State<StateChainEntity>,
    db_read: DatabaseR,
) -> Result<Json<Option<Root>>> {
    match sc_entity.get_smt_root(db_read) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[get("/info/confirmed_root", format = "json")]
pub fn get_confirmed_smt_root(
    sc_entity: State<StateChainEntity>,
    db_read: DatabaseR,
    db_write: DatabaseW,
) -> Result<Json<Option<Root>>> {
    match sc_entity.get_confirmed_smt_root(db_read, db_write) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/info/proof", format = "json", data = "<smt_proof_msg>")]
pub fn get_smt_proof(
    sc_entity: State<StateChainEntity>,
    db_read: DatabaseR,
    smt_proof_msg: Json<SmtProofMsgAPI>,
) -> Result<Json<Option<Proof>>> {
    match sc_entity.get_smt_proof(db_read, smt_proof_msg.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[get("/info/transfer-batch/<batch_id>", format = "json")]
pub fn get_transfer_batch_status(
    sc_entity: State<StateChainEntity>,
    db_read: DatabaseR,
    db_write: DatabaseW,
    batch_id: String,
) -> Result<Json<TransferBatchDataAPI>> {
    match sc_entity.get_transfer_batch_status(db_read, db_write, batch_id) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/prepare-sign", format = "json", data = "<prepare_sign_msg>")]
pub fn prepare_sign_tx(
    sc_entity: State<StateChainEntity>,
    db_read: DatabaseR,
    db_write: DatabaseW,
    prepare_sign_msg: Json<PrepareSignTxMsg>,
) -> Result<Json<()>> {
    match sc_entity.prepare_sign_tx(db_read, db_write, prepare_sign_msg.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

// Utily functions for StateChainEntity to be used throughout codebase.
impl StateChainEntity {
    /// Query an Electrum Server for a transaction's confirmation status.
    /// Return Ok() if confirmed or Error if not after some waiting period.
    pub fn verify_tx_confirmed(&self, txid: &String, sc_entity: &StateChainEntity) -> Result<()> {
        let mut electrum: Box<dyn Electrumx> = if sc_entity.config.testing_mode {
            Box::new(MockElectrum::new())
        } else {
            Box::new(ElectrumxClient::new(sc_entity.config.electrum_server.clone()).unwrap())
        };

        info!(
            "DEPOSIT: Waiting for funding transaction confirmation. Txid: {}",
            txid
        );

        let mut is_broadcast = 0; // num blocks waited for tx to be broadcast
        let mut is_mined = 0; // num blocks waited for tx to be mined
        while is_broadcast < 3 {
            // Check for tx broadcast. If not after 3*(block time) then return error.
            match electrum.get_transaction_conf_status(txid.clone(), false) {
                Ok(res) => {
                    // Check for tx confs. If none after 10*(block time) then return error.
                    if res.confirmations.is_none() {
                        is_mined += 1;
                        if is_mined > 9 {
                            warn!("Funding transaction not mined after 10 blocks. Deposit failed. Txid: {}", txid);
                            return Err(SEError::Generic(String::from("Funding transaction failure to be mined - consider increasing the fee. Deposit failed.")));
                        }
                        thread::sleep(Duration::from_millis(sc_entity.config.block_time));
                    } else {
                        // If confs increase then wait 6*(block time) and return Ok()
                        info!(
                            "Funding transaction mined. Waiting for 6 blocks confirmation. Txid: {}",
                            txid
                        );
                        thread::sleep(Duration::from_millis(6 * sc_entity.config.block_time));
                        return Ok(());
                    }
                }
                Err(_) => {
                    is_broadcast += 1;
                    thread::sleep(Duration::from_millis(sc_entity.config.block_time));
                }
            }
        }
        return Err(SEError::Generic(String::from(
            "Funding Transaction not found in blockchain. Deposit failed.",
        )));
    }

    // Set state chain time-out
    pub fn state_chain_punish(
        &self,
        db_read: &DatabaseR,
        db_write: &DatabaseW,
        state_chain_id: Uuid,
    ) -> Result<()> {
        let (sc_locked_until) = db_get_1::<NaiveDateTime>(
            &db_read,
            &state_chain_id,
            Table::StateChain,
            vec![Column::LockedUntil],
        )?;

        if is_locked(sc_locked_until).is_err() {
            return Err(SEError::Generic(String::from(
                "State chain is already locked. This should not be possible.",
            )));
        }

        db_update(
            &db_write,
            &state_chain_id,
            Table::StateChain,
            vec![Column::LockedUntil],
            vec![&get_locked_until(self.config.punishment_duration as i64)?],
        )?;

        info!(
            "PUNISHMENT: State Chain ID: {} locked for {}s.",
            state_chain_id, self.config.punishment_duration
        );
        Ok(())
    }

    /// Update SMT with new (key: value) pair and update current root value
    pub fn update_smt_db(
        &self,
        db_read: &DatabaseR,
        db_write: &DatabaseW,
        funding_txid: &String,
        proof_key: &String,
    ) -> Result<(Option<Root>, Root)> {
        let current_root = db_root_get(&db_read, &db_root_get_current_id(&db_read)?)?;
        let new_root_hash = update_statechain_smt(
            &self.config.smt_db_loc,
            &current_root.clone().map(|r| r.hash()),
            funding_txid,
            proof_key,
        )?;

        let new_root = Root::from_hash(&new_root_hash.unwrap());
        root_update(db_read, db_write, &self.config.mainstay, &new_root)?; // Update current root

        Ok((current_root, new_root))
    }

    /// Check if user has passed authentication.
    pub fn check_user_auth(&self, db_read: &DatabaseR, user_id: &Uuid) -> Result<()> {
        // check authorisation id is in DB (and TOOD: check password?)
        if let Err(_) = db_get_1::<Uuid>(&db_read, &user_id, Table::UserSession, vec![Column::Id]) {
            return Err(SEError::AuthError);
        }
        Ok(())
    }
}
