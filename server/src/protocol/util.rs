//! StateEntity Utilities
//!
//! StateChain Entity protocol Utilites API calls trait and implementat. Also other non-trait
//! utility functions.

pub use super::super::Result;
use super::{transfer_batch::{transfer_batch_is_ended, BatchTransfer}};
use url::Url;
extern crate shared_lib;
use shared_lib::{
    mainstay::Attestable,
    mocks::mock_electrum::MockElectrum,
    state_chain::*,
    structs::*,
    util::{get_sighash, tx_withdraw_verify, transaction_deserialise, transaction_serialise},
    Root,
};
pub use kms::ecdsa::two_party::Party1Public;

use shared_lib::structs::Protocol;

use rocket_okapi::openapi;
use crate::error::{DBErrorType, SEError};
use crate::storage::Storage;
use crate::{server::StateChainEntity, Database};
use cfg_if::cfg_if;

use electrumx_client::{electrumx_client::ElectrumxClient, interface::Electrumx};
#[cfg(test)]
use mockito::{mock, Matcher, Mock};
pub use monotree::Proof;
use rocket::State;
use rocket_contrib::json::Json;
use std::str::FromStr;
use uuid::Uuid;
use bitcoin::OutPoint;
use bitcoin::Transaction;
use curv::GE;
use std::ops::Deref;


const MAX_LOCKTIME: u32 = 500000000; // bitcoin tx nlocktime cutoff

//Generics cannot be used in Rocket State, therefore we define the concrete
//type of StateChainEntity here
cfg_if! {
    if #[cfg(any(test,feature="mockdb"))]{
        use crate::MockDatabase;
        use monotree::database::MemoryDB;
        type SCE = StateChainEntity::<MockDatabase, MemoryDB>;
    } else {
        use crate::PGDatabase;
        type SCE = StateChainEntity::<PGDatabase, PGDatabase>;
    }
}

/// StateChain Entity Utilities API calls. Includes Information GET requests and prepare_sign_tx which
/// is used in all Protocols
pub trait Utilities {
    /// API: Return StateChain Entity fee information.
    fn get_fees(&self) -> Result<StateEntityFeeInfoAPI>;

    /// API: Generates sparse merkle tree inclusion proof for some key in a tree with some root.
    fn get_smt_proof(&self, smt_proof_msg: SmtProofMsgAPI) -> Result<Option<Proof>>;

    /// API: Get root of sparse merkle tree. Will be via Mainstay in the future.
    //fn get_smt_root(&self) -> Result<Option<Root>>;

    /// API: Get root of sparse merkle tree. Will be via Mainstay in the future.
    //fn get_confirmed_smt_root(
    //    &self,
    //) -> Result<Option<Root>>;

    /// API: Return a TransferBatchData status.
    /// Triggers check for all transfers complete - if so then finalize all.
    /// Also triggers check for batch transfer lifetime. If passed then cancel all transfers and punish state chains.
    //fn get_transfer_batch_status(
    //    &self,
    //    batch_id: String,
    //) -> Result<TransferBatchDataAPI>;

    /// API: Prepare to co-sign a transaction input. This is where SE checks that the tx to be signed is
    /// honest and error free:
    ///     - Check tx data
    ///     - Calculate and store tx sighash for validation before performing ecdsa::sign
    fn prepare_sign_tx(&self, prepare_sign_msg: PrepareSignTxMsg) -> Result<()>;

    /// API: Return statecoin info, proofs and backup txs to enable wallet recovery from the proof key.
    /// The request includes the public proof key and an authenticating signature
    fn get_recovery_data(&self, recovery_request: Vec<RecoveryRequest>) -> Result<Vec<RecoveryDataMsg>>;

    // get lockbox url
    fn get_lockbox_url(&self, user_id: &Uuid) -> Result<Option<(Url,usize)>>;
}

impl Utilities for SCE {
    fn get_fees(&self) -> Result<StateEntityFeeInfoAPI> {
        let fee_address_vec: Vec<&str> = self.config.fee_address.split(",").collect();
        Ok(StateEntityFeeInfoAPI {
            address: fee_address_vec[0].to_string().clone(),
            deposit: self.config.fee_deposit as i64,
            withdraw: self.config.fee_withdraw,
            interval: self.config.lh_decrement,
            initlock: self.config.lockheight_init,
        })
    }

    fn get_smt_proof(&self, smt_proof_msg: SmtProofMsgAPI) -> Result<Option<Proof>> {
        // ensure root exists
        match smt_proof_msg.root.id() {
            Some(id) => {
                if self.database.get_root(id as i64)?.is_none() {
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
            self.smt.clone(),
            &Some(smt_proof_msg.root.hash()),
            &smt_proof_msg.funding_txid,
        )?)
    }

    // fn get_smt_root(&self, db_read: DatabaseR) -> Result<Option<Root>> {
    //     Ok(db_root_get(&db_read, &db_root_get_current_id(&db_read)?)?)
    // }
    //
    // fn get_confirmed_smt_root(
    //     &self,
    //     db_read: DatabaseR,
    //     db_write: DatabaseW,
    // ) -> Result<Option<Root>> {
    //     Ok(db::get_confirmed_root(
    //         &db_read,
    //         &db_write,
    //         &self.config.mainstay,
    //     )?)
    // }

    // fn get_transfer_batch_status(
    //     &self,
    //     db_read: DatabaseR,
    //     db_write: DatabaseW,
    //     batch_id: String,
    // ) -> Result<TransferBatchDataAPI> {
    //     let batch_id = Uuid::from_str(&batch_id).unwrap();
    //
    //     let (state_chains_str, start_time, finalized) = db_get_3::<String, NaiveDateTime, bool>(
    //         &db_read,
    //         &batch_id,
    //         Table::TransferBatch,
    //         vec![Column::StateChains, Column::StartTime, Column::Finalized],
    //     )?;
    //     let state_chains: HashMap<Uuid, bool> = db_deser(state_chains_str)?;
    //
    //     // Check if all transfers are complete. If so then all transfers in batch can be finalized.
    //     if !finalized {
    //         let mut state_chains_copy = state_chains.clone();
    //         state_chains_copy.retain(|_, &mut v| v == false);
    //         if state_chains_copy.len() == 0 {
    //             self.finalize_batch(&db_read, &db_write, batch_id)?;
    //             info!(
    //                 "TRANSFER_BATCH: All transfers complete in batch. Finalized. ID: {}.",
    //                 batch_id
    //             );
    //         }
    //         // Check batch is still within lifetime
    //         if transfer_batch_is_ended(start_time, self.config.batch_lifetime as i64) {
    //             let mut punished_state_chains: Vec<Uuid> = db_deser(db_get_1(
    //                 &db_read,
    //                 &batch_id,
    //                 Table::TransferBatch,
    //                 vec![Column::PunishedStateChains],
    //             )?)?;
    //
    //             if punished_state_chains.len() == 0 {
    //                 // Punishments not yet set
    //                 info!("TRANSFER_BATCH: Lifetime reached. ID: {}.", batch_id);
    //                 // Set punishments for all statechains involved in batch
    //                 for (statechain_id, _) in state_chains {
    //                     self.state_chain_punish(&db_read, &db_write, statechain_id.clone())?;
    //                     punished_state_chains.push(statechain_id.clone());
    //
    //                     // Remove TransferData involved. Ignore failed update err since Transfer data may not exist.
    //                     let _ = db_remove(&db_write, &statechain_id, Table::Transfer);
    //
    //                     info!(
    //                         "TRANSFER_BATCH: Transfer data deleted. State Chain ID: {}.",
    //                         statechain_id
    //                     );
    //                 }
    //
    //                 db_update(
    //                     &db_write,
    //                     &batch_id,
    //                     Table::TransferBatch,
    //                     vec![Column::PunishedStateChains],
    //                     vec![&db_ser(punished_state_chains)?],
    //                 )?;
    //
    //                 info!(
    //                     "TRANSFER_BATCH: Punished all state chains in failed batch. ID: {}.",
    //                     batch_id
    //                 );
    //             }
    //             return Err(SEError::Generic(String::from("Transfer Batch ended.")));
    //         }
    //     }
    //
    //     // return status of transfers
    //     Ok(TransferBatchDataAPI {
    //         state_chains,
    //         finalized,
    //     })
    // }

    fn prepare_sign_tx(&self, prepare_sign_msg: PrepareSignTxMsg) -> Result<()> {
        // Verify unsigned withdraw tx to ensure co-sign will be signing the correct data
        let mut amount = 0;

        for (i, input_amount) in prepare_sign_msg.input_amounts.iter().enumerate(){
            let user_id = &prepare_sign_msg.shared_key_ids[i];
            self.check_user_auth(&user_id)?;
            amount += input_amount;

            if prepare_sign_msg.protocol == Protocol::Withdraw {
                // Verify withdrawal has been authorised via presense of withdraw_sc_sig
                if let Err(_) = self.database.has_withdraw_sc_sig(*user_id) {
                    return Err(SEError::Generic(String::from(
                        "Withdraw has not been authorised. /withdraw/init must be called first.",
                    )));
                }
            }
        }


        // calculate SE fee amount from rate
        let withdraw_fee = (amount * self.config.fee_withdraw) / 10000 as u64;
        let tx = transaction_deserialise(&prepare_sign_msg.tx_hex)?;

        let fee_address_str = self.config.fee_address.replace(" ", "");
        let fee_address_vec: Vec<&str> = fee_address_str.split(",").collect();

        // Which protocol are we signing for?
        match prepare_sign_msg.protocol {
            Protocol::Withdraw => {
                tx_withdraw_verify(
                    &prepare_sign_msg,
                    &fee_address_vec,
                    &withdraw_fee,
                )?;

                for (i, user_id) in prepare_sign_msg.shared_key_ids.iter().enumerate(){
                    let statechain_id = self.database.get_statechain_id(*user_id)?;
                    let tx_backup = self.database.get_backup_transaction(statechain_id)?;

                // Check funding txid UTXO info
                let tx_backup_input = tx_backup.input.get(0).unwrap().previous_output.to_owned();
                if tx
                    .input
                        .get(i)
                    .unwrap()
                    .previous_output
                    .to_owned().clone()
                    != tx_backup_input
                {
                        return Err(SEError::Generic(format!(
                            "Incorrect withdraw transacton input - input number {}", i
                    )));
                }
                }

                for (i, input_addr) in prepare_sign_msg.input_addrs.iter().enumerate(){
                        let user_id = &prepare_sign_msg.shared_key_ids[i];
                    // Update UserSession with withdraw tx info
                    let sig_hash = get_sighash(
                        &tx,
                            &i,
                        &input_addr,
                        &prepare_sign_msg.input_amounts[i],
                        &self.config.network,
                    );

                    self.database.update_withdraw_tx_sighash(
                        &user_id,
                        sig_hash,
                        tx.clone(),
                    )?;

                        info!(
                            "WITHDRAW: Withdraw tx ready for signing. User ID: {:?}.",
                            user_id
                        );

                        // Verify withdrawal has been authorised via presense of withdraw_sc_sig
                        if let Err(_) = self.database.has_withdraw_sc_sig(*user_id) {
                            return Err(SEError::Generic(String::from(
                                "Withdraw has not been authorised. /withdraw/init must be called first.",
                    )));
                        }

                        let statechain_id = self.database.get_statechain_id(*user_id)?;
                        let tx_backup = self.database.get_backup_transaction(statechain_id)?;
                        // Check funding txid UTXO info
                        let tx_backup_input = tx_backup.input.get(0).unwrap().previous_output.to_owned();
                        if tx
                            .input
                            .get(i)
                            .unwrap()
                            .previous_output
                            != tx_backup_input
                        {
                            return Err(SEError::Generic(String::from(
                                "Incorrect withdraw transacton input.",
                            )));
                        }
                        // Update UserSession with withdraw tx info
                   
                        self.database.update_withdraw_tx_sighash(
                            &user_id,
                            sig_hash,
                            tx.clone(),
                        )?;
                    }

                info!(
                    "WITHDRAW: Withdraw tx ready for signing. User IDs: {:?}.",
                    prepare_sign_msg.shared_key_ids
                );
            },
            _ => {
                // Verify unsigned backup tx to ensure co-sign will be signing the correct data
                if prepare_sign_msg.input_addrs.len() != prepare_sign_msg.input_amounts.len() {
                    return Err(SEError::Generic(String::from(
                        "Back up tx number of signing addresses != number of input amounts.",
                    )));
                }

                // Verify that there is a single input
                if tx.input.len() != 1 {
                    return Err(SEError::Generic(String::from(
                        "Expected a single input address for transfer.",
                    )));
                }

                //check that the locktime is height and not epoch
                if (tx.lock_time as u32) >= MAX_LOCKTIME {
                    return Err(SEError::Generic(String::from(
                        "Backup tx locktime specified as Unix epoch time not block height.",
                    )));
                }

                //check withdrawal fee is correctly set

                tx_withdraw_verify(
                    &prepare_sign_msg,
                    &fee_address_vec,
                    &withdraw_fee,
                )?;

                let user_id = prepare_sign_msg.shared_key_ids[0];

                //for transfer (not deposit)
                if prepare_sign_msg.protocol == Protocol::Transfer {
                    //verify transfer locktime is correct
                    let statechain_id = self.database.get_statechain_id(user_id)?;
                    let current_tx_backup = self.database.get_backup_transaction(statechain_id.clone())?;

                    if (current_tx_backup.lock_time as u32) != (tx.lock_time as u32) + (self.config.lh_decrement as u32) {
                        return Err(SEError::Generic(String::from(
                            "Backup tx locktime not correctly decremented.",
                        )));
                    }
                    // add unsigned transaction to backup store
                    // (this ensures that incompleted swaps also decrement the required locktime)
                    self.database.update_backup_tx(&statechain_id, tx.clone())?;
                }

                // Only in deposit case add backup tx to UserSession
                if prepare_sign_msg.protocol == Protocol::Deposit {
                    // check if there is an existing backup transaction (from a previous deposit confirm)
                    // if there is: verify that the locktime of the new tx is the same and the destination address
                    let locktime: Option<u32> = match self.database.get_user_backup_tx(user_id.clone()) {
                        Ok(old_tx) => Some(old_tx.lock_time as u32),
                        Err(e) => { 
                        if (e.to_string().contains("No data for identifier")) {
                            None
                        } else {
                            return Err(SEError::Generic(String::from("DBError",)));                            
                            }
                        }
                    };

                    if (locktime.is_none() || locktime == Some(tx.lock_time as u32)) {
                        self.database.update_user_backup_tx(&user_id, tx.clone())?;
                    } else {
                        return Err(SEError::Generic(String::from(
                            "Replacement backup tx locktime not correct.",
                        )));
                    }
                }

                let sig_hash = get_sighash(
                    &tx,
                    &0,
                    &prepare_sign_msg.input_addrs[0],
                    &prepare_sign_msg.input_amounts[0],
                    &self.config.network,
                );

                self.database.update_sighash(&user_id, sig_hash)?;

                info!(
                    "DEPOSIT: Backup tx ready for signing. Shared Key ID: {}.",
                    user_id
                );
            }
        }
        Ok(())
    }

    fn get_recovery_data(&self, recovery_requests: Vec<RecoveryRequest>) -> Result<Vec<RecoveryDataMsg>> {
        let mut recovery_data = vec!();
        for recovery_request in recovery_requests {
            let rec_vec: Vec<(Uuid, Uuid, Transaction)> = match self.database.get_recovery_data(recovery_request.key.clone()) {
                Ok(res) => res,
                Err(_) => continue
            };
            for statecoin in rec_vec {
                // If withdrawn err will be thrown. Return nothing in this case
                let amount = match self.get_statechain_data_api(statecoin.1) {
                    Ok(statechain_data) => statechain_data.amount,
                    Err(_) => continue
                };

                let mut master_key: Party1Public = serde_json::from_str(&self.database.get_public_master(statecoin.0)?.unwrap()).map_err(|e| e.to_string())?;
                let shared_public: GE = serde_json::from_str(&self.database.get_statecoin_pubkey(statecoin.1)?.unwrap()).map_err(|e| e.to_string())?;
                master_key.q = shared_public;
                let public = serde_json::to_string(&master_key).map_err(|e| e.to_string())?;

                recovery_data.push(RecoveryDataMsg {
                    shared_key_id: statecoin.0,
                    statechain_id: statecoin.1,
                    amount,
                    tx_hex: transaction_serialise(&statecoin.2),
                    proof_key: recovery_request.key.clone(),
                    shared_key_data: public
                })
            }
        }
        return Ok(recovery_data);
    }

    fn get_lockbox_url(&self, user_id: &Uuid) -> Result<Option<(Url,usize)>> {
        let db = &self.database;

        match db.get_lockbox_index(user_id)? {
            Some(i) => {
                match &self.lockbox {
                    Some(l) => {
                        match l.endpoint.get(&i) {
                            Some(url) => Ok(Some((url.clone(), i))),
                            None => Err(SEError::Generic(format!(
                                "get_lockbox_url - no endpoint with index {} for user_id {}",
                                &i, &user_id))) 
                        }
                    },
                    None => return Err(SEError::Generic(format!(
                        "get_lockbox_url - lockbox not configured"))),

                }
            },
            None => Ok(None),
        }
    }

}

pub trait RateLimiter{
    fn check_rate_slow<T:'static+Into<String>>(&self, key: T) -> Result<()>;
    fn check_rate_fast<T:'static+Into<String>>(&self, key: T) -> Result<()>;
    fn check_rate_id(&self, key: &Uuid) -> Result<()>;
}

impl RateLimiter for SCE {
    fn check_rate_slow<T:'static+Into<String>>(&self, key: T) -> Result<()> {
        // If rate_limiter is 'None' the result is Ok. Otherwise, check the rate for 'key'.

       match &self.rate_limiter_slow {
            Some(r) => {
                let key_str: &String = &key.into();
                r.check_key(key_str)
                    .map_err(|e| SEError::RateLimitError(format!("{} for key {} (slow limiter) ",SEError::from(e), key_str)))?;

               Ok(())
            },
            None => Ok(())
        }
    }

    fn check_rate_fast<T:'static+Into<String>>(&self, key: T) -> Result<()> {
        match &self.rate_limiter_fast {
            Some(r) => {
                let key_str: &String = &key.into();
                r.check_key(key_str)
                    .map_err(|e| SEError::RateLimitError(format!("{} for key {} (fast limiter) ",SEError::from(e), key_str)))?;
                Ok(())
            },
            None => Ok(())
        }
    }

    fn check_rate_id(&self, key: &Uuid) -> Result<()> {
        match &self.rate_limiter_id {
            Some(r) => {
                r.check_key(key)
                    .map_err(|e| SEError::RateLimitError(format!("{} for key {} (id limiter) ",SEError::from(e), key)))?;
                Ok(())
            },
            None => Ok(())
        }
    }
}

#[openapi]
/// # Get statechain entity operating information
#[get("/info/fee", format = "json")]
pub fn get_fees(sc_entity: State<SCE>) -> Result<Json<StateEntityFeeInfoAPI>> {
    sc_entity.check_rate_fast("info")?;
    match sc_entity.get_fees() {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Get the current statecoin amount histogram
#[get("/info/coins", format = "json")]
pub fn get_coin_info(sc_entity: State<SCE>) -> Result<Json<CoinValueInfo>> {
    sc_entity.check_rate_fast("info")?;
    let guard = sc_entity.coin_value_info.as_ref().lock()?;
    Ok(Json(guard.deref().clone()))
}

#[openapi]
/// # Get current statechain information for specified statechain ID
#[get("/info/statechain/<statechain_id>", format = "json")]
pub fn get_statechain(
    sc_entity: State<SCE>,
    statechain_id: String,
) -> Result<Json<StateChainDataAPI>> {
    sc_entity.check_rate_fast("info")?;
    match sc_entity.get_statechain_data_api(Uuid::from_str(&statechain_id).unwrap()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Get current statecoin (statechain tip) information for specified statechain ID
#[get("/info/statecoin/<statechain_id>", format = "json")]
pub fn get_statecoin(
    sc_entity: State<SCE>,
    statechain_id: String,
) -> Result<Json<StateCoinDataAPI>> {
    sc_entity.check_rate_fast("info")?;
    match sc_entity.get_statecoin_data_api(Uuid::from_str(&statechain_id).unwrap()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Get current statechain information for specified statechain ID
#[get("/info/owner/<statechain_id>", format = "json")]
pub fn get_owner_id(
    sc_entity: State<SCE>,
    statechain_id: String,
) -> Result<Json<OwnerID>> {
    sc_entity.check_rate_fast("info")?;
    match sc_entity.get_owner_id(Uuid::from_str(&statechain_id).unwrap()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Get the current Sparse Merkle Tree commitment root
#[get("/info/root", format = "json")]
pub fn get_smt_root(sc_entity: State<SCE>) -> Result<Json<Option<Root>>> {
    sc_entity.check_rate_fast("info")?;
    match sc_entity.get_smt_root() {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Get the Merkle path proof for a specified statechain (TxID) and root
#[post("/info/proof", format = "json", data = "<smt_proof_msg>")]
pub fn get_smt_proof(
    sc_entity: State<SCE>,
    smt_proof_msg: Json<SmtProofMsgAPI>,
) -> Result<Json<Option<Proof>>> {
    sc_entity.check_rate_fast("info")?;
    match sc_entity.get_smt_proof(smt_proof_msg.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Get batch transfer status and statecoin IDs for specified batch ID
#[get("/info/transfer-batch/<batch_id>", format = "json")]
pub fn get_transfer_batch_status(
    sc_entity: State<SCE>,
    batch_id: String,
) -> Result<Json<TransferBatchDataAPI>> {
    sc_entity.check_rate_fast("info")?;
    match sc_entity.get_transfer_batch_status(Uuid::from_str(&batch_id).unwrap()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Recover statechain and backup transaction for proof key
#[post("/info/recover", format = "json", data = "<request_recovery_data>")]
pub fn get_recovery_data(
    sc_entity: State<SCE>,
    request_recovery_data: Json<Vec<RecoveryRequest>>,
) -> Result<Json<Vec<RecoveryDataMsg>>> {
    sc_entity.check_rate_fast("info")?;
    match sc_entity.get_recovery_data(request_recovery_data.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Submit transaction details to the server in preparation for 2P-ECDSA signing
#[post("/prepare-sign", format = "json", data = "<prepare_sign_msg>")]
pub fn prepare_sign_tx(
    sc_entity: State<SCE>,
    prepare_sign_msg: Json<PrepareSignTxMsg>,
) -> Result<Json<()>> {
    sc_entity.check_rate_fast("info")?;
    match sc_entity.prepare_sign_tx(prepare_sign_msg.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Reset databases and in-RAM data if in testing mode
#[get("/test/reset-db")]
pub fn reset_test_dbs(sc_entity: State<SCE>) -> Result<Json<()>> {
    sc_entity.check_rate_fast("reset-db")?;
    if sc_entity.config.testing_mode {
        match sc_entity.database.reset() {
            Ok(_res) => {
                sc_entity.reset_data()?;
                sc_entity.database.init(sc_entity.coin_value_info.as_ref(), 
                    sc_entity.user_ids.as_ref())?;
                return Ok(Json(()))
            },
            Err(e) => return Err(e),
        }
    }
    return Err(SEError::Generic(String::from(
        "Cannot reset Databases when not in testing mode.",
    )));
}

#[openapi]
/// # Reset databases and in-RAM data if in testing mode
#[get("/test/reset-inram-data")]
pub fn reset_inram_data(sc_entity: State<SCE>) -> Result<Json<()>> {
    sc_entity.check_rate_fast("reset-inram-data")?;
    if sc_entity.config.testing_mode {
        sc_entity.reset_data()?;
        sc_entity.database.init(sc_entity.coin_value_info.as_ref(), 
                    sc_entity.user_ids.as_ref())?;
        return Ok(Json(()));
    };

    return Err(SEError::Generic(String::from(
        "Cannot reset in-ram data when not in testing mode.",
    )));
}


// Utily functions for StateChainEntity to be used throughout codebase.
impl SCE {
    /// Query an Electrum Server for a transaction's confirmation status.
    /// Return Ok() if confirmed or Error if not within configured confirmation number.
    pub fn verify_tx_confirmed(&self, txid: &String) -> Result<()> {

        if self.config.required_confirmation == 0 {
            return Ok(());
        };

        let mut electrum: Box<dyn Electrumx> = if self.config.testing_mode {
            Box::new(MockElectrum::new())
        } else {
            Box::new(ElectrumxClient::new(self.config.electrum_server.clone()).unwrap())
        };

        info!(
            "DEPOSIT: Verifying funding transaction confirmation. Txid: {}",
            txid
        );

        match electrum.get_transaction_conf_status(txid.clone(), false) {
            Ok(res) => {
                // Check for tx confs. If none after 10*(block time) then return error.
                if res.confirmations.is_none() {
                    return Err(SEError::Generic(String::from(
                        "Funding Transaction not confirmed.",
                    )));
                }
                else if res.confirmations.unwrap() < self.config.required_confirmation {
                    return Err(SEError::Generic(String::from(
                        "Funding Transaction insufficient confirmations.",
                    )));
                }
                else {
                    return Ok(());
                }
            }
            Err(_) => {
                return Err(SEError::Generic(String::from(
                    "Funding Transaction not found.",
                )));
            }
        }
    }

    // Set state chain time-out
    pub fn state_chain_punish(&self, statechain_id: Uuid) -> Result<()> {
        let sc_locked_until = self.database.get_sc_locked_until(statechain_id)?;

        if is_locked(sc_locked_until).is_err() {
            return Err(SEError::Generic(String::from(
                "State chain is already locked. This should not be possible.",
            )));
        }

        self.database.update_locked_until(
            &statechain_id,
            &get_locked_until(self.config.conductor.punishment_duration as i64)?,
        )?;

        info!(
            "PUNISHMENT: State Chain ID: {} locked for {}s.",
            statechain_id, self.config.conductor.punishment_duration
        );
        Ok(())
    }

    /// Check if user has passed authentication.
    pub fn check_user_auth(&self, user_id: &Uuid) -> Result<()> {
        // check authorisation id is in DB (and TOOD: check password?)
        let mut guard = self.user_ids.as_ref().lock()?;
        match guard.contains(user_id){
            true => {
                // rate limit by user id
                self.check_rate_id(user_id)
            },
            //Update the user ids set in a rate-limited manner
            false => {
                let _auth = self.check_rate_fast("check_user_auth")
                            .and_then(|_| Ok(self.database.get_user_auth(user_id)))
                            .map_err(|_| SEError::AuthError)?;
                guard.insert(*user_id);
                Ok(())
            }
        }
    }

    pub fn get_transfer_batch_status(&self, batch_id: Uuid) -> Result<TransferBatchDataAPI> {
        let tbd = self.database.get_transfer_batch_data(batch_id)?;
        debug!("TRANSFER_BATCH: data: {:?}", tbd);
        let mut finalized = tbd.finalized;
        if !finalized {
            debug!("TRANSFER_BATCH: attempting to finalize batch transfer - batch id: {}", batch_id);
            // Attempt to finalize transfers - will fail with Err if not all ready to be finalized
            match self.finalize_batch(batch_id){
                Ok(_) => {
                        info!(
                        "TRANSFER_BATCH: All transfers complete in batch. Finalized. ID: {}.",
                        batch_id
                        );
                        finalized = true;
                    },
                Err(_) => (),
            }
            // Check batch is still within lifetime
            debug!("TRANSFER_BATCH: checking if batch transfer has ended");
            if transfer_batch_is_ended(tbd.start_time, self.config.batch_lifetime as i64) {
                let mut punished_state_chains: Vec<Uuid> =
                    self.database.get_punished_state_chains(batch_id)?;

                if punished_state_chains.len() == 0 {
                    // Punishments not yet set
                    info!("TRANSFER_BATCH: Lifetime reached. ID: {}.", batch_id);
                    // Set punishments for all statechains involved in batch
                    for statechain_id in tbd.state_chains {
                        self.state_chain_punish(statechain_id.clone())?;
                        punished_state_chains.push(statechain_id.clone());

                        // Remove TransferData involved. Ignore failed update err since Transfer data may not exist.
                        let _ = self.database.remove_transfer_data(&statechain_id);

                        info!(
                            "TRANSFER_BATCH: Transfer data deleted. State Chain ID: {}.",
                            statechain_id
                        );
                    }

                    self.database
                        .update_punished(&batch_id, punished_state_chains)?;

                    info!(
                        "TRANSFER_BATCH: Punished all state chains in failed batch. ID: {}.",
                        batch_id
                    );
                }
                return Err(SEError::TransferBatchEnded(String::from("Timeout")));
            }
            debug!("TRANSFER_BATCH: batch transfer ongoing: {:?}", tbd);
        }

        debug!("TRANSFER_BATCH: batch transfer ended: {:?}, finalized: {}", tbd, finalized);
        // return status of transfers
        Ok(TransferBatchDataAPI {
            state_chains: tbd.state_chains,
            finalized,
        })
    }
}

impl<T: Database + Send + Sync + 'static, D: monotree::Database + Send + Sync + 'static> Storage
    for StateChainEntity<T, D>
{
    fn reset_data(&self) -> Result<()>{
        let mut guard_coins_mutex = self.coin_value_info.as_ref().lock()?;
        let mut guard_ids_mutex = self.user_ids.as_ref().lock()?;
        guard_coins_mutex.clear();
        guard_ids_mutex.clear();
        Ok(())
    }

    /// Update the database and the mainstay slot with the SMT root, if applicable
    fn update_root(&self, root: &Root) -> Result<i64> {
        let db = &self.database;

        match &self.config.mainstay {
            Some(c) => match root.attest(&c) {
                Ok(_) => (),
                Err(e) => info!("Mainstay attestation error: {}.",e.to_string()),
            },
            None => (),
        };

        let id = db.root_update(root)?;
        Ok(id)
    }

    // Update SMT with new (key: value) pair and update current root value
    fn update_smt(
        &self,
        funding_txid: &String,
        proof_key: &String,
    ) -> Result<(Option<Root>, Root)> {
        let db = &self.database;

        //If mocked out current_root will be randomly chosen
        let current_root_id = db.root_get_current_id()?;
        let current_root = db.get_root(current_root_id)?;

        let new_root_hash = update_statechain_smt(
            self.smt.clone(),
            &current_root.clone().map(|r| r.hash()),
            funding_txid,
            proof_key,
        )?;

        let new_root = Root::from_hash(&new_root_hash.unwrap());
        self.update_root(&new_root)?; // Update current root

        Ok((current_root, new_root))
    }

    fn get_smt_root(&self) -> Result<Option<Root>> {
        Ok(self
            .database
            .get_root(self.database.root_get_current_id()?)?)
    }

    /// Update the database with the latest available mainstay attestation info
    fn get_confirmed_smt_root(&self) -> Result<Option<Root>> {
        use crate::shared_lib::mainstay::{
            Commitment, CommitmentIndexed, CommitmentInfo, MainstayAPIError,
        };

        let db = &self.database;

        fn update_db_from_ci<U: Database>(db: &U, ci: &CommitmentInfo) -> Result<Option<Root>> {
            let mut root = Root::from_commitment_info(ci);
            let current_id = db.root_get_current_id()?;
            let mut id;
            for x in 0..=current_id - 1 {
                id = current_id - x;
                let root_get = db.get_root(id)?;
                match root_get {
                    Some(r) => {
                        if r.hash() == ci.commitment().to_hash() {
                            match r.id() {
                                Some(r_id) => {
                                    root.set_id(&r_id);
                                    break;
                                }
                                None => (),
                            }
                        }
                    }
                    None => (),
                };
            }

            let root = root;

            match db.root_update(&root) {
                Ok(_) => Ok(Some(root)),
                Err(e) => Err(e),
            }
        }

        match &self.config.mainstay {
            Some(conf) => {
                match &db.get_confirmed_smt_root()? {
                    Some(cr_db) => {
                        //Search for update

                        //First try to find the latest root in the latest commitment
                        let result = match &CommitmentInfo::from_latest(conf) {
                            Ok(ci) => match cr_db.commitment_info() {
                                Some(ci_db) => {
                                    if ci_db == ci {
                                        Ok(Some(cr_db.clone()))
                                    } else {
                                        update_db_from_ci(db, ci)
                                    }
                                }
                                None => update_db_from_ci(db, ci),
                            },
                            Err(e) => Err(SEError::SharedLibError(e.to_string())),
                        };

                        //Search for the roots in historical mainstay commitments if not found from latest
                        match result? {
                            Some(r) => Ok(Some(r)),
                            None => {
                                let current_id = db.root_get_current_id()?;
                                for x in 0..=current_id - 1 {
                                    let id = current_id - x;
                                    let _ = match db.get_root(id)? {
                                        Some(r) => {
                                            match &CommitmentInfo::from_commitment(
                                                conf,
                                                &Commitment::from_hash(&r.hash()),
                                            ) {
                                                Ok(ci) => {
                                                    let mut root = Root::from_commitment_info(ci);
                                                    root.set_id(&id);
                                                    //Latest confirmed commitment found. Updating db
                                                    return match self.database.root_update(&root) {
                                                        Ok(_) => Ok(Some(root)),
                                                        Err(e) => Err(e),
                                                    };
                                                }

                                                //MainStay::NotFoundRrror is acceptable - continue the search. Otherwise return the error
                                                Err(e) => {
                                                    match e.downcast_ref::<MainstayAPIError>() {
                                                        Some(e) => match e {
                                                            MainstayAPIError::NotFoundError(_) => {
                                                                ()
                                                            }
                                                            _ => {
                                                                return Err(SEError::Generic(
                                                                    e.to_string(),
                                                                ))
                                                            }
                                                        },
                                                        None => {
                                                            return Err(SEError::Generic(
                                                                e.to_string(),
                                                            ))
                                                        }
                                                    }
                                                }
                                            };
                                        }
                                        None => (),
                                    };
                                }
                                Ok(None)
                            }
                        }
                    }
                    None => match &CommitmentInfo::from_latest(conf) {
                        Ok(ci) => update_db_from_ci(db, ci),
                        Err(e) => Err(SEError::SharedLibError(e.to_string())),
                    },
                }
            }
            None => Ok(None),
        }
    }

    fn get_root(&self, id: i64) -> Result<Option<Root>> {
        self.database.get_root(id)
    }

    //    fn save_user_session(&self, id: &Uuid, auth: String, proof_key: String)
    //-> Result<()>;

    // fn save_statechain(&self, statechain_id: &Uuid, statechain: &StateChain,
    //amount: i64,
    //user_id: &Uuid) -> Result<()>;

    //fn save_backup_tx(&self, statechain_id: &Uuid, backup_tx: &Transaction)
    //   -> Result<()>;

    //Returns: (new_root, current_root)
    //fn update_smt(&self, backup_tx: &Transaction, proof_key: &String)
    //   -> Result<(Option<Root>, Root)>;

    //fn save_ecdsa(&self, user_id: &Uuid,
    //    first_msg: party_one::KeyGenFirstMsg) -> Result<()>;

    //fn get_confirmed_root(&self, id: &i64) -> Result<Option<Root>>;

    //fn get_root(&self, id: &i64) -> Result<Option<Root>>;

    //fn update_root(&self, root: &Root) -> Result<i64>;

    fn get_statechain(&self, statechain_id: Uuid) -> Result<StateChain> {
        self.database.get_statechain(statechain_id)
    }

    fn get_statechain_data_api(&self, statechain_id: Uuid) -> Result<StateChainDataAPI> {
        //let statechain_id = Uuid::from_str(&statechain_id).unwrap();

        let state_chain = self.database.get_statechain_amount(statechain_id)?;

        let state = match state_chain.chain.chain.get(0){
            Some(s) => s.next_state.clone(),
            None => return Err(SEError::Generic(format!("statechain with id {} is empty", &statechain_id)))
        };

        if state.is_some() {
                if state.unwrap().purpose == String::from("WITHDRAW") {
                    return Ok({StateChainDataAPI {
                        amount: state_chain.amount as u64,
                        utxo: OutPoint::null(),
                        chain: state_chain.chain.chain,
                        locktime: 0 as u32,
                    }});
                }
            }

        let tx_backup = self.database.get_backup_transaction(statechain_id)?;

        return Ok({StateChainDataAPI {
            amount: state_chain.amount as u64,
            utxo: tx_backup.input.get(0).unwrap().previous_output,
            chain: state_chain.chain.chain,
            locktime: tx_backup.lock_time,
        }});
    }

    fn get_statecoin_data_api(&self, statechain_id: Uuid) -> Result<StateCoinDataAPI> {

        let state_chain = self.database.get_statechain_amount(statechain_id)?;

        let statecoin = state_chain.chain.get_tip()?;

        match state_chain.chain.get_first()?.next_state {
            Some(state) => {
                if state.purpose == String::from("WITHDRAW") {
                    return Ok({StateCoinDataAPI {
                        amount: state_chain.amount as u64,
                        utxo: OutPoint::null(),
                        statecoin: statecoin.to_owned(),
                        locktime: 0 as u32,
                    }});
                }
            },
            None => ()
        };
        
        let tx_backup = self.database.get_backup_transaction(statechain_id)?;

        return Ok({StateCoinDataAPI {
            amount: state_chain.amount as u64,
            utxo: tx_backup.input.get(0).unwrap().previous_output,
            statecoin: statecoin.to_owned(),
            locktime: tx_backup.lock_time,
        }});
    }


    fn get_owner_id(&self, statechain_id: Uuid) -> Result<OwnerID> {
        //let statechain_id = Uuid::from_str(&statechain_id).unwrap();

        let new_user_id = self.database.get_owner_id(statechain_id)?;

        return Ok({OwnerID {
            shared_key_id: new_user_id,
        }});
    }   

    //fn authorise_withdrawal(&self, user_id: &Uuid, signature: StateChainSig) -> Result<()>;

    // /withdraw/confirm
    //fn confirm_withdrawal(&self, user_id: &Uuid, address: &String)->Result<()>;

    // /transfer/sender
    //fn init_transfer(&self, user_id: &Uuid, sig: &StateChainSig)->Result<()>;

    // Returns statechain_id, sstatechain_sig_str, x1_str
    //fn get_transfer(&self, statechain_id: &Uuid) -> Result<(Uuid, StateChainSig, FE)>;

    //Returns party1_private_str, party2_public_str
    //fn get_transfer_ecdsa_pair(&self, user_id: &Uuid) -> Result<Party1Private, GE>;

    //fn finalize_transfer(&self, &Option<BatchData>, tf_data: &TransferFinalizeData);

    //fn batch_transfer_exists(&self, batch_id: &Uuid, sig: &StateChainSig)-> bool;

    // /transfer/batch/init
    //fn init_batch_transfer(&self, batch_id: &Uuid,
    //                   state_chains: &HashMap<Uuid, bool>) -> Result<()>;

    // Update the locked until time of a state chain (used for punishment)
    //fn update_locked_until(&self, statechain_id: &Uuid, time: &NaiveDateTime);

    //Update the list of punished state chains
    //fn update_punished(&self, punished: &Vec<Uuid>);
}

#[cfg(test)]
pub mod mocks {
    use super::{mock, Matcher, Mock};

    pub mod ms {
        use super::*;
        pub fn commitment_proof_not_found() -> Mock {
            mock(
                "GET",
                Matcher::Regex(r"^/commitment/commitment\?commitment=[abcdef\d]{64}".to_string()),
            )
            .with_header("Content-Type", "application/json")
            .with_body(
                "{\"error\":\"Not found\",\"timestamp\":1596123963077,
                \"allowance\":{\"cost\":3796208}}",
            )
        }

        pub fn post_commitment() -> Mock {
            mock("POST", "/commitment/send")
            .match_header("content-type", "application/json")
            .with_body(json!({"response":"Commitment added","timestamp":1541761540,"allowance":{"cost":4832691}}).to_string())
            .with_header("content-type", "application/json")
        }

        pub fn commitment() -> Mock {
            mock("GET", "/latestcommitment?position=1")
               .with_header("Content-Type", "application/json")
               .with_body("{
                   \"response\":
                    {
                        \"commitment\": \"71c7f2f246caf3e4f0b94ea4ad54b6c506687069bf1e17024cd5961b0df78d6d\",
                        \"merkle_root\": \"47fc767ebc5095133d6de9a060c248c115b3fdf5f30921de2ee111225690de01\",
                        \"txid\": \"4be7f5fbd3272cec65e520f5b04c79c2059548c4576558aac3f4f6655138d5d4\"
                    },
                    \"timestamp\": 1548329166363,
                    \"allowance\":
                    {
                        \"cost\": 3119659
                    }
                }")
        }

        pub fn commitment_proof() -> Mock {
            mock("GET",
                        "/commitment/commitment?commitment=71c7f2f246caf3e4f0b94ea4ad54b6c506687069bf1e17024cd5961b0df78d6d")
                        .with_header("Content-Type", "application/json")
                        .with_body("{\"response\":{
                            \"attestation\":{\"merkle_root\":\"47fc767ebc5095133d6de9a060c248c115b3fdf5f30921de2ee111225690de01\",
                    \"txid\":\"4be7f5fbd3272cec65e520f5b04c79c2059548c4576558aac3f4f6655138d5d4\",\"confirmed\":true,
                    \"inserted_at\":\"12:07:54 05/02/2020 UTC\"},
                    \"merkleproof\":{\"position\":1,
                    \"merkle_root\":\"47fc767ebc5095133d6de9a060c248c115b3fdf5f30921de2ee111225690de01\",
                    \"commitment\":\"71c7f2f246caf3e4f0b94ea4ad54b6c506687069bf1e17024cd5961b0df78d6d\",
                    \"ops\":[{\"append\":false,\"commitment\":\"31e66288b9074bcfeb3bc5734f2d0b189ad601b61f86b8241ee427648b59fdbc\"},
                    {\"append\":true,\"commitment\":\"60da74551926c4283dd4b4e295d2a1eb5147b5cf6c7c2019e8b64c22a1ba5bab\"},{\"append\":true,
                    \"commitment\":\"94adb04ab09036fbc6cc164ec6df4d9d8fba45bcd7901a03d2e91b123071a5ec\"}]}}
                    ,\"timestamp\":1593160486862,
                    \"allowance\":{\"cost\":17954530}
                    }")
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::shared_lib::mainstay;
    use crate::{structs::StateChainAmount, MockDatabase};
    use monotree::database::{Database as monotreeDatabase, MemoryDB};
    use std::convert::TryInto;
    use std::str::FromStr;
    use bitcoin::Transaction;
    use std::num::NonZeroU32;
    use crate::config::Config;
    
    // Useful data structs for tests throughout codebase
    pub static BACKUP_TX_NOT_SIGNED: &str = "{\"version\":2,\"lock_time\":0,\"input\":[{\"previous_output\":\"faaaa0920fbaefae9c98a57cdace0deffa96cc64a651851bdd167f397117397c:0\",\"script_sig\":\"\",\"sequence\":4294967295,\"witness\":[]}],\"output\":[{\"value\":9000,\"script_pubkey\":\"00148fc32525487d2cb7323c960bdfb0a5ee6a364738\"}]}";
    pub static BACKUP_TX_SIGNED: &str = "{\"version\":2,\"lock_time\":0,\"input\":[{\"previous_output\":\"faaaa0920fbaefae9c98a57cdace0deffa96cc64a651851bdd167f397117397c:0\",\"script_sig\":\"\",\"sequence\":4294967295,\"witness\":[[48,68,2,32,45,42,91,77,252,143,55,65,154,96,191,149,204,131,88,79,80,161,231,209,234,229,217,100,28,99,48,148,136,194,204,98,2,32,90,111,183,68,74,24,75,120,179,80,20,183,60,198,127,106,102,64,37,193,174,226,199,118,237,35,96,236,45,94,203,49,1],[2,242,131,110,175,215,21,123,219,179,199,144,85,14,163,42,19,197,97,249,41,130,243,139,15,17,51,185,147,228,100,122,213]]}],\"output\":[{\"value\":9000,\"script_pubkey\":\"00148fc32525487d2cb7323c960bdfb0a5ee6a364738\"}]}";
    pub static STATE_CHAIN: &str = "{\"chain\":[{\"data\":\"026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e\",\"next_state\":null}]}";
    pub static STATE_CHAIN_SIG: &str = "{ \"purpose\": \"TRANSFER\", \"data\": \"026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e\", \"sig\": \"3045022100abe02f0d1918aca36b634eb1af8a4e0714f3f699fb425de65cc661e538da3f2002200a538a22df665a95adb739ff6bb592b152dba5613602c453c58adf70858f05f6\"}";
    pub static MASTER_KEY: &str = "{\"public\":{\"q\":{\"x\":\"f8308498a5b5996eb7c410fb7ada7f3524d604b45b247cc4d13e5a32c3763908\",\"y\":\"7e41091fd5ab1138d1a3cdf41b43c82a064839a6b82b251be2be70099b642d1a\"},\"p1\":{\"x\":\"701e7d08608e6065b8f19f7cd867bcd7c5c4a11290e51187210a66713349c76c\",\"y\":\"10f76cae4eac6727bec6ae239de37d806a4877bc418f9fadaad0fd379cb11e73\"},\"p2\":{\"x\":\"caff57b3e214231182b2ba729079422887527dec2c2be1af03eb9a28be046fbb\",\"y\":\"94d4d2624a6be1e5fccf22ea5d7d2294a65f86b23642e7107c5523bb383d2612\"},\"paillier_pub\":{\"n\":\"11489233870088042333010221250016305472224248130131837344400358635737478519468920848276451747026121985401781804607266395846806728547165860151830628936151241253052105217375620729553123605998218501591757218904947955026013349855548130232876481464163645763380508660165838175358408923868455078398162478065282146744074902115770410655628975593804546170315851709066735895285416399351986223748741323752676766246912115655411869835426209804163120117240537098699118426250380831687194901410283437954378683229249501222250355118886953166922692541953136499596437296944964919863277847025337779172484000271289374153321801582770169915217\"},\"c_key\":\"13acbe9791ae6136f0d3700bad8cbe723ed2676e33d9f080122283a3a5838e3418d9ae3f61cc5e3b033ec71979f339c87e2da410c46a3a6238e40fc403799b5b7855bf529c381bd80288f5002f62a460cc005ec71e85c7d0eda2133245a857fe414c8653f0248016545618e2d53f466e3808edfe15774fb32ffeafc98dc08dd9eaca2e5411ae22bd4dad358bffadb51e82d2f99404ff73db8c473a2483133863aeaf6ffccd455fe4ba0966f90e85ea02083962d15779215941396676d90a0ce99a09adaa064956f506ca40d18ba91a7f9826a2e82050fb3b569790b5642ac45e39d9dfb63f8c975c30090f9eceaca387129539eaebfcedc17d2e49f0bd029e3591ac30e3db26139368b1423cf058e2128978411518e87c2d3c106a91c16de80895ad7f928a9a40c6d5aac356bd2966b3bf98c77f616f04329caecc895d13d16d8193e9f0bfe866c86a2eee3b2b0beb95478d4c216e00f8a9712618599d176ad253e59e9e27743f1e61a710bb9a0ae989226900ef809acb17e11f9f068bdb35fd7a767560e912da3aa98cd9d529b3d993e360d73f19adf830599f71ca139f6e17014302dce8a40401276d3a7e3dda04ef4b344a7dc4cb94c106c346e389ab7e089b97aa1e3f1680d4b8eeb62d405ab3a4e827b93dd15074e1dfd74244a9b4857017818b63504399c98fc02d0b3af135a0d7ac4f9de9a7cd47fdbe40cb3a6185b6\"},\"private\":{\"x1\":\"7d40223e23d9be8a484f02c193f6d637ee920d22107bcc271315ecd7cf7bd417\",\"paillier_priv\":{\"p\":\"95968611635960852961029982396007186819172638068010828329449274935568627735159638229570155217385550521772837802209343399026212621624237395184543248204625051917248015126148738583692391387724379315739614056981768639631978130165718525707250385364943792301344169291673198185105717525805446423420947171964258675871\",\"q\":\"119718662948572417380116608786988393154649208452700228802334036347214087888515999164811204446322560182519144489173108609786997536166347774811155976446122754875172588386796176207110943485933259100127115436979944772204093241941218507628108172049881866436113901845596310515366261414462580028675547493957305267727\"},\"c_key_randomness\":\"2cca6bbfb2f111aaa52b33bd3320cff512f23010822687156ed81f231403d0c2ded58514221d81cd8185bf584efd79534e55b78da3766a18175121d0df84c098c442553513cda8646a81e36cd3bd853381678d6cba7adeb2dffc425e6209bf0ccd2a824d78d1fe8ad388d999c626cd1d0bad6e312fbdd06f219de1e7379e1b8c1f1c8bd50bcfc8acad0692f5028252e18ffe60268ecea8cf35343895d9f78e406ea9301f3392d6b78ea87884a710d548cad991571abe8264653e63dc30c4276b7fcfeb9783bc7e7f88b2d573e3de2d6fe4d3809c50866b820402925621a7bcae34d87914db54455ce5ffd189e2d0bb9032913e4be221eae1a22e31d5803cbc07\"},\"chain_code\":\"0\"}";
    pub static PARTY2PUBLIC: &str = "{\"q\":{\"x\":\"f8308498a5b5996eb7c410fb7ada7f3524d604b45b247cc4d13e5a32c3763908\",\"y\":\"7e41091fd5ab1138d1a3cdf41b43c82a064839a6b82b251be2be70099b642d1a\"},\"p1\":{\"x\":\"701e7d08608e6065b8f19f7cd867bcd7c5c4a11290e51187210a66713349c76c\",\"y\":\"10f76cae4eac6727bec6ae239de37d806a4877bc418f9fadaad0fd379cb11e73\"},\"p2\":{\"x\":\"caff57b3e214231182b2ba729079422887527dec2c2be1af03eb9a28be046fbb\",\"y\":\"94d4d2624a6be1e5fccf22ea5d7d2294a65f86b23642e7107c5523bb383d2612\"},\"paillier_pub\":{\"n\":\"11489233870088042333010221250016305472224248130131837344400358635737478519468920848276451747026121985401781804607266395846806728547165860151830628936151241253052105217375620729553123605998218501591757218904947955026013349855548130232876481464163645763380508660165838175358408923868455078398162478065282146744074902115770410655628975593804546170315851709066735895285416399351986223748741323752676766246912115655411869835426209804163120117240537098699118426250380831687194901410283437954378683229249501222250355118886953166922692541953136499596437296944964919863277847025337779172484000271289374153321801582770169915217\"},\"c_key\":\"13acbe9791ae6136f0d3700bad8cbe723ed2676e33d9f080122283a3a5838e3418d9ae3f61cc5e3b033ec71979f339c87e2da410c46a3a6238e40fc403799b5b7855bf529c381bd80288f5002f62a460cc005ec71e85c7d0eda2133245a857fe414c8653f0248016545618e2d53f466e3808edfe15774fb32ffeafc98dc08dd9eaca2e5411ae22bd4dad358bffadb51e82d2f99404ff73db8c473a2483133863aeaf6ffccd455fe4ba0966f90e85ea02083962d15779215941396676d90a0ce99a09adaa064956f506ca40d18ba91a7f9826a2e82050fb3b569790b5642ac45e39d9dfb63f8c975c30090f9eceaca387129539eaebfcedc17d2e49f0bd029e3591ac30e3db26139368b1423cf058e2128978411518e87c2d3c106a91c16de80895ad7f928a9a40c6d5aac356bd2966b3bf98c77f616f04329caecc895d13d16d8193e9f0bfe866c86a2eee3b2b0beb95478d4c216e00f8a9712618599d176ad253e59e9e27743f1e61a710bb9a0ae989226900ef809acb17e11f9f068bdb35fd7a767560e912da3aa98cd9d529b3d993e360d73f19adf830599f71ca139f6e17014302dce8a40401276d3a7e3dda04ef4b344a7dc4cb94c106c346e389ab7e089b97aa1e3f1680d4b8eeb62d405ab3a4e827b93dd15074e1dfd74244a9b4857017818b63504399c98fc02d0b3af135a0d7ac4f9de9a7cd47fdbe40cb3a6185b6\"}";
    pub static SHAREDPUBLIC: &str = "{\"x\":\"f8308498a5b5996eb7c410fb7ada7f3524d604b45b247cc4d13e5a32c3763908\",\"y\":\"7e41091fd5ab1138d1a3cdf41b43c82a064839a6b82b251be2be70099b642d1a\"}";

    pub fn test_sc_entity(db: MockDatabase, 
            lockbox_url: Option<String>, 
            rate_limit_slow: Option<NonZeroU32>,
            rate_limit_fast: Option<NonZeroU32>,
            rate_limit_id: Option<NonZeroU32>
    ) -> SCE {
        let mut config = Config::load().unwrap();
        config.lockbox = lockbox_url;
        config.rate_limit_slow = rate_limit_slow;
        config.rate_limit_fast = rate_limit_fast;
        config.rate_limit_id = rate_limit_id;

        let mut sc_entity = SCE::load(db, MemoryDB::new(""),Some(config)).unwrap();
        sc_entity.config.testing_mode = true;
        sc_entity.config.mainstay = Some(mainstay::MainstayConfig::mock_from_url(&test_url()));
        sc_entity
    }

    fn test_url() -> String {
        String::from(&mockito::server_url())
    }

    #[test]
    #[serial]
    fn test_verify_root() {
        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_root_update().returning(|_| Ok(1 as i64));
        db.expect_root_get_current_id().returning(|| Ok(1 as i64));
        db.expect_get_root().returning(|_| Ok(None));
        db.expect_root_get_current_id().returning(|| Ok(1 as i64));
        db.expect_get_root()
            .returning(|_x| Ok(Some(Root::from_random())));
        db.expect_root_update().returning(|_x| Ok(1));
        db.expect_get_confirmed_smt_root()
            .returning(|| Ok(Some(Root::from_random())));

        let sc_entity = test_sc_entity(db, None, None, None, None);

        //No commitments initially
        let _m = mocks::ms::commitment_proof_not_found();

        assert_eq!(sc_entity.get_smt_root().unwrap(), None, "expected Ok(None)");

        let com1 = mainstay::Commitment::from_str(
            "71c7f2f246caf3e4f0b94ea4ad54b6c506687069bf1e17024cd5961b0df78d6d",
        )
        .unwrap();

        let root1 = Root::from_hash(&com1.to_hash());

        assert_eq!(root1.hash(), com1.to_hash(), "expected roots to match");

        let _m_send = mocks::ms::post_commitment().create();

        let _root1_id = match sc_entity.update_root(&root1) {
            Ok(id) => id,
            Err(e) => {
                assert!(false, "{}", e.to_string());
                0
            }
        };

        // Root posted but not confirmed yet

        //Update the local copy of root1
        //let root1 = db_root_get(&db_read, &(root1_id as i64)).unwrap().unwrap();

        assert!(root1.is_confirmed() == false);

        //Some time later, the root is committed to mainstay
        let _m_com = mocks::ms::commitment().create();
        let _m_com_proof = mocks::ms::commitment_proof().create();

        //The root should be confirmed now
        let rootc = sc_entity.get_confirmed_smt_root().unwrap().unwrap();

        assert!(rootc.is_confirmed(), "expected the root to be confirmed");

        //let root1 = db_root_get(&db_read, &(root1_id as i64)).unwrap().unwrap();

        assert_eq!(
            rootc.hash(),
            root1.hash(),
            "expected equal Root hashes:\n{:?}\n\n{:?}",
            rootc,
            root1
        );

        assert!(rootc.is_confirmed(), "expected root to be confirmed");
    }

    #[test]
    #[serial]
    fn test_update_root_smt() {
        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_root_update().returning(|_| Ok(1 as i64));
        db.expect_root_get_current_id().returning(|| Ok(1 as i64));
        db.expect_get_root().returning(|_| Ok(None));
        db.expect_root_get_current_id().returning(|| Ok(1 as i64));
        db.expect_get_root()
            .returning(|_x| Ok(Some(Root::from_random())));
        db.expect_root_update().returning(|_x| Ok(1));
        db.expect_get_confirmed_smt_root()
            .returning(|| Ok(Some(Root::from_random())));
        let sc_entity = test_sc_entity(db, None, None, None, None);

        //Mainstay post commitment mock
        let _m = mocks::ms::post_commitment().create();

        let (_, new_root) = sc_entity
            .update_smt(
                &"1dcaca3b140dfbfe7e6a2d6d7cafea5cdb905178ee5d377804d8337c2c35f62e".to_string(),
                &"026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e".to_string(),
            )
            .unwrap();

        let hash_exp: [u8; 32] =
            hex::decode("cfeecaedcbaa90b750637ad2044b2e4b6425bd1430fc7250dceb28053a7e2733")
                .unwrap()[..]
                .try_into()
                .unwrap();

        assert_eq!(new_root.hash(), hash_exp, "new root incorrect");
    }

    #[test]
    #[serial]
    fn test_get_recovery_data() {
        let user_id = Uuid::new_v4();
        let statechain_id = Uuid::new_v4();
        let tx_backup = serde_json::from_str::<Transaction>(
                            &BACKUP_TX_SIGNED.to_string(),
                        ).unwrap();
        let amount = 1000;

        let recovery_data = RecoveryDataMsg {
            shared_key_id: user_id,
            statechain_id,
            amount,
            tx_hex: transaction_serialise(&tx_backup),
            proof_key: "03b2483ab9bea9843bd9bfb941e8c86c1308e77aa95fccd0e63c2874c0e3ead3f5".to_string(),
            shared_key_data: "".to_string(),
        };


        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_get_recovery_data().returning(move |key| {
            // return error to simulate no statecoin for key
            if key.len() == 0 {
                return Err(SEError::Generic("error".to_string()));
            }
            Ok(vec![(user_id,statechain_id,serde_json::from_str::<Transaction>(
                &BACKUP_TX_SIGNED.to_string(),
            ).unwrap())])
        });
        db.expect_get_statechain_amount().returning(move |_| {
            Ok(StateChainAmount {
                chain: serde_json::from_str::<StateChain>(&STATE_CHAIN.to_string()).unwrap(),
                amount: 10000,
            })
        });
        db.expect_get_backup_transaction().returning(move |_| {
            Ok(serde_json::from_str::<Transaction>(
                &BACKUP_TX_SIGNED.to_string(),
            ).unwrap())
        });
        db.expect_get_ecdsa_master().returning(move |_| {
            Ok(Some(MASTER_KEY.to_string()))
        });
        db.expect_get_public_master().returning(move |_| {
            Ok(Some(PARTY2PUBLIC.to_string()))
        });
        db.expect_get_statecoin_pubkey().returning(move |_| {
            Ok(Some(SHAREDPUBLIC.to_string()))
        });

        let sc_entity = test_sc_entity(db, None, None, None, None);

        // get_recovery invalid public key
        let recover_msg = vec!(RecoveryRequest {
            key: "0297901882fc1601c3ea2b5326c4e635455b5451573c619782502894df69e24548".to_string(),
            sig: "".to_string(),
        },RecoveryRequest {
            key: "".to_string(),
            sig: "".to_string(),
        });

        let recovery_return = sc_entity.get_recovery_data(recover_msg).unwrap();
        assert_eq!(recovery_return.len(), 1);
        assert_eq!(recovery_data.shared_key_id, recovery_return[0].shared_key_id);
        assert_eq!(recovery_data.statechain_id, recovery_return[0].statechain_id);
        assert_eq!(recovery_data.tx_hex,recovery_return[0].tx_hex);
    }
}
