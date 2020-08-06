//! StateEntity Utilities
//!
//! StateChain Entity protocol Utilites API calls trait and implementat. Also other non-trait
//! utility functions.

use super::{
    super::{Result, StateChainEntity},
    transfer_batch::{transfer_batch_is_ended, BatchTransfer},
};
extern crate shared_lib;
use shared_lib::{
    mocks::mock_electrum::MockElectrum,
    state_chain::*,
    structs::*,
    util::{get_sighash, tx_backup_verify, tx_withdraw_verify},
    Root,
    mainstay::Attestable,
    mainstay
};


use crate::error::{DBErrorType, SEError};
use crate::storage::db::{
    self,

    //db_deser, db_get_1, db_get_2, db_get_3, db_remove, db_root_get, db_root_get_current_id,
    //db_ser, db_update, 
    //Column, Table,
};
use crate::structs::*;
use crate::storage::Storage;
use crate::Database;
use cfg_if::cfg_if;

//cfg_if! {
//    if #[cfg(test)]{
//        use crate::MockDatabase as DB;
//    } else {
        use crate::PGDatabase as DB;
//    }
//}


use bitcoin::Transaction;
use chrono::NaiveDateTime;
//use db::root_update;
use electrumx_client::{electrumx_client::ElectrumxClient, interface::Electrumx};
use monotree::Proof;
use rocket::State;
use rocket_contrib::json::Json;
use std::{collections::HashMap, str::FromStr};
use std::{thread, time::Duration};
use uuid::Uuid;
#[cfg(test)]
use mockito::{mock, Matcher, Mock};

/// StateChain Entity Utilities API calls. Includes Information GET requests and prepare_sign_tx which
/// is used in all Protocols
pub trait Utilities {
    /// API: Return StateChain Entity fee information.
    fn get_fees(&self) -> Result<StateEntityFeeInfoAPI>;

    /// API: Generates sparse merkle tree inclusion proof for some key in a tree with some root.
    fn get_smt_proof(
        &self,
        smt_proof_msg: SmtProofMsgAPI,
    ) -> Result<Option<Proof>>;

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
    fn prepare_sign_tx(
        &self,
        prepare_sign_msg: PrepareSignTxMsg,
    ) -> Result<()>;
}

impl Utilities for StateChainEntity {
    fn get_fees(&self) -> Result<StateEntityFeeInfoAPI> {
        Ok(StateEntityFeeInfoAPI {
            address: self.fee_address.clone(),
            deposit: self.fee_deposit,
            withdraw: self.fee_withdraw,
        })
    }

    fn get_smt_proof(
        &self,
        smt_proof_msg: SmtProofMsgAPI,
    ) -> Result<Option<Proof>> {
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
            &self.smt_db_loc,
            &Some(smt_proof_msg.root.hash()),
            &smt_proof_msg.funding_txid,
        )?)
    }

  
    
    fn prepare_sign_tx(
        &self,
        prepare_sign_msg: PrepareSignTxMsg,
    ) -> Result<()> {
        let user_id = prepare_sign_msg.shared_key_id;
        self.check_user_auth(&user_id)?;

        // Which protocol are we signing for?
        match prepare_sign_msg.protocol {
            Protocol::Withdraw => {
                // Verify withdrawal has been authorised via presense of withdraw_sc_sig
                if let Err(_) = self.database.has_withdraw_sc_sig(user_id){
                    return Err(SEError::Generic(String::from(
                        "Withdraw has not been authorised. /withdraw/init must be called first.",
                    )));
                }

                // Verify unsigned withdraw tx to ensure co-sign will be signing the correct data
                tx_withdraw_verify(&prepare_sign_msg, &self.fee_address, &self.fee_withdraw)?;

                let tx_backup = self.database.get_backup_transaction(user_id)?;

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
                    &self.network,
                );

                self.database.update_withdraw_tx_sighash(&user_id, sig_hash, prepare_sign_msg.tx)?;

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
                    &self.network,
                );

                self.database.update_sighash(&user_id, sig_hash);

                
                // Only in deposit case add backup tx to UserSession
                if prepare_sign_msg.protocol == Protocol::Deposit {
                    self.database.update_user_backup_tx(&user_id, prepare_sign_msg.tx)?;
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

#[post("/info/fee", format = "json")]
pub fn get_fees(sc_entity: State<StateChainEntity>) -> Result<Json<StateEntityFeeInfoAPI>> {
    match sc_entity.get_fees() {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/info/statechain/<state_chain_id>", format = "json")]
pub fn get_statechain(
    sc_entity: State<StateChainEntity>,
    state_chain_id: String,
) -> Result<Json<StateChainDataAPI>> {
    match sc_entity.get_statechain_data_api(Uuid::from_str(&state_chain_id).unwrap()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/info/proof", format = "json", data = "<smt_proof_msg>")]
pub fn get_smt_proof(
    sc_entity: State<StateChainEntity>,
    smt_proof_msg: Json<SmtProofMsgAPI>,
) -> Result<Json<Option<Proof>>> {
    match sc_entity.get_smt_proof(smt_proof_msg.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/info/root", format = "json")]
pub fn get_smt_root(
    sc_entity: State<StateChainEntity>
) -> Result<Json<Option<Root>>> {
    match sc_entity.get_smt_root() {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/info/confirmed_root", format = "json")]
pub fn get_confirmed_smt_root(
    sc_entity: State<StateChainEntity>,
) -> Result<Json<Option<Root>>> {
    match sc_entity.get_confirmed_smt_root() {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/info/transfer-batch/<batch_id>", format = "json")]
pub fn get_transfer_batch_status(
    sc_entity: State<StateChainEntity>,
    batch_id: String,
) -> Result<Json<TransferBatchDataAPI>> {
    match sc_entity.get_transfer_batch_status(Uuid::from_str(&batch_id).unwrap()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/prepare-sign", format = "json", data = "<prepare_sign_msg>")]
pub fn prepare_sign_tx(
    sc_entity: State<StateChainEntity>,
    prepare_sign_msg: Json<PrepareSignTxMsg>,
) -> Result<Json<()>> {
    match sc_entity.prepare_sign_tx(prepare_sign_msg.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

// Utily functions for StateChainEntity to be used throughout codebase.
impl StateChainEntity {
    /// Query an Electrum Server for a transaction's confirmation status.
    /// Return Ok() if confirmed or Error if not after some waiting period.
    pub fn verify_tx_confirmed(&self, txid: &String, sc_entity: &StateChainEntity) -> Result<()> {
        let mut electrum: Box<dyn Electrumx> = if sc_entity.testing_mode {
            Box::new(MockElectrum::new())
        } else {
            Box::new(ElectrumxClient::new(sc_entity.electrum_server.clone()).unwrap())
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
                        thread::sleep(Duration::from_millis(sc_entity.block_time));
                    } else {
                        // If confs increase then wait 6*(block time) and return Ok()
                        info!(
                            "Funding transaction mined. Waiting for 6 blocks confirmation. Txid: {}",
                            txid
                        );
                        thread::sleep(Duration::from_millis(6 * sc_entity.block_time));
                        return Ok(());
                    }
                }
                Err(_) => {
                    is_broadcast += 1;
                    thread::sleep(Duration::from_millis(sc_entity.block_time));
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
        state_chain_id: Uuid,
    ) -> Result<()> {
        let sc_locked_until = self.database.get_sc_locked_until(state_chain_id)?;
        
        if is_locked(sc_locked_until).is_err() {
            return Err(SEError::Generic(String::from(
                "State chain is already locked. This should not be possible.",
            )));
        }

        self.database.update_locked_until(&state_chain_id, 
            &get_locked_until(self.punishment_duration as i64)?)?;

        info!(
            "PUNISHMENT: State Chain ID: {} locked for {}s.",
            state_chain_id, self.punishment_duration
        );
        Ok(())
    }

    /// Check if user has passed authentication.
    pub fn check_user_auth(&self, user_id: &Uuid) -> Result<()> {
        // check authorisation id is in DB (and TOOD: check password?)
        if let Err(_) = self.database.get_user_auth(*user_id) {
            return Err(SEError::AuthError);
        }
        Ok(())
    }

    fn get_transfer_batch_status(
        &self,
        batch_id: Uuid,
    ) -> Result<TransferBatchDataAPI> {
        //let batch_id = Uuid::from_str(&batch_id).unwrap();

        let tbd = self.database.get_transfer_batch_data(batch_id)?; 

        // Check if all transfers are complete. If so then all transfers in batch can be finalized.
        if !tbd.finalized {
            let mut state_chains_copy = tbd.state_chains.clone();
            state_chains_copy.retain(|_, &mut v| v == false);
            if state_chains_copy.len() == 0 {
                self.finalize_batch(batch_id)?;
                info!(
                    "TRANSFER_BATCH: All transfers complete in batch. Finalized. ID: {}.",
                    batch_id
                );
            }
            // Check batch is still within lifetime
            if transfer_batch_is_ended(tbd.start_time, self.batch_lifetime as i64) {
                let mut punished_state_chains: Vec<Uuid> = 
                    self.database.get_punished_state_chains(batch_id)?;
                
                
                if punished_state_chains.len() == 0 {
                    // Punishments not yet set
                    info!("TRANSFER_BATCH: Lifetime reached. ID: {}.", batch_id);
                    // Set punishments for all statechains involved in batch
                    for (state_chain_id, _) in tbd.state_chains {
                        self.state_chain_punish(state_chain_id.clone())?;
                        punished_state_chains.push(state_chain_id.clone());

                        // Remove TransferData involved. Ignore failed update err since Transfer data may not exist.
                        let _ = self.database.remove_transfer_data(&state_chain_id);
                        
                        info!(
                            "TRANSFER_BATCH: Transfer data deleted. State Chain ID: {}.",
                            state_chain_id
                        );
                    }

                    self.database.update_punished(&batch_id, punished_state_chains)?;

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
            state_chains: tbd.state_chains,
            finalized: tbd.finalized,
        })
    }
}

impl Storage for StateChainEntity {

     /// Update the database and the mainstay slot with the SMT root, if applicable
     fn update_root(&self, root: &Root) -> Result<i64> {
        
        match &self.mainstay_config {
            Some(c) => match root.attest(&c) {
                Ok(_) => (),
                Err(e) => return Err(SEError::SharedLibError(e.to_string())),
            },
            None => (),
        };

        let id = self.database.root_update(root)?;
        Ok(id)
        
     }

    // Update SMT with new (key: value) pair and update current root value
    fn update_smt(
        &self,
        funding_txid: &String,
        proof_key: &String,
    ) -> Result<(Option<Root>, Root)> {
        //Use the mock database trait if in test mode
        //cfg_if! {
        //    if #[cfg(test)]{
                //Create a new mock database
        //        let mut db = DB::get_test();
                // Set the expectations
                //Current id is 0
        //        db.expect_root_get_current_id().returning(|| Ok(0 as i64));
                //Current root is randomly chosen
         //       db.expect_get_root().returning(|x| Ok(Some(Root::from_random())));
         //   } else {
                let db = &self.database;
         //   }
        //}

        //If mocked out current_root will be randomly chosen
        let current_root = db.get_root(db.root_get_current_id()?)?;
        let new_root_hash = update_statechain_smt(
            &self.smt_db_loc,
            &current_root.clone().map(|r| r.hash()),
            funding_txid,
            proof_key,
        )?;

        let new_root = Root::from_hash(&new_root_hash.unwrap());
        self.update_root(&new_root)?; // Update current root

        Ok((current_root, new_root))
    }

    fn get_smt_root(&self) -> Result<Option<Root>> {
        Ok(self.database.get_root(self.database.root_get_current_id()?)?)
    }

    /// Update the database with the latest available mainstay attestation info
    fn get_confirmed_smt_root(&self) -> Result<Option<Root>> {
        use crate::shared_lib::mainstay::{Commitment, CommitmentIndexed, 
            CommitmentInfo, MainstayAPIError};

        //cfg_if!{
        //    if #[cfg(test)]{
                //Create a new mock database
        //        let db = &DB::get_test();
       //     } else {
                let db = &self.database;
       //     }
       // }


        fn update_db_from_ci(
            db: &DB,
            ci: &CommitmentInfo,
            ) -> Result<Option<Root>> {
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
                    Ok(_) => {
                        Ok(Some(root))
                    }
                    Err(e) => Err(e),
                }
            }
    

            match &self.mainstay_config {
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
                                        update_db_from_ci(&db, ci)
                                    }
                                }
                                None => update_db_from_ci(&db, ci),
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
                                                Err(e) => match e.downcast_ref::<MainstayAPIError>() {
                                                    Some(e) => match e {
                                                        MainstayAPIError::NotFoundError(_) => (),
                                                        _ => {
                                                            return Err(SEError::Generic(e.to_string()))
                                                        }
                                                    },
                                                    None => {
                                                        return Err(SEError::Generic(e.to_string()))
                                                    }
                                                },
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
                        Ok(ci) => update_db_from_ci(&db,ci),
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


    fn get_statechain(&self, state_chain_id: Uuid) -> Result<StateChain> {
        self.database.get_statechain(state_chain_id)
    }

    fn get_statechain_data_api(
        &self,
        state_chain_id: Uuid,
    ) -> Result<StateChainDataAPI> {
        
        //let state_chain_id = Uuid::from_str(&state_chain_id).unwrap();

        let state_chain = self.database.get_statechain_amount(state_chain_id)?;
        let tx_backup = self.database.get_backup_transaction(state_chain_id)?;
        
        Ok({
            StateChainDataAPI {
                amount: state_chain.amount as u64,
                utxo: tx_backup.input.get(0).unwrap().previous_output,
                chain: state_chain.chain.chain,
            }
        })
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
    //fn update_locked_until(&self, state_chain_id: &Uuid, time: &NaiveDateTime);

    //Update the list of punished state chains
    //fn update_punished(&self, punished: &Vec<Uuid>);

}

#[cfg(test)]
mod mocks {
    use super::{Mock,Matcher,mock};

    pub mod ms {
        use super::*;
        pub fn commitment_proof_not_found() -> Mock {
            mock("GET", Matcher::Regex(r"^/commitment/commitment\?commitment=[abcdef\d]{64}".to_string()))

               .with_header("Content-Type", "application/json")
                .with_body("{\"error\":\"Not found\",\"timestamp\":1596123963077,
                \"allowance\":{\"cost\":3796208}}")
        }

        pub fn post_commitment() -> Mock {
            mock("POST", "/commitment/send")
            .match_header("content-type", "application/json")
            .with_body(serde_json::json!({"response":"Commitment added","timestamp":1541761540,
            "allowance":{"cost":4832691}}).to_string())
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
mod tests {

    use std::str::FromStr;
    use super::*;
    use super::super::super::server::get_settings_as_map;
    use super::super::super::StateChainEntity;

    fn test_sc_entity() -> StateChainEntity {
        let mut sc_entity = StateChainEntity::load(get_settings_as_map()).unwrap();
        sc_entity.mainstay_config = mainstay::Config::from_test();
        sc_entity
    }

    fn test_url() -> String {
        String::from(&mockito::server_url())
    }

    #[test]
    #[serial]
    fn test_verify_root() {
        let sc_entity = test_sc_entity();
        let mc = Some(mainstay::Config::mock_from_url(&test_url()));

        //No commitments initially
        let _m = mocks::ms::commitment_proof_not_found();

        assert_eq!(sc_entity.get_smt_root().unwrap(), None, "expected Ok(None)");

        let com1 = mainstay::Commitment::from_str(
            "71c7f2f246caf3e4f0b94ea4ad54b6c506687069bf1e17024cd5961b0df78d6d")
            .unwrap();

        let root1 = Root::from_hash(&com1.to_hash());

        assert_eq!(root1.hash(), com1.to_hash(), "expected roots to match");

        let _m_send = mocks::ms::post_commitment().create();

        let _root1_id = match sc_entity.update_root(&root1) {
            Ok(id) => id,
            Err(e) => {
                assert!(false, e.to_string());
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

        assert_eq!(rootc.hash(), root1.hash(), "expected equal Root hashes:\n{:?}\n\n{:?}", rootc, root1);

        assert!(rootc.is_confirmed(), "expected root to be confirmed");
    }

    #[test]
    #[serial]
    fn test_update_root_smt() {
        let db = DB::get_test();        
        let sc_entity = test_sc_entity();

        let (_, new_root) = sc_entity.update_smt(
            &"1dcaca3b140dfbfe7e6a2d6d7cafea5cdb905178ee5d377804d8337c2c35f62e".to_string(),
            &"026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e".to_string(),
        )
        .unwrap();

        let current_root = sc_entity.get_root(db.root_get_current_id().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(new_root.hash(), current_root.hash());

    }
}
