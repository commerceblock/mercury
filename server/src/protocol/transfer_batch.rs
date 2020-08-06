//! StateEntity Batch Transfer
//!
//! StateEntity Batch Transfer protocol trait and implementation.

use super::{
    super::{Result, StateChainEntity},
    transfer::{Transfer, TransferFinalizeData},
};

extern crate shared_lib;
use crate::error::SEError;
use crate::{
    //storage::db::{
        //db_deser, db_get_1, db_get_2, db_get_4, db_insert, db_ser, db_update, Column, Table,
    //},
    //DatabaseR, DatabaseW,
    Database
};
use shared_lib::{commitment::verify_commitment, state_chain::*, structs::*};

use chrono::{NaiveDateTime, Utc};
use rocket::State;
use rocket_contrib::json::Json;
use std::{collections::HashMap, str::FromStr};
use uuid::Uuid;

/// StateChain BatchTransfer protocol trait
pub trait BatchTransfer {
    /// API: Request setup of a batch transfer.
    ///     - Verify all signatures
    ///     - Create TransferBatchData DB object
    fn transfer_batch_init(
        &self,
        transfer_batch_init_msg: TransferBatchInitMsg,
    ) -> Result<()>;

    /// Finalize all transfers in a batch if all are complete and validated.
    fn finalize_batch(
        &self,
        batch_id: Uuid,
    ) -> Result<()>;

    /// API: Reveal a nonce for a corresponding Transfer commitment.
    fn transfer_reveal_nonce(
        &self,
        transfer_reveal_nonce: TransferRevealNonce,
    ) -> Result<()>;
}

impl BatchTransfer for StateChainEntity {
    fn transfer_batch_init(
        &self,
        transfer_batch_init_msg: TransferBatchInitMsg,
    ) -> Result<()> {
        let batch_id = transfer_batch_init_msg.id.clone();
        info!("TRANSFER_BATCH_INIT: ID: {}", batch_id);

        if self.database.has_transfer_batch_id(batch_id) {
            return Err(SEError::Generic(format!(
                "Batch transfer with ID {} already exists.",
                batch_id.to_string()
            )));
        }

        // Ensure sigs purpose is for batch transfer
        for sig in &transfer_batch_init_msg.signatures {
            if !sig.purpose.contains("TRANSFER_BATCH") {
                return Err(SEError::Generic(String::from(
                    "Signture's purpose is not valid for batch transfer.",
                )));
            }
        }

        let mut state_chains = HashMap::<Uuid, bool>::new();
        for sig in transfer_batch_init_msg.signatures.clone() {
            // Ensure sig is for same batch as others
            if &sig.clone().purpose[15..] != batch_id.to_string() {
                return Err(SEError::Generic(String::from(
                    "Batch id is not identical for all signtures.",
                )));
            }

            let state_chain_id = Uuid::from_str(&sig.data).unwrap();
            let sco = self.database.get_statechain_owner(state_chain_id)?;

            // Verify sigs
            let proof_key = sco.chain.get_tip()?.data;
            sig.verify(&proof_key)?;

            // Ensure state chains are all available
            is_locked(sco.locked_until)?;

            // Add to TransferBatchData object
            state_chains.insert(state_chain_id, false);
        }

        // Create new TransferBatchData and add to DB
        self.database.create_transfer_batch_data(
            &batch_id,
            state_chains)?;


        info!("TRANSFER_BATCH_INIT: Batch ID {} initiated.", batch_id);
        debug!(
            "TRANSFER_BATCH_INIT: Batch ID {}. Signatures: {:?}.",
            batch_id, transfer_batch_init_msg.signatures
        );

        Ok(())
    }

    fn finalize_batch(
        &self,
        batch_id: Uuid,
    ) -> Result<()> {
        info!("TRANSFER_FINALIZE_BATCH: ID: {}", batch_id);
      
        let fbd = self.database.get_finalize_batch_data(batch_id)?;


        if fbd.state_chains.len() != fbd.finalized_data_vec.len() {
            return Err(SEError::Generic(String::from(
                "TransferBatch has unequal finalized data to state chains.",
            )));
        }

        for finalized_data in fbd.finalized_data_vec.clone() {
            self.transfer_finalize(&finalized_data)?;
        }

        self.database.update_transfer_batch_finalized(&batch_id, &true)?;

        Ok(())
    }

    fn transfer_reveal_nonce(
        &self,
        transfer_reveal_nonce: TransferRevealNonce,
    ) -> Result<()> {
        let batch_id = transfer_reveal_nonce.batch_id;
        let state_chain_id = transfer_reveal_nonce.state_chain_id;
        info!(
            "TRANSFER_REVEAL_NONCE: Batch ID: {}. State Chain ID: {}",
            batch_id, state_chain_id
        );

        let tbd = self.database.get_transfer_batch_data(batch_id)?;

        if tbd.finalized {
            return Err(SEError::Generic(String::from(
                "Transfer Batch completed successfully.",
            )));
        }

        if !transfer_batch_is_ended(tbd.start_time, self.batch_lifetime as i64) {
            return Err(SEError::Generic(String::from("Transfer Batch still live.")));
        }

        if tbd.state_chains.get(&state_chain_id).is_none() {
            return Err(SEError::Generic(String::from(
                "State chain ID not in this batch.",
            )));
        }

        verify_commitment(
            &transfer_reveal_nonce.hash,
            &state_chain_id.to_string(),
            &transfer_reveal_nonce.nonce,
        )?;

        // If state chain completed + commitment revealed then punishment can be removed from state chain
        if *tbd.state_chains.get(&state_chain_id).unwrap() {
            self.database.update_locked_until(&state_chain_id, &get_time_now())?;
            info!(
                "TRANSFER_REVEAL_NONCE: State Chain unlocked. ID: {}",
                state_chain_id
            );

            // remove from transfer batch punished list
            let mut new_punished = tbd.punished_state_chains.clone();
            new_punished.retain(|x| x != &state_chain_id);
            self.database.update_punished(&batch_id, new_punished)?;
        }
        Ok(())
    }
}

/// Check if Transfer Batch is out of time
pub fn transfer_batch_is_ended(start_time: NaiveDateTime, batch_lifetime: i64) -> bool {
    let current_time = Utc::now().naive_utc().timestamp();

    if current_time - start_time.timestamp() > batch_lifetime {
        return true;
    }
    false
}

#[post(
    "/transfer/batch/init",
    format = "json",
    data = "<transfer_batch_init_msg>"
)]
pub fn transfer_batch_init(
    sc_entity: State<StateChainEntity>,
    transfer_batch_init_msg: Json<TransferBatchInitMsg>,
) -> Result<Json<()>> {
    match sc_entity.transfer_batch_init(transfer_batch_init_msg.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post(
    "/transfer/batch/reveal",
    format = "json",
    data = "<transfer_reveal_nonce>"
)]
pub fn transfer_reveal_nonce(
    sc_entity: State<StateChainEntity>,
    transfer_reveal_nonce: Json<TransferRevealNonce>,
) -> Result<Json<()>> {
    match sc_entity.transfer_reveal_nonce(transfer_reveal_nonce.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}
