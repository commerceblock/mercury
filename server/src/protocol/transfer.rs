//! StateEntity Transfer
//!
//! StateEntity Transfer protocol trait and implementation.

use super::{
    super::Result,
    transfer_batch::transfer_batch_is_ended,
};

extern crate shared_lib;
use crate::error::SEError;
<<<<<<< HEAD
use crate::{
    storage::db::{
        db_deser, db_get_1, db_get_2, db_get_3, db_insert, db_remove, db_ser, db_update, Column,
        Table,
    },
    DatabaseR, DatabaseW, server::StateChainEntity,
};
=======
//use crate::{
    //storage::db::{
        //db_deser, db_get_1, db_get_2, db_get_3, db_insert, db_remove, db_ser, db_update, 
        //Column,
        //Table,
    //},
    //DatabaseR, DatabaseW,
//};
use crate::storage::db;
use crate::Database;
>>>>>>> 87681e6c8fc0a82806b665c559e624acaac9cb39
use shared_lib::{state_chain::*, structs::*};
use crate::storage::Storage;

use bitcoin::Transaction;
use chrono::NaiveDateTime;
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    {BigInt, FE, GE},
};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one::Party1Private;
use rocket::State;
use rocket_contrib::json::Json;
use std::collections::HashMap;
use uuid::Uuid;

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

/// StateChain Transfer protocol trait
pub trait Transfer {
    /// API: Initiliase transfer protocol:
    ///     - Authorisation of Owner and DoS protection
    ///     - Validate transfer parameters
    ///     - Store transfer parameters
    fn transfer_sender(
        &self,
        transfer_msg1: TransferMsg1,
    ) -> Result<TransferMsg2>;

    /// API: Transfer shared wallet to new Owner:
    ///     - Check new Owner's state chain is correct
    ///     - Perform 2P-ECDSA key rotation
    ///     - Return new public shared key S2
    fn transfer_receiver(
        &self,
        transfer_msg4: TransferMsg4,
    ) -> Result<TransferMsg5>;

    /// Update DB and SMT after successful transfer.
    /// This function is called immediately in the regular transfer case or after confirmation of atomic
    /// transfers completion in the batch transfer case.
    fn transfer_finalize(
        &self,
        finalized_data: &TransferFinalizeData,
    ) -> Result<()>;
}

impl Transfer for StateChainEntity {
    fn transfer_sender(
        &self,
        transfer_msg1: TransferMsg1,
    ) -> Result<TransferMsg2> {
        let user_id = transfer_msg1.shared_key_id;
        self.check_user_auth(&user_id)?;

        info!("TRANSFER: Sender Side. Shared Key ID: {}", user_id);

        // Get state_chain id
        let state_chain_id = self.database.get_statechain_id(user_id)?;

        // Check if transfer has already been completed (but not finalized)
        if self.database.transfer_is_completed(state_chain_id){    
            return Err(SEError::Generic(String::from(
                "Transfer already completed. Waiting for finalize.",
            )));
        }

        // Check if state chain is owned by user and not locked
        let sco = self.database.get_statechain_owner(state_chain_id)?;

        is_locked(sco.locked_until)?;
        if sco.owner_id != user_id {
            return Err(SEError::Generic(format!(
                "State Chain not owned by User ID: {}.",
                user_id
            )));
        }

        // Generate x1
        let x1: FE = ECScalar::new_random();

        self.database.create_transfer(&state_chain_id, &transfer_msg1.state_chain_sig, &x1)?;

        info!(
            "TRANSFER: Sender side complete. Previous shared key ID: {}. State Chain ID: {}",
            user_id.to_string(),
            state_chain_id
        );
        debug!("TRANSFER: Sender side complete. State Chain ID: {}. State Chain Signature: {:?}. x1: {:?}.", state_chain_id, transfer_msg1.state_chain_sig, x1);

        // TODO encrypt x1 with Senders proof key

        Ok(TransferMsg2 { x1 })
    }

    fn transfer_receiver(
        &self,
        transfer_msg4: TransferMsg4,
    ) -> Result<TransferMsg5> {
        let user_id = transfer_msg4.shared_key_id;
        let state_chain_id = transfer_msg4.state_chain_id;

        info!("TRANSFER: Receiver side. Shared Key ID: {}", user_id);

        // Get Transfer Data for state_chain_id
        let td = self.database.get_transfer_data(state_chain_id)?;

        // Ensure state_chain_sigs are the same
        if td.state_chain_sig != transfer_msg4.state_chain_sig.to_owned() {
            return Err(SEError::Generic(format!(
                "State chain siganture provided does not match state chain at id {}",
                state_chain_id
            )));
        }

        let kp = self.database.get_ecdsa_keypair(user_id)?;


        // TODO: decrypt t2

        // let x1 = transfer_data.x1;
        let t2 = transfer_msg4.t2;
        let s1 = kp.party_1_private.get_private_key();

        // Note:
        //  s2 = o1*o2_inv*s1
        //  t2 = o1*x1*o2_inv
        let s2 = t2 * (td.x1.invert()) * s1;

        // Check s2 is valid for Lindell protocol (s2<q/3)
        let sk_bigint = s2.to_big_int();
        let q_third = FE::q();
        if sk_bigint >= q_third.div_floor(&BigInt::from(3)) {
            return Err(SEError::Generic(format!("Invalid o2, try again.")));
        }

        let g: GE = ECPoint::generator();
        let s2_pub: GE = g * s2;

        let p1_pub = kp.party_2_public * s1;
        let p2_pub = transfer_msg4.o2_pub * s2;

        // Check P1 = o1_pub*s1 === p2 = o2_pub*s2
        if p1_pub != p2_pub {
            error!("TRANSFER: Protocol failed. P1 != P2.");
            return Err(SEError::Generic(String::from(
                "Transfer protocol error: P1 != P2",
            )));
        }

        // Create user ID for new UserSession (receiver of transfer)
        let new_shared_key_id = Uuid::new_v4();

        let finalized_data = TransferFinalizeData {
            new_shared_key_id: new_shared_key_id.clone(),
            state_chain_id: state_chain_id.clone(),
            state_chain_sig: td.state_chain_sig,
            s2,
            new_tx_backup: transfer_msg4.tx_backup.clone(),
            batch_data: transfer_msg4.batch_data.clone(),
        };

        // If batch transfer then mark StateChain as complete and store finalized data in TransferBatch table.
        // This is so the transfers can be finalized when all transfers in the batch are complete.
        if transfer_msg4.batch_data.is_some() {
            let batch_id = transfer_msg4.batch_data.clone().unwrap().id;
            info!(
                "TRANSFER: Transfer as part of batch {}. State Chain ID: {}",
                batch_id, state_chain_id
            );
            // Get TransferBatch data
            let mut tbd = self.database.get_finalize_batch_data(batch_id)?;

            // Ensure batch transfer is still active
<<<<<<< HEAD
            if transfer_batch_is_ended(start_time, self.config.batch_lifetime as i64) {
=======
            if transfer_batch_is_ended(tbd.start_time, self.batch_lifetime as i64) {
>>>>>>> 87681e6c8fc0a82806b665c559e624acaac9cb39
                return Err(SEError::Generic(String::from(
                    "Transfer batch ended. Too late to complete transfer.",
                )));
            }

            tbd.state_chains.insert(state_chain_id.clone(), true);
            tbd.finalized_data_vec.push(finalized_data.clone());

            self.database.update_finalize_batch_data(&batch_id, tbd.state_chains, 
                                                        tbd.finalized_data_vec)?;

        // If not batch then finalize transfer now
        } else {
            // Update DB and SMT with new transfer data
            self.transfer_finalize(&finalized_data)?;
        }

        info!(
            "TRANSFER: Receiver side complete. State Chain ID: {}",
            new_shared_key_id
        );
        debug!("TRANSFER: Receiver side complete. State Chain ID: {}. New Shared Key ID: {}. Finalized data: {:?}",state_chain_id,state_chain_id,finalized_data);

        Ok(TransferMsg5 {
            new_shared_key_id,
            s2_pub,
        })
    }

    /// Update DB and SMT after successful transfer.
    /// This function is called immediately in the regular transfer case or after confirmation of atomic
    /// transfers completion in the batch transfer case.
    fn transfer_finalize(
        &self,
        finalized_data: &TransferFinalizeData,
    ) -> Result<()> {
        let state_chain_id = finalized_data.state_chain_id;

        info!("TRANSFER_FINALIZE: State Chain ID: {}", state_chain_id);

        // Update state chain
        let mut state_chain: StateChain = self.database.get_statechain(state_chain_id)?;
    
        state_chain.add(finalized_data.state_chain_sig.to_owned())?;

        
        let new_user_id = finalized_data.new_shared_key_id;

        self.database.update_statechain_owner(&state_chain_id, 
            state_chain.clone(), &new_user_id)?;

        // Create new UserSession to allow new owner to generate shared wallet

        self.database.transfer_init_user_session(&new_user_id, &state_chain_id, 
            finalized_data.to_owned())?;
            

        self.database.update_backup_tx(&state_chain_id, finalized_data.new_tx_backup.to_owned())?;
      

        info!(
            "TRANSFER: Finalized. New shared key ID: {}. State Chain ID: {}",
            finalized_data.new_shared_key_id, state_chain_id
        );

        // Update sparse merkle tree with new StateChain entry
        let (new_root, prev_root) = self.update_smt(
            &finalized_data
                .new_tx_backup
                .input
                .get(0)
                .unwrap()
                .previous_output
                .txid
                .to_string(),
                &state_chain
                .chain
                .last()
                .ok_or(SEError::Generic(String::from("StateChain empty")))?
                .data
                .clone()
        )?;

        info!(
            "TRANSFER: Included in sparse merkle tree. State Chain ID: {}",
            state_chain_id
        );
        debug!(
            "TRANSFER: State Chain ID: {}. New root: {:?}. Previous root: {:?}.",
            state_chain_id, &new_root, &prev_root
        );

        // Remove TransferData for this transfer
        self.database.remove_transfer_data(&state_chain_id)?;

        Ok(())
    }
}

#[post("/transfer/sender", format = "json", data = "<transfer_msg1>")]
pub fn transfer_sender(
    sc_entity: State<StateChainEntity>,
    transfer_msg1: Json<TransferMsg1>,
) -> Result<Json<TransferMsg2>> {
    match sc_entity.transfer_sender(transfer_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/transfer/receiver", format = "json", data = "<transfer_msg4>")]
pub fn transfer_receiver(
    sc_entity: State<StateChainEntity>,
    transfer_msg4: Json<TransferMsg4>,
) -> Result<Json<TransferMsg5>> {
    match sc_entity.transfer_receiver(transfer_msg4.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}
