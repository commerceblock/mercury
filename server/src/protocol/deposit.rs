//! StateEntity Deposit
//!
//! StateEntity Deposit trait and implementation for StateChainEntity.

use super::super::{Result, StateChainEntity};
extern crate shared_lib;
use crate::error::SEError;
use crate::storage::db::{db_deser, db_get_2, db_insert, db_ser, db_update, Column, Table};
use crate::{DatabaseR, DatabaseW};
use bitcoin::Transaction;
use shared_lib::{state_chain::*, structs::*, util::FEE};

use rocket::State;
use rocket_contrib::json::Json;
use uuid::Uuid;

/// StateChain Deposit protocol trait
pub trait Deposit {
    /// API: Initiliase deposit protocol:
    ///     - Generate and return shared wallet ID
    ///     - Can do auth or other DoS mitigation here
    fn deposit_init(&self, db_write: DatabaseW, deposit_msg1: DepositMsg1) -> Result<Uuid>;

    /// API: Complete deposit protocol:
    ///     - Wait for confirmation of funding tx in blockchain
    ///     - Create StateChain DB object
    ///     - Update sparse merkle tree with new StateChain entry
    fn deposit_confirm(
        &self,
        db_read: DatabaseR,
        db_write: DatabaseW,
        deposit_msg2: DepositMsg2,
    ) -> Result<Uuid>;
}

impl Deposit for StateChainEntity {
    fn deposit_init(&self, db_write: DatabaseW, deposit_msg1: DepositMsg1) -> Result<Uuid> {
        // Generate shared wallet ID (user ID)
        let user_id = Uuid::new_v4();

        // if Verification/PoW/authoriation failed {
        //      warn!("Failed authorisation.")
        //      Err(SEError::AuthError)
        //  }

        // Create DB entry for newly generated ID signalling that user has passed some
        // verification. For now use ID as 'password' to interact with state entity
        db_insert(&db_write, &user_id, Table::UserSession)?;
        db_update(
            &db_write,
            &user_id,
            Table::UserSession,
            vec![Column::Authentication, Column::ProofKey],
            vec![
                &deposit_msg1.auth.clone(),
                &deposit_msg1.proof_key.to_owned(),
            ],
        )?;

        info!(
            "DEPOSIT: Protocol initiated. User ID generated: {}",
            user_id
        );
        debug!(
            "DEPOSIT: User ID: {} corresponding Proof key: {}",
            user_id,
            deposit_msg1.proof_key.to_owned()
        );

        Ok(user_id)
    }

    fn deposit_confirm(
        &self,
        db_read: DatabaseR,
        db_write: DatabaseW,
        deposit_msg2: DepositMsg2,
    ) -> Result<Uuid> {
        // let shared_key_id = deposit_msg2.shared_key_id.clone();
        let user_id = deposit_msg2.shared_key_id;

        // Get back up tx and proof key
        let (tx_backup_str, proof_key) = db_get_2::<String, String>(
            &db_read,
            &user_id,
            Table::UserSession,
            vec![Column::TxBackup, Column::ProofKey],
        )?;
        let tx_backup: Transaction = db_deser(tx_backup_str)?;

        // Ensure backup tx exists is signed
        if tx_backup.input[0].witness.len() == 0 {
            return Err(SEError::Generic(String::from(
                "Signed Back up transaction not found.",
            )));
        }

        // Wait for funding tx existence in blockchain and confs
        self.verify_tx_confirmed(&tx_backup.input[0].previous_output.txid.to_string(), self)?;

        // Create state chain DB object
        let state_chain_id = Uuid::new_v4();
        let amount = (tx_backup.output.last().unwrap().value + FEE) as i64;
        let state_chain = StateChain::new(proof_key.clone());

        // Insert into StateChain table
        db_insert(&db_write, &state_chain_id, Table::StateChain)?;
        db_update(
            &db_write,
            &state_chain_id,
            Table::StateChain,
            vec![
                Column::Chain,
                Column::Amount,
                Column::LockedUntil,
                Column::OwnerId,
            ],
            vec![
                &db_ser(state_chain)?,
                &amount,
                &get_time_now(),
                &user_id.to_owned(),
            ],
        )?;

        // Insert into BackupTx table
        db_insert(&db_write, &state_chain_id, Table::BackupTxs)?;
        db_update(
            &db_write,
            &state_chain_id,
            Table::BackupTxs,
            vec![Column::TxBackup],
            vec![&db_ser(tx_backup.clone())?],
        )?;

        info!(
            "DEPOSIT: State Chain created. ID: {} For user ID: {}",
            state_chain_id, user_id
        );

        // Update sparse merkle tree with new StateChain entry
        let (new_root, current_root) = self.update_smt_db(
            &db_read,
            &db_write,
            &tx_backup
                .input
                .get(0)
                .unwrap()
                .previous_output
                .txid
                .to_string(),
            &proof_key,
        )?;

        info!(
            "DEPOSIT: Included in sparse merkle tree. State Chain ID: {}",
            state_chain_id
        );
        debug!(
            "DEPOSIT: State Chain ID: {}. New root: {:?}. Previous root: {:?}.",
            state_chain_id, new_root, current_root
        );

        // Update UserSession with StateChain's ID
        db_update(
            &db_write,
            &user_id,
            Table::UserSession,
            vec![Column::StateChainId],
            vec![&state_chain_id],
        )?;

        Ok(state_chain_id)
    }
}

#[post("/deposit/init", format = "json", data = "<deposit_msg1>")]
pub fn deposit_init(
    sc_entity: State<StateChainEntity>,
    db_write: DatabaseW,
    deposit_msg1: Json<DepositMsg1>,
) -> Result<Json<Uuid>> {
    match sc_entity.deposit_init(db_write, deposit_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/deposit/confirm", format = "json", data = "<deposit_msg2>")]
pub fn deposit_confirm(
    sc_entity: State<StateChainEntity>,
    db_read: DatabaseR,
    db_write: DatabaseW,
    deposit_msg2: Json<DepositMsg2>,
) -> Result<Json<Uuid>> {
    match sc_entity.deposit_confirm(db_read, db_write, deposit_msg2.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}
