//! StateEntity Withdraw
//!
//! StateEntity Withdraw protocol trait and implementation for StateChainEntity.

use super::super::Result;
extern crate shared_lib;
use shared_lib::{state_chain::*, structs::*};

use crate::error::SEError;
use crate::storage::db::{db_deser, db_get_1, db_get_3, db_ser, db_update, Column, Table};
use crate::{DatabaseR, DatabaseW, server::StateChainEntity};

use bitcoin::Transaction;
use chrono::NaiveDateTime;
use rocket::State;
use rocket_contrib::json::Json;
use uuid::Uuid;

/// StateChain Withdraw protocol trait
pub trait Withdraw {
    /// User request withdraw:
    ///     - Check StateChainSig validity
    ///     - Mark user as authorised to withdraw
    fn withdraw_init(
        &self,
        db_read: DatabaseR,
        db_write: DatabaseW,
        withdraw_msg1: WithdrawMsg1,
    ) -> Result<()>;

    /// Finish withdrawal:
    ///     - Ensure withdraw tx has been signed
    ///     - Update UserSession, StateChain and Sparse merkle tree
    ///     - Return withdraw tx signature
    fn withdraw_confirm(
        &self,
        db_read: DatabaseR,
        db_write: DatabaseW,
        withdraw_msg2: WithdrawMsg2,
    ) -> Result<Vec<Vec<u8>>>;
}

impl Withdraw for StateChainEntity {
    fn withdraw_init(
        &self,
        db_read: DatabaseR,
        db_write: DatabaseW,
        withdraw_msg1: WithdrawMsg1,
    ) -> Result<()> {
        let user_id = withdraw_msg1.shared_key_id;
        self.check_user_auth(&db_read, &user_id)?;

        info!("WITHDRAW: Init. Shared Key ID: {}", user_id);

        let (state_chain_id) = db_get_1::<Uuid>(
            &db_read,
            &user_id,
            Table::UserSession,
            vec![Column::StateChainId],
        )?;

        // Get statechain
        let (sc_locked_until, sc_owner_id, state_chain_str) =
            db_get_3::<NaiveDateTime, Uuid, String>(
                &db_read,
                &state_chain_id,
                Table::StateChain,
                vec![Column::LockedUntil, Column::OwnerId, Column::Chain],
            )?;
        let state_chain: StateChain = db_deser(state_chain_str)?;
        // Check if locked
        is_locked(sc_locked_until)?;
        // check if owned by caller
        if sc_owner_id != user_id {
            return Err(SEError::Generic(format!(
                "State Chain not owned by User ID: {}.",
                state_chain_id
            )));
        }

        // Verify new StateChainSig
        let prev_proof_key = state_chain.get_tip()?.data;
        withdraw_msg1.state_chain_sig.verify(&prev_proof_key)?;

        // Mark UserSession as authorised for withdrawal
        db_update(
            &db_write,
            &user_id,
            Table::UserSession,
            vec![Column::WithdrawScSig],
            vec![&db_ser(withdraw_msg1.state_chain_sig.clone())?],
        )?;

        info!(
            "WITHDRAW: Authorised. Shared Key ID: {}. State Chain: {}",
            user_id, state_chain_id
        );

        Ok(())
    }

    fn withdraw_confirm(
        &self,
        db_read: DatabaseR,
        db_write: DatabaseW,
        withdraw_msg2: WithdrawMsg2,
    ) -> Result<Vec<Vec<u8>>> {
        let user_id = withdraw_msg2.shared_key_id;
        info!("WITHDRAW: Confirm. Shared Key ID: {}", user_id.to_string());

        // Get UserSession data - Checking that withdraw tx and statechain signature exists
        let (tx_withdraw_str, withdraw_sc_sig_str, state_chain_id) =
            db_get_3::<String, String, Uuid>(
                &db_read,
                &user_id,
                Table::UserSession,
                vec![
                    Column::TxWithdraw,
                    Column::WithdrawScSig,
                    Column::StateChainId,
                ],
            )?;
        let tx_withdraw: Transaction = db_deser(tx_withdraw_str)?;
        let withdraw_sc_sig: StateChainSig = db_deser(withdraw_sc_sig_str)?;

        // Get statechain and update with final StateChainSig
        let mut state_chain: StateChain = db_deser(db_get_1(
            &db_read,
            &state_chain_id,
            Table::StateChain,
            vec![Column::Chain],
        )?)?;

        state_chain.add(withdraw_sc_sig.to_owned())?;

        db_update(
            &db_write,
            &state_chain_id,
            Table::StateChain,
            vec![Column::Chain, Column::Amount],
            vec![&db_ser(state_chain.clone())?, &(0 as i64)], // signals withdrawn funds
        )?;

        // Remove state_chain_id from user session to signal end of session
        db_update(
            &db_write,
            &user_id,
            Table::UserSession,
            vec![Column::StateChainId],
            vec![&Uuid::nil()],
        )?;

        // Update sparse merkle tree
        let (new_root, prev_root) = self.update_smt_db(
            &db_read,
            &db_write,
            &tx_withdraw
                .input
                .get(0)
                .unwrap()
                .previous_output
                .txid
                .to_string(),
            &withdraw_msg2.address,
        )?;

        info!(
            "WITHDRAW: Address included in sparse merkle tree. State Chain ID: {}",
            state_chain_id
        );
        debug!(
            "WITHDRAW: State Chain ID: {}. New root: {:?}. Previous root: {:?}.",
            state_chain_id, &new_root, &prev_root
        );

        info!(
            "WITHDRAW: Complete. Shared Key ID: {}. State Chain: {}",
            user_id.to_string(),
            state_chain_id
        );

        Ok(tx_withdraw.input[0].clone().witness)
    }
}

#[post("/withdraw/init", format = "json", data = "<withdraw_msg1>")]
pub fn withdraw_init(
    sc_entity: State<StateChainEntity>,
    db_read: DatabaseR,
    db_write: DatabaseW,
    withdraw_msg1: Json<WithdrawMsg1>,
) -> Result<Json<()>> {
    match sc_entity.withdraw_init(db_read, db_write, withdraw_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/withdraw/confirm", format = "json", data = "<withdraw_msg2>")]
pub fn withdraw_confirm(
    sc_entity: State<StateChainEntity>,
    db_read: DatabaseR,
    db_write: DatabaseW,
    withdraw_msg2: Json<WithdrawMsg2>,
) -> Result<Json<Vec<Vec<u8>>>> {
    match sc_entity.withdraw_confirm(db_read, db_write, withdraw_msg2.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}
