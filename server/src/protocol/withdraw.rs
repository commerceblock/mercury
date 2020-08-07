//! StateEntity Withdraw
//!
//! StateEntity Withdraw protocol trait and implementation for StateChainEntity.

pub use super::super::Result;
extern crate shared_lib;
use shared_lib::{state_chain::*, structs::*};

use rocket::State;
use rocket_contrib::json::Json;

use crate::error::SEError;
use crate::Database;
use crate::{server::StateChainEntity, storage::Storage};
use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(test)]{
        use crate::MockDatabase;
        type SCE = StateChainEntity::<MockDatabase>;
    } else {
        use crate::PGDatabase;
        type SCE = StateChainEntity::<PGDatabase>;
    }
}

/// StateChain Withdraw protocol trait
pub trait Withdraw {
    /// User request withdraw:
    ///     - Check StateChainSig validity
    ///     - Mark user as authorised to withdraw
    fn withdraw_init(
        &self,
        withdraw_msg1: WithdrawMsg1,
    ) -> Result<()>;

    /// Finish withdrawal:
    ///     - Ensure withdraw tx has been signed
    ///     - Update UserSession, StateChain and Sparse merkle tree
    ///     - Return withdraw tx signature
    fn withdraw_confirm(
        &self,
        withdraw_msg2: WithdrawMsg2,
    ) -> Result<Vec<Vec<u8>>>;
}

impl Withdraw for SCE {
    fn withdraw_init(
        &self,
        withdraw_msg1: WithdrawMsg1,
    ) -> Result<()> {
        let user_id = withdraw_msg1.shared_key_id;
        self.check_user_auth(&user_id)?;

        info!("WITHDRAW: Init. Shared Key ID: {}", user_id);

        let state_chain_id = self.database.get_statechain_id(user_id)?;

        // Get statechain
        let sco = self.database.get_statechain_owner(state_chain_id)?;


        // Check if locked
        is_locked(sco.locked_until)?;
        // check if owned by caller
        if sco.owner_id != user_id {
            return Err(SEError::Generic(format!(
                "State Chain not owned by User ID: {}.",
                state_chain_id
            )));
        }

        // Verify new StateChainSig
        let prev_proof_key = sco.chain.get_tip()?.data;
        withdraw_msg1.state_chain_sig.verify(&prev_proof_key)?;

        // Mark UserSession as authorised for withdrawal

        self.database.update_withdraw_sc_sig(&user_id, withdraw_msg1.state_chain_sig)?;

        info!(
            "WITHDRAW: Authorised. Shared Key ID: {}. State Chain: {}",
            user_id, state_chain_id
        );

        Ok(())
    }

    fn withdraw_confirm(
        &self,
        withdraw_msg2: WithdrawMsg2,
    ) -> Result<Vec<Vec<u8>>> {
        let user_id = withdraw_msg2.shared_key_id;
        info!("WITHDRAW: Confirm. Shared Key ID: {}", user_id.to_string());

        // Get UserSession data - Checking that withdraw tx and statechain signature exists
        let wcd = self.database.get_withdraw_confirm_data(user_id)?;

        // Get statechain and update with final StateChainSig
        let mut state_chain: StateChain = self.database.get_statechain(wcd.state_chain_id)?;

        state_chain.add(wcd.withdraw_sc_sig.to_owned())?;

        self.database.update_statechain_amount(&wcd.state_chain_id, state_chain, 0)?;



        // Remove state_chain_id from user session to signal end of session
        self.database.remove_statechain_id(&user_id)?;

        // Update sparse merkle tree
        let (new_root, prev_root) = self.update_smt(
            &wcd.tx_withdraw
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
            wcd.state_chain_id
        );
        debug!(
            "WITHDRAW: State Chain ID: {}. New root: {:?}. Previous root: {:?}.",
            wcd.state_chain_id, &new_root, &prev_root
        );

        info!(
            "WITHDRAW: Complete. Shared Key ID: {}. State Chain: {}",
            user_id.to_string(),
            wcd.state_chain_id
        );

        Ok(wcd.tx_withdraw.input[0].clone().witness)
    }
}

#[post("/withdraw/init", format = "json", data = "<withdraw_msg1>")]
pub fn withdraw_init(
    sc_entity: State<SCE>,
    withdraw_msg1: Json<WithdrawMsg1>,
) -> Result<Json<()>> {
    match sc_entity.withdraw_init(withdraw_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/withdraw/confirm", format = "json", data = "<withdraw_msg2>")]
pub fn withdraw_confirm(
    sc_entity: State<SCE>,
    withdraw_msg2: Json<WithdrawMsg2>,
) -> Result<Json<Vec<Vec<u8>>>> {
    match sc_entity.withdraw_confirm(withdraw_msg2.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}
