//! StateEntity Withdraw
//!
//! StateEntity Withdraw protocol.

use super::super::{{Result,Config},
        auth::jwt::Claims,
        storage::db};
extern crate shared_lib;
use shared_lib::{structs::*,
    state_chain::*,
    Root};

use crate::routes::util::{UserSession, StateEntityStruct, check_user_auth};
use crate::error::{SEError,DBErrorType::NoDataForID};
use crate::storage::db::{get_current_root, DB_SC_LOC, update_root};

use rocket_contrib::json::Json;
use rocket::State;

/// User request withdraw:
///     - Check StateChainSig validity
///     - Mark user as authorised to withdraw
#[post("/withdraw/init", format = "json", data = "<withdraw_msg1>")]
pub fn withdraw_init(
    state: State<Config>,
    claim: Claims,
    withdraw_msg1: Json<WithdrawMsg1>,
) -> Result<Json<()>> {
    let shared_key_id = withdraw_msg1.shared_key_id.clone();
    info!("WITHDRAW: Init. Shared Key ID: {}", shared_key_id);

    // Auth user
    check_user_auth(&state, &claim, &shared_key_id)?;

    // Get UserSession data
    let mut user_session: UserSession =
        db::get(&state.db, &claim.sub, &shared_key_id, &StateEntityStruct::UserSession)?
            .ok_or(SEError::DBError(NoDataForID, shared_key_id.clone()))?;

    // Get statechain
    let state_chain_id = user_session.state_chain_id.clone()
        .ok_or(SEError::Generic(String::from("No state chain session found for this user.")))?;
    let state_chain: StateChain =
        db::get(&state.db, &claim.sub, &state_chain_id.to_owned(), &StateEntityStruct::StateChain)?
            .ok_or(SEError::DBError(NoDataForID, state_chain_id.to_owned()))?;
    // Check if state chain is still owned by user and not locked
    state_chain.is_locked()?;
    state_chain.is_owned_by(&shared_key_id)?;


    // Verify new StateChainSig
    let prev_proof_key = state_chain.get_tip()?.data;
    withdraw_msg1.state_chain_sig.verify(&prev_proof_key)?;

    // Mark UserSession as authorised for withdrawal
    user_session.withdraw_sc_sig = Some(withdraw_msg1.state_chain_sig.clone());
    db::insert(
        &state.db,
        &claim.sub,
        &shared_key_id,
        &StateEntityStruct::UserSession,
        &user_session
    )?;

    info!("WITHDRAW: Authorised. Shared Key ID: {}. State Chain: {}",shared_key_id, state_chain_id);

    Ok(Json(()))
}

/// Finish withdrawal:
///     - Ensure withdraw tx has been signed
///     - Update UserSession, StateChain and Sparse merkle tree
///     - Return withdraw tx signature
#[post("/withdraw/confirm", format = "json", data = "<withdraw_msg2>")]
pub fn withdraw_confirm(
    state: State<Config>,
    claim: Claims,
    withdraw_msg2: Json<WithdrawMsg2>,
) -> Result<Json<Vec<Vec<u8>>>> {
    let shared_key_id = withdraw_msg2.shared_key_id.clone();
    info!("WITHDRAW: Confirm. Shared Key ID: {}", shared_key_id);

    // Get UserSession data
    let mut user_session: UserSession =
        db::get(&state.db, &claim.sub, &shared_key_id, &StateEntityStruct::UserSession)?
            .ok_or(SEError::DBError(NoDataForID, shared_key_id.clone()))?;
    // Check withdraw tx and statechain signature exists
    if user_session.tx_withdraw.is_none() {
        return Err(SEError::Generic(String::from("Withdraw Error: No withdraw tx has been signed.")));
    }
    if user_session.withdraw_sc_sig.is_none() {
        return Err(SEError::Generic(String::from("Withdraw Error: No state chain signature exists for this user.")));
    }

    // Get statechain and update with final StateChainSig
    let state_chain_id = user_session.state_chain_id
        .ok_or(SEError::Generic(String::from("No state chain session found for this user.")))?;
    let mut state_chain: StateChain =
        db::get(&state.db, &claim.sub, &state_chain_id.to_owned(), &StateEntityStruct::StateChain)?
            .ok_or(SEError::DBError(NoDataForID, state_chain_id.to_owned()))?;

    state_chain.add(user_session.withdraw_sc_sig.to_owned().unwrap())?;
    state_chain.amount = 0;     // signals withdrawn funds
    db::insert(
        &state.db,
        &claim.sub,
        &state_chain_id,
        &StateEntityStruct::StateChain,
        &state_chain
    )?;

    // Remove state_chain_id from user session to signal end of session
    user_session.state_chain_id = None;
    db::insert(
        &state.db,
        &claim.sub,
        &shared_key_id,
        &StateEntityStruct::UserSession,
        &user_session
    )?;

    // Update sparse merkle tree
    let tx_withdraw = user_session.tx_withdraw.unwrap();
    let funding_txid = tx_withdraw.input.get(0).unwrap().previous_output.txid.to_string();

    let root = get_current_root::<Root>(&state.db)?;
    let new_root = update_statechain_smt(DB_SC_LOC, &root.value, &funding_txid, &withdraw_msg2.address)?;
    update_root(&state.db, &state.mainstay_config, new_root.unwrap())?;

    info!("WITHDRAW: Complete. Shared Key ID: {}. State Chain: {}",shared_key_id, state_chain_id);

    Ok(Json(tx_withdraw.input[0].clone().witness))
}
