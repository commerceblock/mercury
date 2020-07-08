//! StateEntity Transfer
//!
//! StateEntity Transfer and batch-transfer protocols.

use super::super::{{Result,Config,DataBase},
    auth::jwt::Claims,
    storage::db};

extern crate shared_lib;
use shared_lib::{
    structs::*,
    state_chain::*,
    Root, commitment::verify_commitment};
use crate::routes::util::*;
use crate::error::{SEError,DBErrorType::NoDataForID};
use crate::storage::{
    db_postgres::{Column, Table, db_get_serialized, db_insert, db_update, db_update_serialized, db_get, db_get_statechain},
    db::get_current_root};

use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one::Party1Private;

use curv::{
    elliptic::curves::traits::{ECScalar,ECPoint},
    {BigInt,FE,GE}};
use rocket_contrib::json::Json;
use rocket::State;
use chrono::NaiveDateTime;
use uuid::Uuid;
use db::{DB_SC_LOC, update_root};
use std::{time::SystemTime,
    collections::HashMap,
    str::FromStr};


/// Initiliase transfer protocol:
///     - Authorisation of Owner and DoS protection
///     - Validate transfer parameters
///     - Store transfer parameters
#[post("/transfer/sender", format = "json", data = "<transfer_msg1>")]
pub fn transfer_sender(
    state: State<Config>,
    claim: Claims,
    conn: DataBase,
    transfer_msg1: Json<TransferMsg1>,
) -> Result<Json<TransferMsg2>> {
    let user_id = transfer_msg1.shared_key_id;

    info!("TRANSFER: Sender Side. Shared Key ID: {}", user_id);

    // Auth user
    check_user_auth(&state, &claim, &conn, &user_id)?;

    // Verification/PoW/authoriation failed
    // Err(SEError::AuthError)

    // Get state_chain id
    // let user_session: UserSession =
    //     db::get(&state.db, &claim.sub, &user_id.to_string(), &StateEntityStruct::UserSession)?
    //         .ok_or(SEError::DBError(NoDataForID, user_id.to_string().clone()))?;
    // let state_chain_id =  user_session.state_chain_id
    //     .ok_or(SEError::Generic(String::from("Transfer Error: User does not own a state chain.")))?;
    let state_chain_id: Uuid =
        db_get(&conn, &user_id, Table::UserSession, Column::StateChainId)?
            .ok_or(SEError::DBErrorWC(NoDataForID, user_id, Column::StateChainId))?;

    // Check if state chain is still owned by user and not locked
    // let state_chain: StateChain =
    //     db::get(&state.db, &claim.sub, &state_chain_id.to_string(), &StateEntityStruct::StateChain)?
    //         .ok_or(SEError::DBError(NoDataForID, state_chain_id.to_string().clone()))?;
    // state_chain.is_locked()?;
    // state_chain.is_owned_by(&user_id)?;

    let sc_locked_until: NaiveDateTime =
        db_get(&conn, &state_chain_id, Table::StateChain, Column::LockedUntil)?
            .ok_or(SEError::DBErrorWC(NoDataForID, state_chain_id, Column::LockedUntil))?;
    is_locked(sc_locked_until)?;

    let sc_owner_id: Uuid =
        db_get(&conn, &state_chain_id, Table::StateChain, Column::OwnerId)?
            .ok_or(SEError::DBErrorWC(NoDataForID, state_chain_id, Column::OwnerId))?;
    if sc_owner_id != user_id {
        return Err(SEError::Generic(format!("State Chain not owned by User ID: {}.", user_id)));
    }

    // Ensure if transfer has already been completed (but not finalized)
    match db::get::<TransferData>(&state.db, &claim.sub, &state_chain_id.to_string(), &StateEntityStruct::TransferData)? {
        None => {},
        Some(_) => {
            return Err(SEError::Generic(String::from("Transfer already completed. Waiting for finalize.")));
        }
    }

    // Generate x1
    let x1: FE = ECScalar::new_random();

    // Create TransferData DB entry
    db::insert(
        &state.db,
        &claim.sub,
        &state_chain_id.to_string(),
        &StateEntityStruct::TransferData,
        &TransferData {
            state_chain_id,
            state_chain_sig: transfer_msg1.state_chain_sig.to_owned(),
            x1: x1.clone(),
        }
    )?;

    info!("TRANSFER: Sender side complete. Previous shared key ID: {}. State Chain ID: {}",user_id.to_string(),state_chain_id);
    debug!("TRANSFER: Sender side complete. State Chain ID: {}. State Chain Signature: {:?}. x1: {:?}.", state_chain_id, transfer_msg1.state_chain_sig, x1);

    // TODO encrypt x1 with Senders proof key

    Ok(Json(TransferMsg2{x1}))
}

/// Transfer shared wallet to new Owner:
///     - Check new Owner's state chain is correct
///     - Perform 2P-ECDSA key rotation
///     - Return new public shared key S2
#[post("/transfer/receiver", format = "json", data = "<transfer_msg4>")]
pub fn transfer_receiver(
    state: State<Config>,
    claim: Claims,
    conn: DataBase,
    transfer_msg4: Json<TransferMsg4>,
) -> Result<Json<TransferMsg5>> {
    let user_id = transfer_msg4.shared_key_id;

    info!("TRANSFER: Receiver side. Shared Key ID: {}", user_id);

    // Get TransferData for state_chain_id
    let transfer_data: TransferData =
        db::get(&state.db, &claim.sub, &transfer_msg4.state_chain_id.to_string(), &StateEntityStruct::TransferData)?
            .ok_or(SEError::DBError(NoDataForID, transfer_msg4.state_chain_id.to_string().clone()))?;
    let state_chain_sig = transfer_data.state_chain_sig;
    let state_chain_id = transfer_data.state_chain_id.clone();

    // Ensure state_chain_sigs are the same
    if state_chain_sig != transfer_msg4.state_chain_sig.to_owned() {
        return Err(SEError::Generic(format!("State chain siganture provided does not match state chain at id {}",state_chain_id)));
    }

    // Get Party1 (State Entity) private share
    let party_one_private: Party1Private =
        db_get_serialized(&conn, &user_id, Table::Ecdsa, Column::Party1Private)?
            .ok_or(SEError::DBErrorWC(NoDataForID, user_id, Column::Party1Private))?;

    // Get Party2 (Owner 1) public share
    let party_2_public: GE =
        db_get_serialized(&conn, &user_id, Table::Ecdsa, Column::Party2Public)?
            .ok_or(SEError::DBErrorWC(NoDataForID, user_id, Column::Party2Public))?;

    // TODO: decrypt t2

    let x1 = transfer_data.x1;
    let t2 = transfer_msg4.t2;
    let s1 = party_one_private.get_private_key();

    // Note:
    //  s2 = o1*o2_inv*s1
    //  t2 = o1*x1*o2_inv
    let s2 = t2 * (x1.invert()) * s1;

    // Check s2 is valid for Lindell protocol (s2<q/3)
    let sk_bigint = s2.to_big_int();
    let q_third = FE::q();
    if sk_bigint >= q_third.div_floor(&BigInt::from(3)) {
        return Err(SEError::Generic(format!("Invalid o2, try again.")));
    }

    let g: GE = ECPoint::generator();
    let s2_pub: GE = g * s2;

    let p1_pub = party_2_public * s1;
    let p2_pub = transfer_msg4.o2_pub * s2;

    // Check P1 = o1_pub*s1 === p2 = o2_pub*s2
    if p1_pub != p2_pub {
        error!("TRANSFER: Protocol failed. P1 != P2.");
        return Err(SEError::Generic(String::from("Transfer protocol error: P1 != P2")));
    }

    // Create user ID for new UserSession (receiver of transfer)
    let new_shared_key_id = Uuid::new_v4();

    let finalized_data = TransferFinalizeData {
        new_shared_key_id: new_shared_key_id.clone(),
        state_chain_id: state_chain_id.clone(),
        state_chain_sig,
        s2,
        new_tx_backup: transfer_msg4.tx_backup.clone(),
        batch_data: transfer_msg4.batch_data.clone()
    };

    // If batch transfer then mark StateChain as complete and store finalized data in TransferBatchData.
    // This is so the transfers can be finalized when all transfers in the batch are complete.
    if transfer_msg4.batch_data.is_some() {
        let batch_id = transfer_msg4.batch_data.clone().unwrap().id;
        info!("TRANSFER: Transfer as part of batch {}. State Chain ID: {}",batch_id,state_chain_id);
        let mut transfer_batch_data: TransferBatchData =
            db::get(&state.db, &claim.sub, &batch_id.to_string(), &StateEntityStruct::TransferBatchData)?
                .ok_or(SEError::DBError(NoDataForID, batch_id.to_string().clone()))?;

        // Ensure batch transfer is still active
        if transfer_batch_data.is_ended(state.batch_lifetime) {
            return Err(SEError::Generic(String::from("Transfer batch ended. Too late to complete transfer.")));
        }

        transfer_batch_data.state_chains.insert(state_chain_id.clone(), true);
        transfer_batch_data.finalized_data.push(finalized_data.clone());
        db::insert(
            &state.db,
            &claim.sub,
            &batch_id.to_string(),
            &StateEntityStruct::TransferBatchData,
            &transfer_batch_data
        )?;
    // If not batch then finalize transfer now
    } else {
        // Update DB and SMT with new transfer data
        transfer_finalize(
            &state,
            &claim,
            &conn,
            &finalized_data
        )?;
    }

    info!("TRANSFER: Receiver side complete. State Chain ID: {}",new_shared_key_id);
    debug!("TRANSFER: Receiver side complete. State Chain ID: {}. New Shared Key ID: {}. Finalized data: {:?}",state_chain_id,transfer_data.state_chain_id,finalized_data);

    Ok(Json(
        TransferMsg5 {
            new_shared_key_id,
            s2_pub,
        }
    ))
}


/// Update DB and SMT after successful transfer.
/// This function is called immediately in the regular transfer case or after confirmation of atomic
/// transfers completion in the batch transfer case.
pub fn transfer_finalize(
    state: &State<Config>,
    claim: &Claims,
    conn: &DataBase,
    finalized_data: &TransferFinalizeData
) -> Result<()> {
    let state_chain_id = finalized_data.state_chain_id;

    info!("TRANSFER_FINALIZE: State Chain ID: {}", state_chain_id);
    // Update state chain
    // let mut state_chain: StateChain =
    //     db::get(&state.db, &claim.sub, &state_chain_id.to_string(), &StateEntityStruct::StateChain)?
    //         .ok_or(SEError::DBError(NoDataForID, state_chain_id.to_string()))?;
    let mut state_chain: StateChain =
        db_get_statechain(&conn, &state_chain_id)?;

    state_chain.add(finalized_data.state_chain_sig.to_owned())?;
    // state_chain.owner_id = finalized_data.new_shared_key_id;

    // db::insert(
    //     &state.db,
    //     &claim.sub,
    //     &state_chain_id.to_string(),
    //     &StateEntityStruct::StateChain,
    //     &state_chain
    // )?;
    db_update_serialized(&conn, &state_chain_id, state_chain.chain.clone(), Table::StateChain, Column::Chain)?;
    db_update(&conn, &state_chain_id, finalized_data.new_shared_key_id, Table::StateChain, Column::OwnerId)?;


    // Create new UserSession to allow new owner to generate shared wallet
    // db::insert(
    //     &state.db,
    //     &claim.sub,
    //     &finalized_data.new_shared_key_id,
    //     &StateEntityStruct::UserSession,
    //     &UserSession {
    //         id: finalized_data.new_shared_key_id.clone(),
    //         auth: String::from("auth"),
    //         proof_key: finalized_data.state_chain_sig.data.to_owned(),
    //         tx_backup: Some(state_chain.tx_backup.clone()),
    //         tx_withdraw: None,
    //         sig_hash: None,
    //         state_chain_id: Some(state_chain_id.clone()),
    //         s2: Some(finalized_data.s2),
    //         withdraw_sc_sig: None
    //     }
    // )?;
    let new_user_id = finalized_data.new_shared_key_id;
    db_insert(&conn, &new_user_id, Table::UserSession)?;
    db_update(&conn, &new_user_id, String::from("auth"), Table::UserSession, Column::Authentication)?;
    db_update(&conn, &new_user_id, finalized_data.state_chain_sig.data.to_owned(), Table::UserSession, Column::ProofKey)?;
    db_update_serialized(&conn, &new_user_id, finalized_data.new_tx_backup.clone(), Table::UserSession, Column::TxBackup)?;
    db_update(&conn, &new_user_id, state_chain_id, Table::UserSession, Column::StateChainId)?;
    db_update_serialized(&conn, &new_user_id, finalized_data.s2, Table::UserSession, Column::S2)?;


    info!("TRANSFER: Finalized. New shared key ID: {}. State Chain ID: {}", finalized_data.new_shared_key_id, state_chain_id);

    // Update sparse merkle tree with new StateChain entry
    let funding_txid = finalized_data.new_tx_backup.input.get(0).unwrap().previous_output.txid.to_string();
    let proof_key = state_chain.chain.last()
        .ok_or(SEError::Generic(String::from("StateChain empty")))?
        .data.clone();

    let root = get_current_root::<Root>(&state.db)?;
    let new_root = update_statechain_smt(DB_SC_LOC, &root.value, &funding_txid, &proof_key)?;
    update_root(&state.db, new_root.unwrap())?;

    info!("TRANSFER: Included in sparse merkle tree. State Chain ID: {}", state_chain_id);
    debug!("TRANSFER: State Chain ID: {}. New root: {:?}. Previous root: {:?}.", state_chain_id, new_root.unwrap(), root);

    // Remove TransferData for this transfer
    db::remove(&state.db, &claim.sub, &state_chain_id.to_string(), &StateEntityStruct::TransferData)?;

    Ok(())
}


/// Request setup of a batch transfer.
///     - Verify all signatures
///     - Create TransferBatchData DB object
#[post("/transfer/batch/init", format = "json", data = "<transfer_batch_init_msg>")]
pub fn transfer_batch_init(
    state: State<Config>,
    claim: Claims,
    conn: DataBase,
    transfer_batch_init_msg: Json<TransferBatchInitMsg>
) -> Result<Json<()>> {
    let batch_id = transfer_batch_init_msg.id.clone();
    info!("TRANSFER_BATCH_INIT: ID: {}", batch_id);

    if db::get::<TransferBatchData>(&state.db, &claim.sub, &batch_id.to_string(), &StateEntityStruct::TransferBatchData)?.is_some() {
        return Err(SEError::Generic(format!("Batch transfer with ID {} already exists.",batch_id.to_string())))
    }

    // Ensure sigs purpose is for batch transfer
    for sig in &transfer_batch_init_msg.signatures {
        if !sig.purpose.contains("TRANSFER_BATCH") {
            return Err(SEError::Generic(String::from("Signture's purpose is not valid for batch transfer.")));
        }
    }

    let mut state_chains = HashMap::new();
    for sig in transfer_batch_init_msg.signatures.clone() {
        // Ensure sig is for same batch as others
        if &sig.clone().purpose[15..] != batch_id.to_string() {
            return Err(SEError::Generic(String::from("Batch id is not identical for all signtures.")));
        }

        let state_chain_id = Uuid::from_str(&sig.data).unwrap();

        // Verify sig
        // let state_chain: StateChain =
        //     db::get(&state.db, &claim.sub, &sig.data, &StateEntityStruct::StateChain)?
        //         .ok_or(SEError::DBError(NoDataForID, sig.data.clone()))?;
        let state_chain: StateChain =
            db_get_statechain(&conn, &state_chain_id)?;

        let proof_key = state_chain.get_tip()?.data;
        sig.verify(&proof_key)?;

        // Ensure state chains are all available
        // match state_chain.is_locked() {
        //     Err(_) => return Err(SEError::Generic(format!("State Chain ID {} is locked.",sig.data))),
        //     Ok(_) => {}
        // }
        let sc_locked_until: NaiveDateTime =
            db_get(&conn, &state_chain_id, Table::StateChain, Column::LockedUntil)?
                .ok_or(SEError::DBErrorWC(NoDataForID, state_chain_id, Column::LockedUntil))?;
        if let Err(_) = is_locked(sc_locked_until) {
            return Err(SEError::Generic(format!("State Chain ID {} is locked.",sig.data)));
        }

        // Add to TransferBatchData object
        state_chains.insert(
            state_chain_id,
            false
        );

    }

    // Create new TransferBatchData and add to DB
    db::insert(
        &state.db,
        &claim.sub,
        &batch_id.to_string(),
        &StateEntityStruct::TransferBatchData,
        &TransferBatchData {
            id: batch_id,
            start_time: SystemTime::now(),
            state_chains,
            finalized_data: vec!(),
            punished_state_chains: vec!(),
            finalized: false
        }
    )?;

    info!("TRANSFER_BATCH_INIT: Batch ID {} initiated.",batch_id);
    debug!("TRANSFER_BATCH_INIT: Batch ID {}. Signatures: {:?}.", batch_id, transfer_batch_init_msg.signatures);

    Ok(Json(()))
}

/// Finalize all transfers in a batch.
pub fn finalize_batch(
    state: &State<Config>,
    claim: &Claims,
    conn: &DataBase,
    batch_id: &String
) -> Result<()> {
    info!("TRANSFER_FINALIZE_BATCH: ID: {}", batch_id);
    let mut transfer_batch_data: TransferBatchData =
        db::get(&state.db, &claim.sub, &batch_id, &StateEntityStruct::TransferBatchData)?
            .ok_or(SEError::DBError(NoDataForID, batch_id.clone()))?;

    if transfer_batch_data.state_chains.len() != transfer_batch_data.finalized_data.len() {
        return Err(SEError::Generic(String::from("TransferBatchData has unequal finalized data to state chains.")))
    }

    for finalized_data in transfer_batch_data.finalized_data.clone() {
        transfer_finalize(
            &state,
            &claim,
            &conn,
            &finalized_data
        )?;
    }

    transfer_batch_data.finalized = true;
    db::insert(
        &state.db,
        &claim.sub,
        &batch_id,
        &StateEntityStruct::TransferBatchData,
        &transfer_batch_data
    )?;

    Ok(())
}


/// API: Reveal a nonce for a corresponding commitment
#[post("/transfer/batch/reveal", format = "json", data = "<transfer_reveal_nonce>")]
pub fn transfer_reveal_nonce(
    state: State<Config>,
    claim: Claims,
    conn: DataBase,
    transfer_reveal_nonce: Json<TransferRevealNonce>,
) -> Result<Json<()>> {
    let batch_id = transfer_reveal_nonce.batch_id;
    let state_chain_id = transfer_reveal_nonce.state_chain_id;
    info!("TRANSFER_REVEAL_NONCE: Batch ID: {}. State Chain ID: {}", batch_id, state_chain_id);

    let mut transfer_batch_data: TransferBatchData =
        db::get(&state.db, &claim.sub, &batch_id.to_string(), &StateEntityStruct::TransferBatchData)?
            .ok_or(SEError::DBError(NoDataForID, batch_id.to_string()))?;

    if transfer_batch_data.finalized {
        return Err(SEError::Generic(String::from("Transfer Batch completed successfully.")));
    }
    if !transfer_batch_data.is_ended(state.batch_lifetime) {
        return Err(SEError::Generic(String::from("Transfer Batch still live.")));
    }
    if transfer_batch_data.state_chains.get(&state_chain_id).is_none() {
        return Err(SEError::Generic(String::from("State chain ID not in this batch.")));
    }

    verify_commitment(
        &transfer_reveal_nonce.hash,
        &state_chain_id.to_string(),
        &transfer_reveal_nonce.nonce,
    )?;

    // If state chain completed + commitment revealed then punishment can be removed from state chain
    if *transfer_batch_data.state_chains.get(&state_chain_id).unwrap() {
        // let mut state_chain: StateChain =
        //     db::get(&state.db, &claim.sub, &state_chain_id.to_string(), &StateEntityStruct::StateChain)?
        //         .ok_or(SEError::DBError(NoDataForID, transfer_reveal_nonce.state_chain_id.to_string()))?;

        // state_chain.locked_until = SystemTime::now();
        // db::insert(
        //     &state.db,
        //     &claim.sub,
        //     &state_chain_id.to_string(),
        //     &StateEntityStruct::StateChain,
        //     &state_chain
        // )?;
        db_update(&conn, &state_chain_id, get_time_now(), Table::StateChain, Column::LockedUntil)?;


        info!("TRANSFER_REVEAL_NONCE: State Chain unlocked. ID: {}", state_chain_id);

        // remove from transfer batch punished list
        transfer_batch_data.punished_state_chains.retain(|x| x != &state_chain_id);
    }

    db::insert(
        &state.db,
        &claim.sub,
        &transfer_reveal_nonce.batch_id.to_string(),
        &StateEntityStruct::TransferBatchData,
        &transfer_batch_data
    )?;

    Ok(Json(()))
}
