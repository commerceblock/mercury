//! Withdraw
//!
//! Withdraw funds from the state entity

// withdraw() messages:
// 0. request withdraw and provide withdraw tx data
// 1. Sign state chain and request withdrawal
// 2. Co-sign withdraw tx
// 3. Broadcast withdraw tx

use super::super::Result;
extern crate shared_lib;
use shared_lib::{
    state_chain::StateChainSig,
    structs::{PrepareSignTxMsg, Protocol, StateChainDataAPI, WithdrawMsg1, WithdrawMsg2},
    util::{transaction_serialise, tx_withdraw_build},
};

use super::api::{get_statechain, get_statechain_fee_info};
use crate::error::{CError, WalletErrorType};
use crate::state_entity::util::cosign_tx_input;
use crate::utilities::requests;
use crate::wallet::wallet::Wallet;

use bitcoin::{consensus, PublicKey};
use curv::elliptic::curves::traits::ECPoint;

use std::str::FromStr;
use uuid::Uuid;

/// Withdraw coins from state entity. Returns signed withdraw transaction, statechain_id and withdrawn amount.
pub fn withdraw(wallet: &mut Wallet, statechain_id: &Uuid) -> Result<(String, Uuid, u64)> {
    let vec_scid = vec![*statechain_id];
    let resp = batch_withdraw(wallet, &vec_scid)?;
    Ok((resp.0, resp.1[0], resp.2))
}

/// Withdraw coins from state entity. Returns signed withdraw transaction, statechain_id and withdrawn amount.
pub fn batch_withdraw(wallet: &mut Wallet, statechain_id: &Vec<Uuid>) -> Result<(String, Vec<Uuid>, u64)> {
    let statechain_id = &statechain_id[0];
    // first get required shared key data
    let shared_key_id;
    let pk;
    {
        let shared_key = wallet.get_shared_key_by_statechain_id(statechain_id)?;
        pk = shared_key.share.public.q.get_element();
        shared_key_id = shared_key.id.clone();
    }

    // Generate receiving address of withdrawn funds
    let rec_se_address = wallet.keys.get_new_address()?;

    // Sign state chain
    let statechain_data: StateChainDataAPI = get_statechain(&wallet.client_shim, &statechain_id)?;
    if statechain_data.amount == 0 {
        return Err(CError::StateEntityError(String::from(
            "Withdraw: StateChain is already withdrawn.",
        )));
    }
    let state_chain = statechain_data.chain;
    // get proof key for signing
    let proof_key_derivation = wallet
        .se_proof_keys
        .get_key_derivation(&PublicKey::from_str(&state_chain.last().unwrap().data).unwrap())
        .ok_or(CError::WalletError(WalletErrorType::KeyNotFound));
    let statechain_sig = StateChainSig::new(
        &proof_key_derivation.unwrap().private_key.key,
        &String::from("WITHDRAW"),
        &rec_se_address.to_string(),
    )?;

    // Alert SE of desire of withdraw and receive authorisation if state chain signature verifies
    requests::postb(
        &wallet.client_shim,
        &format!("withdraw/init"),
        &WithdrawMsg1 {
            shared_key_ids: vec![shared_key_id.clone()],
            statechain_sigs: vec![statechain_sig],
        },
    )?;

    // Get state chain info
    let sc_info = get_statechain(&wallet.client_shim, &statechain_id)?;
    // Get state entity withdraw fee info
    let se_fee_info = get_statechain_fee_info(&wallet.client_shim)?;

    //calculate SE fee amount from rate
    let withdraw_fee = (sc_info.amount * se_fee_info.withdraw) / 10000 as u64;

    let sc_infos = vec![sc_info];

    // Construct withdraw tx
    let tx_withdraw_unsigned = tx_withdraw_build(
        &sc_infos,
        &rec_se_address,
        &se_fee_info,
    )?;
    /*
    let tx_withdraw_unsigned = tx_withdraw_build(
        &sc_info.utxo.txid,
        &rec_se_address,
        &(sc_info.amount + se_fee_info.deposit),
        &withdraw_fee,
        &se_fee_info.address,
    )?;
    */

    let mut input_amounts = vec![];
    for info in sc_infos {
        input_amounts.push(info.amount);
    }

    // co-sign withdraw tx
    let tx_w_prepare_sign_msg = PrepareSignTxMsg {
        shared_key_id: shared_key_id.to_owned(),
        protocol: Protocol::Withdraw,
        tx_hex: transaction_serialise(&tx_withdraw_unsigned),
        input_addrs: vec![pk],
        input_amounts,
        proof_key: None,
    };
    cosign_tx_input(wallet, &tx_w_prepare_sign_msg)?;
    
    let witness: Vec<Vec<Vec<u8>>> = requests::postb(
        &wallet.client_shim,
        &format!("/withdraw/confirm"),
        &WithdrawMsg2 {
            shared_key_ids: vec![shared_key_id.to_owned()],
            address: rec_se_address.to_string(),
        },
    )?;
    
    let mut tx_withdraw_signed = tx_withdraw_unsigned.clone();
    tx_withdraw_signed.input[0].witness = witness[0].clone();

    // Mark funds as withdrawn in wallet
    {
        let mut shared_key = wallet.get_shared_key_mut(&shared_key_id)?;
        shared_key.unspent = false;
    }

    // Broadcast transcation
    let withdraw_txid = wallet
        .electrumx_client
        .instance
        .broadcast_transaction(hex::encode(consensus::serialize(&tx_withdraw_signed)))?;
    debug!("Withdraw: Withdrawal tx broadcast. txid: {}", withdraw_txid);

    Ok((
        withdraw_txid,
        vec![statechain_id.clone()],
        statechain_data.amount - se_fee_info.withdraw,
    ))
}
