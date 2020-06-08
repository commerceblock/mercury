//! Withdraw
//!
//! Withdraw funds from the state entity

// withdraw() messages:
// 0. request withdraw and provide withdraw tx data
// 1. co-sign withdraw tx
// 2. verify withdraws transaction received is corrcet


use super::super::Result;
extern crate shared_lib;
use shared_lib::state_chain::StateChainSig;
use shared_lib::structs::{StateChainDataAPI, WithdrawMsg1, PrepareSignTxMsg, Protocol};
use shared_lib::util::tx_withdraw_build;

use crate::wallet::wallet::{to_bitcoin_public_key, Wallet};
use crate::state_entity::util::cosign_tx_input;
use super::api::{get_statechain, get_statechain_fee_info};
use crate::{utilities::requests, error::CError};

use bitcoin::{ Transaction, PublicKey };
use curv::elliptic::curves::traits::ECPoint;
use std::str::FromStr;


/// Withdraw coins from state entity. Returns signed withdraw transaction, state_chain_id and withdrawn amount.
pub fn withdraw(wallet: &mut Wallet, shared_key_id: &String)
    -> Result<(Transaction, String, u64)>
{
    // Get required shared key data
    let state_chain_id;
    let pk;
    {
        let shared_key = wallet.get_shared_key(shared_key_id)?;
        pk = shared_key.share.public.q.get_element();
        state_chain_id = shared_key.state_chain_id.clone()
            .ok_or(CError::Generic(String::from("No state chain for this shared key id")))?;
    }

    // Get state chain info
    let sc_info = get_statechain(&wallet.client_shim, &state_chain_id)?;

    // Get state entity withdraw fee info
    let se_fee_info = get_statechain_fee_info(&wallet.client_shim)?;

    // Find address which spends funding tx (P_addr)
    let p_addr = bitcoin::Address::p2wpkh(
        &to_bitcoin_public_key(pk),
        wallet.get_bitcoin_network()
    );

    // Make unsigned withdraw tx
    let rec_address = wallet.keys.get_new_address()?; // receiving address of withdrawn funds
    let tx_withdraw_unsigned = tx_withdraw_build(
        &sc_info.utxo.txid,
        &rec_address,
        &sc_info.amount,
        &se_fee_info.withdraw,
        &se_fee_info.address
    )?;

    let tx_b_prepare_sign_msg = PrepareSignTxMsg {
        protocol: Protocol::Withdraw,
        tx: tx_withdraw_unsigned,
        input_addrs: vec!(p_addr.to_string()),
        input_amounts: vec!(sc_info.amount),
        proof_key: None,
    };
    // // prepare to sign withdraw transaction
    // let tx_prepare_sign_msg = WithdrawTxPSM {
    //     spending_addr: p_addr.to_string(),
    //     input: sc_info.utxo,
    //     address: rec_address.to_string(),
    //     amount: sc_info.amount,
    //     se_fee: se_fee_info.withdraw,
    //     se_fee_addr: se_fee_info.address,
    // };

    cosign_tx_input(wallet, &shared_key_id, &tx_b_prepare_sign_msg)?;

    // first sign state chain
    let state_chain_data: StateChainDataAPI = get_statechain(&wallet.client_shim, &state_chain_id)?;
    let state_chain = state_chain_data.chain;
    // get proof key for signing
    let proof_key_derivation = wallet.se_proof_keys.get_key_derivation(&PublicKey::from_str(&state_chain.last().unwrap().data).unwrap());
    let state_chain_sig = StateChainSig::new(
        &proof_key_derivation.unwrap().private_key.key,
        &String::from("WITHDRAW"),
        &rec_address.to_string()
    )?;

    let tx_w: Transaction = requests::postb(&wallet.client_shim,&format!("/withdraw"),
        &WithdrawMsg1 {
            shared_key_id: shared_key_id.clone(),
            state_chain_sig,
            address: rec_address.to_string(),
        })?;

    // Mark funds as spent in wallet
    {
        let mut shared_key = wallet.get_shared_key_mut(shared_key_id)?;
        shared_key.unspent = false;
    }

    // TODO verify signed tx_w matches tx_prepare_sign_msg. Broadcast transaction?

    Ok((tx_w, state_chain_id, state_chain_data.amount-se_fee_info.withdraw))
}
