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
use crate::wallet::{wallet::Wallet, shared_key::SharedKey};

use bitcoin::{consensus, PublicKey};
use curv::elliptic::curves::traits::ECPoint;

use std::str::FromStr;
use uuid::Uuid;
use curv::PK;
use itertools::Zip;

/// Withdraw coins from state entity. Returns signed withdraw transaction, statechain_id and withdrawn amount.
pub fn withdraw(wallet: &mut Wallet, statechain_id: &Uuid) -> Result<(String, Uuid, u64)> {
    let vec_scid = vec![*statechain_id];
    let resp = batch_withdraw(wallet, &vec_scid)?;
    Ok((resp.0, resp.1[0], resp.2))
}


/// Withdraw coins from state entity. Returns signed withdraw transaction, statechain_id and withdrawn amount.
pub fn batch_withdraw(wallet: &mut Wallet, statechain_id: &Vec::<Uuid>) -> 
    Result<(String, Vec::<Uuid>, u64)> {
    // Generate receiving address of withdrawn funds
    let rec_se_address = wallet.keys.get_new_address()?;
    
    // first get required shared key data
    let mut shared_key_ids = Vec::<Uuid>::new();
    let mut statechain_sigs = Vec::<StateChainSig>::new();
    // Get state chain info
    let mut sc_infos = Vec::<StateChainDataAPI>::new();
    let mut input_addrs = Vec::<PK>::new();
    let mut input_amounts = Vec::<u64>::new();
    let mut total_amount: u64 = 0;

    for scid in statechain_id {
        println!("getting shared key for statechain id: {}", scid);
        let shared_key = wallet.get_shared_key_by_statechain_id(scid)?;
        shared_key_ids.push(shared_key.id);
        input_addrs.push(shared_key.share.public.q.get_element());

        // Sign state chain
        let statechain_data: StateChainDataAPI = get_statechain(&wallet.client_shim, scid)?;
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
        statechain_sigs.push(statechain_sig);


        sc_infos.push(get_statechain(&wallet.client_shim, scid)?);
        let amount = sc_infos.last().unwrap().amount;
        input_amounts.push(amount);
        total_amount+=amount;
    }

    // Alert SE of desire of withdraw and receive authorisation if state chain signature verifies
    requests::postb(
        &wallet.client_shim,
        &format!("withdraw/init"),
        &WithdrawMsg1 {
            shared_key_ids: shared_key_ids.clone(),
            statechain_sigs: statechain_sigs.clone(),
        },
    )?;

    
    // Get state entity withdraw fee info
    let se_fee_info = get_statechain_fee_info(&wallet.client_shim)?;

    //calculate SE fee amount from rate
    //let withdraw_fee = (sc_info.amount * se_fee_info.withdraw) / 10000 as u64;

    // Construct withdraw tx
    //let tx_withdraw_unsigned = tx_withdraw_build(
    //    &sc_info.utxo.txid,
    //    &rec_se_address,
    //    &(sc_info.amount + se_fee_info.deposit),
    //    &withdraw_fee,
    //    &se_fee_info.address,
    //)?;

    let tx_withdraw_unsigned = tx_withdraw_build(
        &sc_infos,
        &rec_se_address,
        &se_fee_info,
    )?;

    let witnesses: Vec<Vec<Vec<u8>>> = requests::postb(
                &wallet.client_shim,
                &format!("/withdraw/confirm"),
                &WithdrawMsg2 {
                    shared_key_ids: shared_key_ids.clone(),
                    address: rec_se_address.to_string(),
                },
        )?;


    //for shared_key_id in shared_key_ids {
        // co-sign withdraw tx
        let tx_w_prepare_sign_msg = PrepareSignTxMsg {
            shared_key_id: shared_key_ids[0].clone(),
            protocol: Protocol::Withdraw,
            tx_hex: transaction_serialise(&tx_withdraw_unsigned),
            input_addrs,
            input_amounts,
            proof_key: None,
        };
        cosign_tx_input(wallet, &tx_w_prepare_sign_msg)?;
    //}
        
    let mut tx_withdraw_signed = tx_withdraw_unsigned.clone();

    //for (witness, input, shared_key_id) in 
    //    itertools::Zip::new((&witnesses, &mut tx_withdraw_signed.input, &shared_key_ids))        
    for (i, witness) in witnesses.iter().enumerate()
    {
        tx_withdraw_signed.input[i].witness = witness.to_owned();
        // Mark funds as withdrawn in wallet
        {
            let mut shared_key = wallet.get_shared_key_mut(&shared_key_ids[i])?;
            shared_key.unspent = false;
        }
    }
        
    // Broadcast transcation
    let withdraw_txid = wallet
        .electrumx_client
        .instance
        .broadcast_transaction(hex::encode(consensus::serialize(&tx_withdraw_signed)))?;
        
    debug!("Withdraw: Withdrawal tx broadcast. txid: {}", withdraw_txid);

    

    Ok((
        withdraw_txid,
        statechain_id.clone(),
        total_amount - se_fee_info.withdraw,
    ))
}
