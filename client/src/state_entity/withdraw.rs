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
    structs::{PrepareSignTxMsg, Protocol, StateCoinDataAPI, WithdrawMsg1, WithdrawMsg2},
    util::{transaction_serialise, tx_withdraw_build},
};

use super::api::{get_statechain, get_statecoin, get_statechain_fee_info};
use crate::error::{CError, WalletErrorType};
use crate::state_entity::util::cosign_tx_input;
use crate::utilities::requests;
use crate::wallet::wallet::Wallet;

use bitcoin::{consensus, PublicKey};
use curv::elliptic::curves::traits::ECPoint;

use std::str::FromStr;
use uuid::Uuid;

/// Withdraw coins from state entity. Returns signed withdraw transaction, statechain_id and withdrawn amount.
pub fn withdraw(wallet: &mut Wallet, statechain_id: &Uuid, tx_fee: &u64, blinded: bool) 
    -> Result<(String, Uuid, u64)> {
    println!("running withdraw init...");
    let (shared_key_id, address, tx_signed, amount) = withdraw_init(wallet, statechain_id, tx_fee)?;
    println!("running withdraw confirm...");
    let tx_id = withdraw_confirm(wallet, &shared_key_id, &tx_signed)?;
    Ok((tx_id, statechain_id.clone(), amount))
}

pub fn batch_withdraw(wallet: &mut Wallet, statechain_ids: &Vec<Uuid>, tx_fee: &u64) 
    -> Result<(String, Vec<Uuid>, u64)> {
    let (shared_key_ids, address, tx_signed, amount) = batch_withdraw_init(wallet, statechain_ids, tx_fee)?;
    let tx_id = batch_withdraw_confirm(wallet, &shared_key_ids, &tx_signed)?;
    Ok((tx_id, statechain_ids.clone(), amount))
}

pub fn withdraw_init(wallet: &mut Wallet, statechain_id: &Uuid, tx_fee: &u64) 
    -> Result<(Uuid, bitcoin::Address, bitcoin::Transaction, u64)> {
    let vec_scid = vec![*statechain_id];
    let (shared_key_ids, address, tx, amount) = batch_withdraw_init(wallet, &vec_scid, tx_fee)?;
    Ok((shared_key_ids[0].clone(), address, tx, amount))
}

pub fn withdraw_confirm(wallet: &mut Wallet, shared_key_id: &Uuid, 
    tx_signed: &bitcoin::Transaction) 
    -> Result<String> {
    let vec_shared_key_id = vec![*shared_key_id];
    batch_withdraw_confirm(wallet, &vec_shared_key_id, tx_signed)
}

/// Withdraw coins from state entity. Returns signed withdraw transaction, statechain_id and withdrawn amount.
pub fn batch_withdraw_init(wallet: &mut Wallet, statechain_ids: &Vec<Uuid>, tx_fee: &u64) 
    -> Result<(Vec<Uuid>, bitcoin::Address, bitcoin::Transaction, u64)> {
    // Generate receiving address of withdrawn funds
    let rec_se_address = wallet.keys.get_new_address()?;
    
    let mut shared_key_ids=vec![];
    let mut pks = vec![];
    let mut statechain_sigs = vec![];

    for statechain_id in statechain_ids{
        // first get required shared key data
        
        {
            let shared_key = wallet.get_shared_key_by_statechain_id(statechain_id)?;
            pks.push(shared_key.share.public.q.get_element());
            shared_key_ids.push(shared_key.id.clone());
        }
    
        // Sign state chain
        let statecoin_data: StateCoinDataAPI = get_statecoin(&wallet.client_shim, &statechain_id)?;
        if statecoin_data.amount == 0 {
            return Err(CError::StateEntityError(String::from(
                "Withdraw: StateChain is already withdrawn.",
            )));
        }
        // get proof key for signing
        let proof_key_derivation = wallet
            .se_proof_keys
            .get_key_derivation(&PublicKey::from_str(&statecoin_data.statecoin.data).unwrap())
            .ok_or(CError::WalletError(WalletErrorType::KeyNotFound));
        let statechain_sig = StateChainSig::new(
            &proof_key_derivation.unwrap().private_key.key,
            &String::from("WITHDRAW"),
            &rec_se_address.to_string(),
        )?;
        statechain_sigs.push(statechain_sig);
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

    let mut sc_infos = vec![];
    let mut amounts = vec![];
    let mut total_amount = 0;
    let se_fee_info = get_statechain_fee_info(&wallet.client_shim)?;
    
    
    for statechain_id in statechain_ids{
        // Get state chain info
        let sc_info = get_statechain(&wallet.client_shim, &statechain_id)?;
        // Get state entity withdraw fee info
        

        total_amount += sc_info.amount;
        amounts.push(sc_info.amount.clone());
        sc_infos.push(sc_info);
    }

    // Construct withdraw tx
    let tx_withdraw_unsigned = tx_withdraw_build(
        &sc_infos,
        &rec_se_address,
        &se_fee_info,
        tx_fee
    )?;
    
    // co-sign withdraw tx
    let tx_w_prepare_sign_msg = PrepareSignTxMsg {
        shared_key_ids: shared_key_ids.clone(),
        protocol: Protocol::Withdraw,
        tx_hex: transaction_serialise(&tx_withdraw_unsigned),
        input_addrs: pks,
        input_amounts: amounts,
        proof_key: None,
    };
    let witness: Vec<Vec<Vec<u8>>> = cosign_tx_input(wallet, &tx_w_prepare_sign_msg)?;

    
    let mut tx_withdraw_signed = tx_withdraw_unsigned.clone();
    tx_withdraw_signed.input[0].witness = witness[0].clone();
    
    Ok((shared_key_ids, rec_se_address, tx_withdraw_signed, total_amount - se_fee_info.withdraw))
}
 
pub fn batch_withdraw_confirm(wallet: &mut Wallet, shared_key_ids: &Vec<Uuid>, 
    tx_withdraw_signed: &bitcoin::Transaction) 
    -> Result<String> {
    let witness: Vec<Vec<Vec<u8>>> = requests::postb(
        &wallet.client_shim,
        &format!("/withdraw/confirm"),
        &WithdrawMsg2 {
            shared_key_ids: shared_key_ids.clone(),
        },
    )?;
    
    assert!(tx_withdraw_signed.input[0].witness == witness[0]);

    // Mark funds as withdrawn in wallet
    for shared_key_id in shared_key_ids
    {
        let mut shared_key = wallet.get_shared_key_mut(&shared_key_id)?;
        shared_key.unspent = false;
    }

    // Broadcast transcation
    let withdraw_txid = wallet
        .electrumx_client
        .instance
        .broadcast_transaction(hex::encode(consensus::serialize(&tx_withdraw_signed.to_owned())))?;
    debug!("Withdraw: Withdrawal tx broadcast. txid: {}", withdraw_txid);

    Ok(withdraw_txid)
}
