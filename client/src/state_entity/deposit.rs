//! Deposit
//!
//! Deposit coins into state entity

// deposit() messages:
// 0. Initiate session - generate ID and perform authorisation
// 1. Generate shared wallet
// 2. user sends backup tx data
// 3. Co-op sign back-up tx

use super::super::Result;
extern crate shared_lib;
use shared_lib::util::{FEE,build_tx_0};
use shared_lib::structs::{PrepareSignMessage, BackUpTxPSM, DepositMsg1, Protocol};

use crate::wallet::wallet::{to_bitcoin_public_key,Wallet};
use crate::utilities::requests;
use crate::state_entity::util::{cosign_tx_input,verify_statechain_smt};
use crate::error::{WalletErrorType, CError};
use super::api::{get_smt_proof, get_smt_root, get_statechain_fee_info};

use bitcoin::{ Address, Transaction, TxIn, PublicKey, OutPoint};
use bitcoin::hashes::sha256d;
use curv::elliptic::curves::traits::ECPoint;

use std::str::FromStr;

/// Message to server initiating state entity protocol.
/// Shared wallet ID returned
pub fn session_init(wallet: &mut Wallet, proof_key: &String) -> Result<String> {
    requests::postb(&wallet.client_shim,&format!("/deposit/init"),
        &DepositMsg1 {
            auth: "auth".to_string(),
            proof_key: proof_key.to_owned()
        }
    )
}

fn basic_input(txid: &String, vout: &u32) -> TxIn {
    TxIn {
        previous_output: OutPoint{
            txid: sha256d::Hash::from_str(txid).unwrap(),
            vout: *vout
        },
        sequence: 0xFFFFFFFF,
        witness: Vec::new(),
        script_sig: bitcoin::Script::default(),
    }
}

/// Select unspent coins greedily. Returd TxIns along with corresponding spending addresses and amounts
pub fn coin_selection_greedy(wallet: &mut Wallet, amount: &u64) -> Result<(Vec<TxIn>, Vec<Address>, Vec<u64>)> {
    // Greedy coin selection.
    let (unspent_addrs, unspent_utxos) = wallet.list_unspent();
    let mut inputs: Vec<TxIn> = vec!();
    let mut addrs: Vec<Address> = vec!(); // corresponding addresses for inputs
    let mut amounts: Vec<u64> = vec!(); // corresponding amounts for inputs
    for (i, addr) in unspent_addrs.into_iter().enumerate() {
        for unspent_utxo in unspent_utxos.get(i).unwrap() {
            inputs.push(basic_input(&unspent_utxo.tx_hash, &(unspent_utxo.tx_pos as u32)));
            addrs.push(addr.clone());
            amounts.push(unspent_utxo.value as u64);
            if *amount < amounts.iter().sum::<u64>() {
                return Ok((inputs, addrs, amounts));
            }
        }
    }
    return Err(CError::WalletError(WalletErrorType::NotEnoughFunds))
}

/// Deposit coins into state entity. Returns shared_key_id, state_chain_id, signed funding tx, back up transacion data and proof_key
pub fn deposit(wallet: &mut Wallet, amount: &u64)
    -> Result<(String, String, Transaction, PrepareSignMessage, PublicKey)>
{
    // get state entity fee info
    let se_fee_info = get_statechain_fee_info(&wallet.client_shim)?;

    // Greedy coin selection.
    let (inputs, addrs, amounts) = coin_selection_greedy(wallet, &(amount+se_fee_info.deposit+FEE))?;

    // Ensure funds cover fees before initiating protocol
    if FEE+se_fee_info.deposit >= *amount {
        return Err(CError::WalletError(WalletErrorType::NotEnoughFunds));
    }

    // generate proof key
    let proof_key = wallet.se_proof_keys.get_new_key()?;

    // init. session - Receive shared wallet ID
    let shared_key_id: String = session_init(wallet, &proof_key.to_string())?;

    // 2P-ECDSA with state entity to create a Shared key
    let shared_key = wallet.gen_shared_key(&shared_key_id, amount)?;

    // make funding tx
    let pk = shared_key.share.public.q.get_element();   // co-owned key address to send funds to (P_addr)
    let p_addr = bitcoin::Address::p2wpkh(
        &to_bitcoin_public_key(pk),
        wallet.get_bitcoin_network()
    );

    let tx_0 = build_tx_0(&inputs, &p_addr.to_string(), amount, &se_fee_info.deposit, &se_fee_info.address)?;
    let tx_0_signed = wallet.sign_tx(
        &tx_0,
        &(0..inputs.len()).collect(), // inputs to sign are all inputs is this case
        &addrs,
        &amounts
    );

    // make backup tx PrepareSignMessage: Data required to build Back up tx
    let backup_receive_addr = wallet.se_backup_keys.get_new_address()?;
    let tx_b_prepare_sign_msg = BackUpTxPSM {
        protocol: Protocol::Deposit,
        spending_addr: p_addr.to_string(), // address which funding tx funds are sent to
        input: OutPoint {
            txid: tx_0_signed.txid(),
            vout: 0
        },
        address: backup_receive_addr.to_string(),
        amount: amount.to_owned(),
        proof_key: Some(proof_key.to_string())
    };

    let state_chain_id = cosign_tx_input(wallet, &shared_key_id, &PrepareSignMessage::BackUpTx(tx_b_prepare_sign_msg.to_owned()))?;

    // TODO: Broadcast funding transcation

    // verify proof key inclusion in SE sparse merkle tree
    let root = get_smt_root(wallet)?;
    let proof = get_smt_proof(wallet, &root, &tx_0_signed.txid().to_string())?;
    assert!(verify_statechain_smt(
        &root.value,
        &proof_key.to_string(),
        &proof
    ));

    // add proof data to Shared key
    wallet.update_shared_key(&shared_key_id, &state_chain_id, &PrepareSignMessage::BackUpTx(tx_b_prepare_sign_msg.to_owned()), &proof_key.to_string(), &root, &proof)?;

    Ok((shared_key_id, state_chain_id, tx_0_signed, PrepareSignMessage::BackUpTx(tx_b_prepare_sign_msg), proof_key))
}
