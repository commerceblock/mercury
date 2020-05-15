//! Deposit
//!
//! Despoit coins into state entity

// deposit() messages:
// 0. Initiate session - generate ID and perform authorisation
// 1. Generate shared wallet
// 2. user sends backup tx data
// 3. Co-op sign back-up tx

use super::super::Result;
extern crate shared_lib;
use crate::wallet::wallet::{to_bitcoin_public_key,Wallet};
use crate::wallet::key_paths::funding_txid_to_int;
use crate::state_entity::util::cosign_tx_input;
use super::super::utilities::requests;


use shared_lib::util::build_tx_0;
use shared_lib::structs::{PrepareSignTxMessage,DepositMsg1};

use bitcoin::{ Address, Amount, Transaction, TxIn, PublicKey };
use curv::elliptic::curves::traits::ECPoint;


/// Message to server initiating state entity protocol.
/// Shared wallet ID returned
pub fn session_init(wallet: &mut Wallet) -> Result<String> {
    requests::postb(&wallet.client_shim,&format!("/deposit/init"),
        &DepositMsg1 {
            auth: "auth".to_string()
        }
    )
}

/// Deposit coins into state entity. Requires list of inputs and spending addresses of those inputs
/// for funding transaction.
pub fn deposit(wallet: &mut Wallet, inputs: Vec<TxIn>, funding_spend_addrs: Vec<Address>, amount: Amount)
    -> Result<(String, String, Transaction, Transaction, PrepareSignTxMessage, PublicKey)>
{
    // init. Receive shared wallet ID
    let shared_key_id: String = session_init(wallet)?;

    // 2P-ECDSA with state entity to create a Shared key
    let shared_key = wallet.gen_shared_key(&shared_key_id)?;

    // make funding tx
    // co-owned key address to send funds to (P_addr)
    let pk = shared_key.share.public.q.get_element();
    let p_addr = bitcoin::Address::p2wpkh(
        &to_bitcoin_public_key(pk),
        wallet.get_bitcoin_network()
    );
    let tx_0 = build_tx_0(&inputs, &p_addr, &amount).unwrap();
    // sign
    let tx_0_signed = wallet.sign_tx(&tx_0, vec!(0), funding_spend_addrs, vec!(amount));

    // generate proof key
    let proof_key = wallet.se_proof_keys.get_new_key_encoded_id(
        funding_txid_to_int(&tx_0_signed.txid().to_string())?
    )?;
    // make backup tx PrepareSignTxMessage: Data required to build Back up tx
    let backup_receive_addr = wallet.se_backup_keys.get_new_address()?;
    let tx_b_prepare_sign_msg = PrepareSignTxMessage {
        spending_addr: p_addr.to_string(), // address which funding tx funds are sent to
        input_txid: tx_0_signed.txid().to_string(),
        input_vout: 0,
        address: backup_receive_addr.to_string(),
        amount: amount.as_sat(),
        proof_key: Some(proof_key.to_string()),
        transfer: false
    };

    let (state_chain_id, tx_b_signed) = cosign_tx_input(wallet, &shared_key_id, &tx_b_prepare_sign_msg)?;

    // Broadcast funding transcation


    Ok((shared_key_id, state_chain_id, tx_0_signed, tx_b_signed, tx_b_prepare_sign_msg, proof_key))
}
