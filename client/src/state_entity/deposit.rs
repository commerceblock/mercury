//! Deposit
//!
//! Despoit coins into state entity

// deposit() messages:
// 0. Initiate session - generate ID and perform authorisation
// 1. Generate shared wallet
// 2. user sends backup tx data
// 3. Co-op sign back-up tx

use super::super::Result;
use crate::wallet::wallet::Wallet;
use crate::state_entity::util::{ build_tx_0, cosign_tx_input, PrepareSignTxMessage };
use super::super::utilities::requests;

use bitcoin::{ Address, Amount, Transaction, TxIn };


#[derive(Serialize, Debug)]
pub struct DepositMsg1 {
    proof_key: String,
}
/// Message to server initiating state entity protocol.
/// Shared wallet ID returned
pub fn session_init(wallet: &mut Wallet) -> Result<String> {
    // generate proof key
    let proof_key_addr = wallet.get_new_bitcoin_address()?;
    let proof_key = wallet.addresses_derivation_map.get(&proof_key_addr.to_string()).unwrap().public_key.to_string();
    requests::postb(&wallet.client_shim,&format!("/deposit/init"),
        &DepositMsg1 {
            proof_key
        }
    )
}

/// Deposit coins into state entity. Requires list of inputs and spending addresses of those inputs
/// for funding transaction.
pub fn deposit(wallet: &mut Wallet, inputs: Vec<TxIn>, funding_spend_addrs: Vec<Address>, amount: Amount) -> Result<(String, Transaction, Transaction, PrepareSignTxMessage)> {
    // init. Receive shared wallet ID
    let shared_wallet_id: String = session_init(wallet)?;

    // 2P-ECDSA with state entity to create a SharedWallet
    wallet.gen_shared_wallet(&shared_wallet_id)?;

    // make funding tx
    // co-owned address to send funds to (P_addr)
    let p_addr = wallet.gen_addr_for_shared_wallet(&shared_wallet_id).unwrap();
    let tx_0 = build_tx_0(&inputs, &p_addr, &amount).unwrap();
    // sign
    let tx_0_signed = wallet.sign_tx(&tx_0, vec!(0), funding_spend_addrs, vec!(amount));

    // make backup tx PrepareSignTxMessage: Data required to build Back up tx
    let backup_receive_addr = wallet.get_new_bitcoin_address()?;
    let tx_b_prepare_sign_msg = PrepareSignTxMessage {
        spending_addr: p_addr.to_string(),
        input_txid: tx_0_signed.txid().to_string(),
        input_vout: 0,
        address: backup_receive_addr.to_string(),
        amount: amount.as_sat(),
        transfer: false
    };

    let tx_b_signed = cosign_tx_input(wallet, &shared_wallet_id, &tx_b_prepare_sign_msg)?;

    Ok((shared_wallet_id, tx_0_signed, tx_b_signed, tx_b_prepare_sign_msg))
}
