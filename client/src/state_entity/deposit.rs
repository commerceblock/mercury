//! Deposit
//!
//! Deposit coins into state entity

// deposit():
// 0. Initiate session - generate ID and perform authorisation
// 1. Generate shared wallet
// 2. Co-op sign back-up tx
// 3. Broadcast funding tx and wait for SE verification
// 4. Verify funding txid and proof key in SM

use super::super::Result;
extern crate shared_lib;
use shared_lib::structs::{DepositMsg1, DepositMsg2, PrepareSignTxMsg, Protocol, UserID, StatechainID};
use shared_lib::util::{tx_backup_build, tx_funding_build, FEE, transaction_serialise};

use super::api::{get_smt_proof, get_smt_root, get_statechain_fee_info};
use crate::error::{CError, WalletErrorType};
use crate::state_entity::util::{cosign_tx_input, verify_statechain_smt};
use crate::utilities::requests;
use crate::wallet::wallet::{to_bitcoin_public_key, Wallet};

use bitcoin::{consensus, PublicKey, Transaction};
use curv::elliptic::curves::traits::ECPoint;
use uuid::Uuid;
use vdf::{VDFParams, WesolowskiVDFParams, VDF};

/// Message to server initiating state entity protocol.
/// Shared wallet ID returned
pub fn session_init(wallet: &mut Wallet, proof_key: &String) -> Result<UserID> {
    requests::postb(
        &wallet.client_shim,
        &format!("deposit/init"),
        &DepositMsg1 {
            auth: "auth".to_string(),
            proof_key: proof_key.to_owned(),
        },
    )
}

/// Deposit coins into state entity. Returns shared_key_id, statechain_id, funding txid,
/// signed backup tx, back up transacion data and proof_key
pub fn deposit(
    wallet: &mut Wallet,
    amount: &u64,
) -> Result<(Uuid, Uuid, String, Transaction, PrepareSignTxMsg, PublicKey)> {
    // Get state entity fee info
    let se_fee_info = get_statechain_fee_info(&wallet.client_shim)?;

    // Ensure funds cover fees before initiating protocol
    if FEE + se_fee_info.deposit >= *amount {
        return Err(CError::WalletError(WalletErrorType::NotEnoughFunds));
    }

    //calculate SE fee amount from rate
    let deposit_fee = (amount * se_fee_info.deposit) / 10000 as u64;
    let withdraw_fee = (amount * se_fee_info.withdraw) / 10000 as u64;

    // Greedy coin selection.
    let (inputs, addrs, amounts) =
        wallet.coin_selection_greedy(&(amount + deposit_fee + FEE))?;

    // Generate proof key
    let proof_key = wallet.se_proof_keys.get_new_key()?;

    // Init. session - Receive shared wallet ID
    let shared_key_id: UserID = session_init(wallet, &proof_key.to_string())?;

    // generate solution for the VDF challenge
    let challenge = match shared_key_id.vdf_challenge {
        Some(c) => c,
        None => return Err(CError::Generic(String::from("missing vdf challenge from server"))),
    };
    let vdf = WesolowskiVDFParams(2048 as u16).new();
    let solution = &vdf.solve(&challenge, 5000).unwrap()[..];

    // 2P-ECDSA with state entity to create a Shared key
    let shared_key = wallet.gen_shared_key(&shared_key_id.id, amount, solution.to_vec())?;

    // Create funding tx
    let pk = shared_key.share.public.q.get_element(); // co-owned key address to send funds to (P_addr)
    let p_addr =
        bitcoin::Address::p2wpkh(&to_bitcoin_public_key(pk), wallet.get_bitcoin_network())?;
    let change_addr = wallet.keys.get_new_address()?.to_string();
    let change_amount = amounts.iter().sum::<u64>() - amount - deposit_fee - FEE;
    
    let tx_0 = tx_funding_build(
        &inputs,
        &p_addr.to_string(),
        amount,
        &deposit_fee,
        &se_fee_info.address,
        &change_addr,
        &change_amount,
    )?;

    
    let tx_funding_signed = wallet.sign_tx(
        &tx_0,
        &(0..inputs.len()).collect(), // inputs to sign are all inputs is this case
        &addrs,
        &amounts,
    );

    //get initial locktime
    let chaintip = wallet
        .electrumx_client
        .instance
        .get_tip_header()?;
    debug!("Deposit: Got current best block height: {}", chaintip.height.to_string());
    let init_locktime: u32 = (chaintip.height as u32) + (se_fee_info.initlock as u32);
    debug!("Deposit: Set initial locktime: {}", init_locktime.to_string());

    // Make unsigned backup tx
    let backup_receive_addr = wallet.se_backup_keys.get_new_address()?;
    
    let tx_backup_unsigned =
        tx_backup_build(&tx_funding_signed.txid(), &backup_receive_addr, &amount, &init_locktime, &withdraw_fee, &se_fee_info.address)?;

    // Co-sign tx backup tx
    let tx_backup_psm = PrepareSignTxMsg {
        shared_key_ids: vec![shared_key_id.id],
        protocol: Protocol::Deposit,
        tx_hex: transaction_serialise(&tx_backup_unsigned),
        input_addrs: vec![pk],
        input_amounts: vec![*amount],
        proof_key: Some(proof_key.to_string()),
    };

    let witness = {
        let tmp = cosign_tx_input(wallet, &tx_backup_psm)?;
        if tmp.len() != 1 {
            return Err(CError::Generic(String::from("expected 1 witness from cosign_tx_input")));
        } else {
            tmp[0].to_owned()
        }
    };

    // Add witness to back up tx
    let mut tx_backup_signed = tx_backup_unsigned.clone();
    tx_backup_signed.input[0].witness = witness;
    // TODO: check signature is valid?

    // Broadcast funding transcation
    let funding_txid = wallet
        .electrumx_client
        .instance
        .broadcast_transaction(hex::encode(consensus::serialize(&tx_funding_signed)))?;

    // Wait for server confirmation of funding tx and receive new StateChain's id
    let statechain_id: StatechainID = requests::postb(
        &wallet.client_shim,
        &format!("deposit/confirm"),
        &DepositMsg2 {
            shared_key_id: shared_key_id.id,
        },
    )?;
    
    // Verify proof key inclusion in SE sparse merkle tree
    let root = get_smt_root(&wallet.client_shim)?.unwrap();
    let proof = get_smt_proof(&wallet.client_shim, &root, &funding_txid)?;
    assert!(verify_statechain_smt(
        &Some(root.hash()),
        &proof_key.to_string(),
        &proof
    ));

    // Add proof and state chain id to Shared key
    {
        let shared_key = wallet.get_shared_key_mut(&shared_key_id.id)?;
        shared_key.statechain_id = Some(statechain_id.id);
        shared_key.tx_backup_psm = Some(tx_backup_psm.to_owned());
        shared_key.add_proof_data(&proof_key.to_string(), &root, &proof, &funding_txid);
    }

    Ok((
        shared_key_id.id,
        statechain_id.id,
        funding_txid,
        tx_backup_signed,
        tx_backup_psm,
        proof_key,
    ))
}
