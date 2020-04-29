// deposit() messages:
// 0. Initiate session - generate ID and perform authorisation
// 1. Generate shared wallet
// 2. user sends backup tx data
// 3. Co-op sign back-up tx

use crate::ClientShim;
use crate::wallet::wallet::Wallet;
use crate::state_entity::util::{ build_tx_0, build_tx_b};
use crate::ecdsa;
use super::super::utilities::requests;

use bitcoin::{ Address, Amount, Transaction, TxIn };
use bitcoin::secp256k1::Signature;
use bitcoin::util::bip143::SighashComponents;

use curv::arithmetic::traits::Converter;
use curv::elliptic::curves::traits::ECPoint;
use curv::{BigInt};

use super::super::Result;

#[derive(Serialize, Deserialize, Debug)]
pub struct DepositMessage1 {
    p_addr: String, // address which funding tx funds are sent to
    tx_b_input_txid: String,
    tx_b_input_vout: u32,
    tx_b_input_seq: u32,
    tx_b_address: String,
    tx_b_amount: u64
}

/// Message to server initiating state entity protocol.
/// Shared wallet ID returned
pub fn session_init(client_shim: &ClientShim) -> Result<String> {
    requests::post(client_shim,&format!("/init"))
}

/// Deposit coins into state entity. Requires list of inputs and spending addresses of those inputs
/// for funding transaction.
pub fn deposit(wallet: &mut Wallet, inputs: Vec<TxIn>, funding_spend_addrs: Vec<Address>, amount: Amount) -> Result<(Transaction, Transaction)> {
    // init. Receive shared wallet ID
    let shared_wallet_id: String = session_init(&wallet.client_shim)?;

    // 2P-ECDSA with state entity to create a SharedWallet
    wallet.gen_shared_wallet(&shared_wallet_id)?;

    // make funding tx
    // co-owned address to send funds to (P_addr)
    let p_addr = wallet.gen_addr_for_shared_wallet(&shared_wallet_id).unwrap();
    let tx_0 = build_tx_0(&inputs, &p_addr, &amount).unwrap();
    // sign
    let tx_0_signed = wallet.sign_tx(&tx_0, vec!(0), funding_spend_addrs, vec!(amount));

    // make backup tx
    let backup_receive_addr = wallet.get_new_bitcoin_address();
    let tx_0_output: bitcoin::blockdata::transaction::TxIn = tx_0.input.get(0).unwrap().clone();
    let tx_b = build_tx_b(&tx_0_output, &backup_receive_addr, &amount).unwrap();

    let deposit_second_msg = DepositMessage1 {
        p_addr: p_addr.to_string(),
        tx_b_input_txid: tx_0_output.previous_output.txid.to_string(),
        tx_b_input_vout: tx_0_output.previous_output.vout,
        tx_b_input_seq: tx_0_output.sequence,
        tx_b_address: backup_receive_addr.to_string(),
        tx_b_amount: amount.as_sat(),
    };

    // message 1 - send back-up tx data for validation.
    requests::postb(&wallet.client_shim, &format!("deposit/{}/first", shared_wallet_id),&deposit_second_msg)?;

    // Co-sign back-up tx
    // get sigHash and transform into message to be signed
    let mut tx_b_signed = tx_b.clone();
    let comp = SighashComponents::new(&tx_b);
    let sig_hash = comp.sighash_all(
        &tx_b.input[0],
        &p_addr.script_pubkey(),
        amount.as_sat()
    );

    let shared_wal = wallet.get_shared_wallet(&shared_wallet_id).unwrap();
    let address_derivation = shared_wal.addresses_derivation_map.get(&p_addr.to_string()).unwrap();
    let mk = &address_derivation.mk;

    // co-sign back up tranaction
    let signature = ecdsa::sign(
        &wallet.client_shim,
        BigInt::from_hex(&hex::encode(&sig_hash[..])),
        &mk,
        BigInt::from(0),
        BigInt::from(address_derivation.pos),
        &shared_wal.private_share.id,
    ).unwrap();

    let mut v = BigInt::to_vec(&signature.r);
    v.extend(BigInt::to_vec(&signature.s));

    let mut sig_vec = Signature::from_compact(&v[..])
        .unwrap()
        .serialize_der()
        .to_vec();
    sig_vec.push(01);

    let pk_vec = mk.public.q.get_element().serialize().to_vec();

    tx_b_signed.input[0].witness = vec![sig_vec, pk_vec];

    Ok((tx_0_signed, tx_b_signed))
}
