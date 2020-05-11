//! Util
//!
//! Utilities methods for Client to use with State Entity

extern crate shared_lib;

use super::super::utilities::requests;
use super::super::Result;
use crate::wallet::wallet::Wallet;
use crate::ecdsa;
use shared_lib::{util::build_tx_b,structs::PrepareSignTxMessage};

use bitcoin::{ Address, Amount, OutPoint, Transaction, TxIn };
use bitcoin::util::bip143::SighashComponents;
use bitcoin::secp256k1::Signature;
use bitcoin::hashes::sha256d;
use curv::{BigInt};
use curv::arithmetic::traits::Converter;
use curv::elliptic::curves::traits::ECPoint;

use std::str::FromStr;

/// Sign a transaction input with state entity shared wallet
pub fn cosign_tx_input(wallet: &mut Wallet, shared_wallet_id: &String, prepare_sign_msg: &PrepareSignTxMessage) -> Result<(String, Transaction)> {

    // message 1 - send back-up tx data for validation.
    let state_chain_id: String = requests::postb(&wallet.client_shim, &format!("prepare-sign/{}", shared_wallet_id), prepare_sign_msg)?;

    // Co-sign back-up tx
    // get sigHash and transform into message to be signed
    let txin = TxIn {
        previous_output: OutPoint {
            txid: sha256d::Hash::from_str(&prepare_sign_msg.input_txid).unwrap(),
            vout: prepare_sign_msg.input_vout
        },
        sequence: 0xFFFFFFFF,
        witness: Vec::new(),
        script_sig: bitcoin::Script::default(),
    };

    let tx = build_tx_b(
        &txin,
        &Address::from_str(&prepare_sign_msg.address).unwrap(),
        &Amount::from_sat(prepare_sign_msg.amount)
    ).unwrap();

    let mut tx_signed = tx.clone();
    let comp = SighashComponents::new(&tx);
    let sig_hash = comp.sighash_all(
        &tx.input[0],
        &Address::from_str(&prepare_sign_msg.spending_addr).unwrap().script_pubkey(),
        prepare_sign_msg.amount
    );

    let shared_wal = wallet.get_shared_wallet(&shared_wallet_id).expect("No shared wallet found for id");
    let address_derivation = shared_wal.addresses_derivation_map.get(&prepare_sign_msg.spending_addr).unwrap();
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

    tx_signed.input[0].witness = vec![sig_vec, pk_vec];
    Ok((state_chain_id, tx_signed))
}
