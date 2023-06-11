//! Util
//!
//! Utilities methods for Client to use with State Entity

extern crate shared_lib;

use super::super::utilities::requests;
use super::super::Result;
use crate::ecdsa;
use crate::wallet::wallet::Wallet;

use shared_lib::structs::PrepareSignTxMsg;
use shared_lib::util::{transaction_deserialise, get_sighash};

use curv::arithmetic::traits::Converter;
use curv::BigInt;
use monotree::{
    hasher::{Blake3, Hasher},
    tree::verify_proof,
    {Hash, Proof},
};

use std::convert::TryInto;

/// Sign a transaction input with state entity shared wallet. Return signature witness.
pub fn blindly_cosign_tx_input(
    wallet: &mut Wallet,
    prepare_sign_msg: &PrepareSignTxMsg,
) -> Result<Vec<Vec<Vec<u8>>>> {

    let tx = transaction_deserialise(&prepare_sign_msg.tx_hex)?;

    let mut witnesses=vec![];

    for (i, shared_key_id) in prepare_sign_msg.shared_key_ids.iter().enumerate() {
        // get sighash as message to be signed
        let sig_hash = get_sighash(
            &tx,
            &i,
            &prepare_sign_msg.input_addrs[i],
            &prepare_sign_msg.input_amounts[i],
            &wallet.network,
        );

        let shared_key = wallet.get_shared_key(&shared_key_id)?;
        let mk = &shared_key.share;

        // co-sign transaction
        let witness = ecdsa::blinded_sign(
            &wallet.client_shim,
            BigInt::from_hex(&hex::encode(&sig_hash[..])),
            &mk,
            prepare_sign_msg.protocol,
            &shared_key.id,
        )?;

        witnesses.push(witness);
    }

    Ok(witnesses)
}

/// Sign a transaction input with state entity shared wallet. Return signature witness.
pub fn cosign_tx_input(
    wallet: &mut Wallet,
    prepare_sign_msg: &PrepareSignTxMsg,
) -> Result<Vec<Vec<Vec<u8>>>> {
    // message 1 - send tx data for validation.
    requests::postb(
        &wallet.client_shim,
        &format!("prepare-sign/"),
        prepare_sign_msg,
    )?;

    let tx = transaction_deserialise(&prepare_sign_msg.tx_hex)?;

    let mut witnesses=vec![];
    
    for (i, shared_key_id) in prepare_sign_msg.shared_key_ids.iter().enumerate() {
        // get sighash as message to be signed
        let sig_hash = get_sighash(
            &tx,
            &i,
            &prepare_sign_msg.input_addrs[i],
            &prepare_sign_msg.input_amounts[i],
            &wallet.network,
        );

        let shared_key = wallet.get_shared_key(&shared_key_id)?;
        let mk = &shared_key.share;

        // co-sign transaction
        let witness = ecdsa::sign(
            &wallet.client_shim,
            BigInt::from_hex(&hex::encode(&sig_hash[..])),
            &mk,
            prepare_sign_msg.protocol,
            &shared_key.id,
        )?;

        witnesses.push(witness);
    }

    Ok(witnesses)
}

pub fn verify_statechain_smt(
    root: &Option<Hash>,
    proof_key: &String,
    proof: &Option<Proof>,
) -> bool {
    let entry: &[u8; 32] = proof_key[..32].as_bytes().try_into().unwrap();
    let hasher = Blake3::new();
    verify_proof(&hasher, root.as_ref(), &entry, proof.as_ref())
}
