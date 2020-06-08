//! Util
//!
//! Utilities methods for Client to use with State Entity

extern crate shared_lib;

use super::super::utilities::requests;
use super::super::Result;
use crate::wallet::wallet::Wallet;
use crate::ecdsa;
use shared_lib::util::get_sighash;
use shared_lib::structs::PrepareSignTxMsg;

use curv::BigInt;
use curv::arithmetic::traits::Converter;

use monotree::tree::verify_proof;
use monotree::hasher::{Hasher,Blake2b};
use monotree::{Proof,Hash};

use std::convert::TryInto;


/// Sign a transaction input with state entity shared wallet. Return signature witness.
pub fn cosign_tx_input(wallet: &mut Wallet, shared_key_id: &String, prepare_sign_msg: &PrepareSignTxMsg)
    -> Result<(Vec<Vec<u8>>, String)> {

    // message 1 - send tx data for validation.
    let state_chain_id: String = requests::postb(&wallet.client_shim, &format!("prepare-sign/{}", shared_key_id), prepare_sign_msg)?;

    // get sighash as message to be signed
    let sig_hash = get_sighash(
        &prepare_sign_msg.tx,
        &0,
        &prepare_sign_msg.input_addrs[0],
        &prepare_sign_msg.input_amounts[0]
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

    Ok((witness, state_chain_id))
}

pub fn verify_statechain_smt(root: &Option<Hash>, proof_key: &String, proof: &Option<Proof>) -> bool {
    let entry: &[u8; 32] = proof_key[..32].as_bytes().try_into().unwrap();
    let hasher = Blake2b::new();
    verify_proof(&hasher, root.as_ref(), &entry, proof.as_ref())
}
