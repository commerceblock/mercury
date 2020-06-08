//! Util
//!
//! Utilities methods for Client to use with State Entity

extern crate shared_lib;

use super::super::utilities::requests;
use super::super::Result;
use crate::wallet::wallet::Wallet;
use crate::ecdsa;
use shared_lib::util::{rebuild_backup_tx,rebuild_withdraw_tx};
use shared_lib::structs::{Protocol, PrepareSignMessage};

use curv::BigInt;
use curv::arithmetic::traits::Converter;

use monotree::tree::verify_proof;
use monotree::hasher::{Hasher,Blake2b};
use monotree::{Proof,Hash};

use std::convert::TryInto;


/// Sign a transaction input with state entity shared wallet
pub fn cosign_tx_input(wallet: &mut Wallet, shared_key_id: &String, prepare_sign_msg: &PrepareSignMessage)
    -> Result<(Vec<Vec<u8>>, String)> {

    // message 1 - send tx data for validation.
    let state_chain_id: String = requests::postb(&wallet.client_shim, &format!("prepare-sign/{}", shared_key_id), prepare_sign_msg)?;

    // get transaction, protocol and sighash as message to be signed
    let protocol;
    let (_, sig_hash) = match prepare_sign_msg {
        PrepareSignMessage::WithdrawTx(prepare_sign_msg) => {
            protocol = Protocol::Withdraw;
            rebuild_withdraw_tx(&prepare_sign_msg)?
        },
        PrepareSignMessage::BackUpTx(prepare_sign_msg) => {
            protocol = prepare_sign_msg.protocol.to_owned();
            rebuild_backup_tx(&prepare_sign_msg)?
        }
    };

    let shared_key = wallet.get_shared_key(&shared_key_id)?;
    let mk = &shared_key.share;

    // co-sign transaction
    let sig = ecdsa::sign(
        &wallet.client_shim,
        BigInt::from_hex(&hex::encode(&sig_hash[..])),
        &mk,
        protocol,
        &shared_key.id,
    )?;

    Ok((sig, state_chain_id))
}

pub fn verify_statechain_smt(root: &Option<Hash>, proof_key: &String, proof: &Option<Proof>) -> bool {
    let entry: &[u8; 32] = proof_key[..32].as_bytes().try_into().unwrap();
    let hasher = Blake2b::new();
    verify_proof(&hasher, root.as_ref(), &entry, proof.as_ref())
}
