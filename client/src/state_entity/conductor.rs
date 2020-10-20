//! Conductor
//! 
//! Interact with a swap conductor

use super::super::Result;

use crate::error::{CError, WalletErrorType};
use crate::state_entity::{
    api::{get_smt_proof, get_smt_root, get_statechain, get_statechain_fee_info},
    util::{cosign_tx_input, verify_statechain_smt},
};
use crate::wallet::{key_paths::funding_txid_to_int, wallet::Wallet};
use crate::{utilities::requests, ClientShim};
use shared_lib::{ecies::WalletDecryptable, state_chain::StateChainSig, structs::*, blinded_token::*};

use shared_lib::blinded_token::{BlindedSpendSignature, BlindedSpendToken, BSTSenderData, BSTRequestorData};
use shared_lib::{structs::*, swap_data::*};

use bitcoin::{Address, PublicKey};
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{FE, GE};
use std::str::FromStr;
use uuid::Uuid;

// Register a state chain for participation in a swap (request a swap)
// with swap_size participants
pub fn swap_register_utxo(
    wallet: &Wallet,
    state_chain_id: &Uuid,
    swap_size: &u64
) -> Result<()> {

    // First sign state chain
    let state_chain_data: StateChainDataAPI = get_statechain(&wallet.client_shim, &state_chain_id)?;
    let state_chain = state_chain_data.chain;
    // Get proof key for signing
    let proof_key_derivation = &wallet
        .se_proof_keys
        .get_key_derivation(&PublicKey::from_str(&state_chain.last().unwrap().data).unwrap())
        .ok_or(CError::WalletError(WalletErrorType::KeyNotFound))?;
    let state_chain_sig = StateChainSig::new(
        &proof_key_derivation
        .private_key
        .key,
        &String::from("SWAP"),
        &proof_key_derivation.public_key.unwrap().to_string(),
    )?;

    requests::postb(
        &wallet.client_shim,
        &String::from("swap/register-utxo"),
        &RegisterUtxo {
            state_chain_id: state_chain_id.to_owned(),
            signature: state_chain_sig,
            swap_size: swap_size.to_owned()
        }
    )
}

pub fn swap_poll_utxo(client_shim: &ClientShim, 
    state_chain_id: &Uuid) -> Result<Option<Uuid>> {
    requests::postb(
        &client_shim,
        &String::from("swap/poll/utxo"),
        &state_chain_id
    )
}

pub fn swap_poll_swap(client_shim: &ClientShim,
swap_id: &Uuid) -> Result<Option<SwapStatus>> {
    requests::postb(
        &client_shim,
        &String::from("swap/poll/swap"),
        &swap_id
    )
}

pub fn swap_info(client_shim: &ClientShim,
swap_id: &Uuid) -> Result<Option<SwapInfo>> {
    requests::postb(
        &client_shim,
        &String::from("swap/info"),
        &swap_id
    )
}

pub fn swap_first_message(wallet: &Wallet,
    swap_info: &SwapInfo,
    state_chain_id: &Uuid,
    new_address: &SCEAddress,
    e_prime: &FE,
) -> Result<BSTRequestorData> {
    let swap_token = swap_info.swap_token.clone();

    let state_chain_data: StateChainDataAPI = get_statechain(&wallet.client_shim, &state_chain_id)?;
    let state_chain = state_chain_data.chain;

    let proof_key_derivation = &wallet
    .se_proof_keys
    .get_key_derivation(&PublicKey::from_str(&state_chain.last().unwrap().data).unwrap())
    .ok_or(CError::WalletError(WalletErrorType::KeyNotFound))?;

    let proof_key_priv = &proof_key_derivation.private_key.key;

    let swap_token_sig = &swap_token.sign(&proof_key_priv)?;



    //Requester
    let m = swap_token.id.to_string();
    // Requester setup BST generation
    let my_bst_data = BSTRequestorData::setup(
        swap_info.bst_sender_data.get_r_prime(),
        &m)?;

    requests::postb(
        &wallet.client_shim,
        &String::from("swap/first"),
        &SwapMsg1 {
            swap_id: swap_token.id.to_owned(),
            state_chain_id: state_chain_id.to_owned(),
            swap_token_sig: swap_token_sig.to_owned(),
            //Address::from_str("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"), //What are these variables?
            address: new_address.to_owned(),
            //FE::new_random
            bst_e_prime: my_bst_data.get_e_prime().clone()
        }
    )?;
    Ok(my_bst_data)
}

pub fn swap_get_blinded_spend_signature(
    client_shim: &ClientShim,
    swap_id: &Uuid,
    state_chain_id: &Uuid
) -> Result<BlindedSpendSignature> {
    requests::postb(
        &client_shim,
        &String::from("swap/blinded-spend-signature"),
        &BSTMsg {
            swap_id: swap_id.to_owned(),
            state_chain_id: state_chain_id.to_owned()
        }
    )
}

pub fn swap_second_message(
    wallet: &Wallet,
    swap_id: &Uuid,
    my_bst_data: &BSTRequestorData,
    blinded_spend_signature: &BlindedSpendSignature
) -> Result<SCEAddress> {
    let s = my_bst_data.unblind_signature(blinded_spend_signature.to_owned());
    let bst = my_bst_data.make_blind_spend_token(s);

    requests::postb(
        &wallet.client_shim,
        &String::from("swap/second"),
        &SwapMsg2 {
            swap_id: swap_id.to_owned(),
            blinded_spend_token: bst
        }
    )
}

pub fn do_swap(
    wallet: &Wallet,
    state_chain_id: &Uuid,
    swap_size: &u64
) -> Result<SCEAddress> {
    swap_register_utxo(wallet, state_chain_id, swap_size)?;
    loop {
        
    }
}