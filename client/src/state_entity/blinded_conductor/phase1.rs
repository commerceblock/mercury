use std::str::FromStr;

use bitcoin::PublicKey;
use shared_lib::{swap_data::{SwapStatus, SwapInfo, SwapMsg1}, structs::{SwapID, SCEAddress}, state_chain::StateChainSig, blinded_token::{BSTRequestorData, BlindedSpentTokenMessage}};
use uuid::Uuid;

use super::super::super::Result;

use crate::{ClientShim, utilities::requests, wallet::wallet::Wallet, error::{CError, WalletErrorType}};

pub fn swap_poll_swap(client_shim: &ClientShim, swap_id: &Uuid) -> Result<Option<SwapStatus>> {
    requests::postb(&client_shim, &String::from("swap/poll/swap"), &SwapID{id: Some(*swap_id)})
}

pub fn swap_info(client_shim: &ClientShim, swap_id: &Uuid) -> Result<Option<SwapInfo>> {
    requests::postb(&client_shim, &String::from("swap/info"), &SwapID{id: Some(*swap_id)})
}

pub fn swap_first_message(
    wallet: &Wallet,
    swap_info: &SwapInfo,
    statechain_id: &Uuid,
    transfer_batch_sig: &StateChainSig,
    new_address: &SCEAddress,
) -> Result<BSTRequestorData> {
    let swap_token = swap_info.swap_token.clone();

    let shared_key = wallet.get_shared_key_by_statechain_id(statechain_id)?;
    
    let proof_pub_key = match PublicKey::from_str(&shared_key.proof_key.as_ref().unwrap()) {
        Ok(v) => v,
        Err(e) => return Err(CError::SwapError(e.to_string())),
    };

    let proof_key_derivation = &wallet
        .se_proof_keys
        .get_key_derivation(&proof_pub_key)
        .ok_or(CError::WalletError(WalletErrorType::KeyNotFound))?;

    let proof_key_priv = &proof_key_derivation.private_key.key;

    let swap_token_sig = &swap_token.sign(&proof_key_priv)?;

    //Requester
    let m = serde_json::to_string(&BlindedSpentTokenMessage::new(swap_token.id))?;
    // Requester setup BST generation
    let my_bst_data = BSTRequestorData::setup(swap_info.bst_sender_data.get_r_prime(), &m)?;

    requests::postb(
        &wallet.conductor_shim,
        &String::from("swap/first"),
        &SwapMsg1 {
            swap_id: swap_token.id.to_owned(),
            statechain_id: statechain_id.to_owned(),
            swap_token_sig: swap_token_sig.to_owned().to_string(),
            transfer_batch_sig: transfer_batch_sig.to_owned(),
            address: new_address.to_owned(),
            bst_e_prime: my_bst_data.get_e_prime().clone(),
        },
    )?;
    Ok(my_bst_data)
}