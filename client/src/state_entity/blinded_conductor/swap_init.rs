
use shared_lib::{state_chain::StateChainSig, swap_data::RegisterUtxo};
use uuid::Uuid;

use super::super::super::Result;

use crate::{wallet::wallet::Wallet, error::{WalletErrorType, CError}, utilities::requests};
use bitcoin::PublicKey;
use std::str::FromStr;

// Register a state chain for participation in a swap (request a swap)
// with swap_size participants
pub fn swap_register_utxo(wallet: &Wallet, statechain_id: &Uuid, swap_size: &u64) -> Result<()> {

    // First sign state chain
    let shared_key = wallet.get_shared_key_by_statechain_id(statechain_id)?;

    // Get proof key for signing
    let proof_key_derivation = wallet
        .se_proof_keys
        .get_key_derivation(&PublicKey::from_str(&shared_key.proof_key.as_ref().unwrap()).unwrap());

    let proof_key_priv = &proof_key_derivation
        .ok_or(CError::WalletError(WalletErrorType::KeyNotFound))?
        .private_key
        .key;

    let data = &proof_key_derivation
        .ok_or(CError::WalletError(WalletErrorType::KeyNotFound))?
        .public_key
        .unwrap().to_string();

    let statechain_sig = StateChainSig::new(
        proof_key_priv,
        &String::from("SWAP"),
        data,
    )?;

    requests::postb(
        &wallet.conductor_shim,
        &String::from("blinded/swap/register-utxo"),
        &RegisterUtxo {
            statechain_id: statechain_id.to_owned(),
            signature: statechain_sig,
            swap_size: swap_size.to_owned(),
            wallet_version: "0.6.0".to_string(),
        },
    )
}