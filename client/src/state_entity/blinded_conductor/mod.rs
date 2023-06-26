pub mod swap_init;
pub mod phase0;
pub mod phase1;
pub mod phase2;
pub mod phase4;

use core::time;
use std::thread;

use bitcoin_hashes::hex::ToHex;
use shared_lib::{swap_data::{SwapInfo, SwapStatus}, structs::{SCEAddress, SwapID}, commitment};
use uuid::Uuid;

use super::{super::Result, transfer};

use crate::{wallet::wallet::Wallet, error::CError, ClientShim, utilities::requests, state_entity::api::{get_transfer_batch_status, get_blinded_transfer_batch_status}};

pub fn swap_poll_swap(client_shim: &ClientShim, swap_id: &Uuid) -> Result<Option<SwapStatus>> {
    requests::postb(&client_shim, &String::from("swap/poll/swap"), &SwapID{id: Some(*swap_id)})
}

pub fn do_swap(
    mut wallet: &mut Wallet,
    statechain_id: &Uuid,
    swap_size: &u64,
    with_tor: bool,
) -> Result<()> {

    if with_tor & (!wallet.client_shim.has_tor()  |! wallet.conductor_shim.has_tor()){
        return Err(CError::SwapError("tor not enabled".to_string()));
    }

    // --- Phase Swap Init ---
    // step 1
    swap_init::swap_register_utxo(&wallet, &statechain_id, &swap_size)?;

    // --- Phase 0 ---
    let swap_id;
    //Wait for swap to commence

    loop {

        println!("Waiting for swap to commence");

        match phase0::swap_poll_utxo(&wallet.conductor_shim, &statechain_id)?.id {
            Some(v) => {
                swap_id = v;
                break;
            }
            None => (),
        }
        thread::sleep(time::Duration::from_secs(3));
    }

    // --- Phase 1 ---
    // Wait for swap info to become available
    let info: SwapInfo;

    loop {
        match phase1::swap_info(&wallet.conductor_shim, &swap_id)? {
            Some(v) => {
                info = v;
                break;
            }
            None => (),
        }
        thread::sleep(time::Duration::from_secs(3));
    }

    let (pub_proof_key, priv_proof_key) = wallet.se_proof_keys.get_new_key_priv()?;

    let proof_key = bitcoin::secp256k1::PublicKey::from_slice(&pub_proof_key.to_bytes().as_slice())?;

    let address = SCEAddress {
        tx_backup_addr: None,
        proof_key,
    };

    let transfer_batch_sig = transfer::blinded_transfer_batch_sign(wallet, &statechain_id, &swap_id)?;

    let my_bst_data = phase1::swap_first_message(
        &wallet,
        &info,
        &statechain_id,
        &transfer_batch_sig,
        &address,
    )?;

    // --- Phase 2 ---
    //Wait until swap is in phase4 then transfer sender

    loop {
        match swap_poll_swap(&wallet.conductor_shim, &swap_id)? {
            Some(v) => match v {
                SwapStatus::Phase2 => {
                    break;
                }
                _ => (),
            },
            None => (),
        };
        thread::sleep(time::Duration::from_secs(3));
    }

    let bss = phase2::swap_get_blinded_spend_signature(&wallet.conductor_shim, &swap_id, &statechain_id)?;

    if with_tor {
        wallet.client_shim.new_tor_id()?;
        wallet.conductor_shim.new_tor_id()?;
    }

    let receiver_addr = phase2::swap_second_message(&wallet, &swap_id, &my_bst_data, &bss)?;

    // --- Phase 3 ---
    //Wait until swap is in phase4 then transfer sender
    loop {
        match swap_poll_swap(&wallet.conductor_shim, &swap_id)? {
            Some(v) => match v {
                SwapStatus::Phase4 => {
                    break;
                }
                _ => (),
            },
            None => (),
        };
        thread::sleep(time::Duration::from_secs(3));
    }

    let _ = transfer::blinded_transfer_sender(&mut wallet, statechain_id, receiver_addr, Some(swap_id.clone()) )?;

    let mut commitment_data = statechain_id.to_string();
    let mut sorted_sc_ids = info.swap_token.statechain_ids.clone();
    sorted_sc_ids.sort();
    for id in sorted_sc_ids {
        commitment_data.push_str(&id.to_string());
    }

    let (commit, _nonce) = commitment::make_commitment(&commitment_data);

    let batch_id = &swap_id;

    // --- Phase 4 ---
    let transfer_finalized_data = phase4::do_transfer_receiver(
        &priv_proof_key,
        wallet,
        batch_id,
        &commit,
        &info.swap_token.statechain_ids,
        &address,
    )?;

    //Wait until swap is in phase End
    loop {
        match swap_poll_swap(&wallet.conductor_shim, &swap_id)? {
            Some(v) => match v {
                SwapStatus::End => {
                    break;
                }
                _ => (),
            },
            None => break,
        };
        thread::sleep(time::Duration::from_secs(3));
    }

    //Confirm batch transfer status and finalize the transfer in the wallet
    let bt_status = get_blinded_transfer_batch_status(&wallet.client_shim, &batch_id)?;

    if !bt_status.finalized {
        return Err(CError::SwapError(
            "batch transfer not finalized".to_string(),
        ));
    }

    transfer::blinded_transfer_receiver_finalize(&mut wallet, transfer_finalized_data)?;

    println!("Swap completed");

    Ok(())

}