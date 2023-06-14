pub mod swap_init;
pub mod phase0;
pub mod phase1;

use core::time;
use std::thread;

use shared_lib::{swap_data::SwapInfo, structs::SCEAddress};
use uuid::Uuid;

use super::{super::Result, transfer};

use crate::{wallet::wallet::Wallet, error::CError};

pub fn do_swap(
    mut wallet: &mut Wallet,
    statechain_id: &Uuid,
    swap_size: &u64,
    with_tor: bool,
) -> Result<()> {

    if with_tor & (!wallet.client_shim.has_tor()  |! wallet.conductor_shim.has_tor()){
        return Err(CError::SwapError("tor not enabled".to_string()));
    }

    // step 1
    swap_init::swap_register_utxo(&wallet, &statechain_id, &swap_size)?;
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

    //Wait for swap info to become available
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

    let proof_key = wallet.se_proof_keys.get_new_key()?;

    let proof_key = bitcoin::secp256k1::PublicKey::from_slice(&proof_key.to_bytes().as_slice())?;

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

    Ok(())

}