//! Conductor
//!
//! Interact with a swap conductor

use super::super::Result;

use crate::error::{CError, WalletErrorType};
use crate::state_entity::{
    api::{get_statecoin, get_transfer_batch_status},
    transfer,
};
use crate::wallet::wallet::Wallet;
use crate::{utilities::requests, ClientShim};
use shared_lib::{state_chain::StateChainSig, structs::*};

use shared_lib::blinded_token::{
    BSTRequestorData, BlindedSpendSignature, BlindedSpentTokenMessage,
};
use shared_lib::{commitment, swap_data::*};

use bitcoin::PublicKey;
use std::str::FromStr;
use std::{thread, time};
use uuid::Uuid;

// Register a state chain for participation in a swap (request a swap)
// with swap_size participants
pub fn swap_register_utxo(wallet: &Wallet, statechain_id: &Uuid, swap_size: &u64) -> Result<()> {
    // First sign state chain
    let statecoin_data: StateCoinDataAPI = get_statecoin(&wallet.client_shim, &statechain_id)?;
    // Get proof key for signing
    let proof_key_derivation = &wallet
        .se_proof_keys
        .get_key_derivation(&PublicKey::from_str(&statecoin_data.statecoin.data).unwrap())
        .ok_or(CError::WalletError(WalletErrorType::KeyNotFound))?;
    let statechain_sig = StateChainSig::new(
        &proof_key_derivation.private_key.key,
        &String::from("SWAP"),
        &proof_key_derivation.public_key.unwrap().to_string(),
    )?;

    requests::postb(
        &wallet.conductor_shim,
        &String::from("swap/register-utxo"),
        &RegisterUtxo {
            statechain_id: statechain_id.to_owned(),
            signature: statechain_sig,
            swap_size: swap_size.to_owned(),
        },
    )
}

pub fn swap_poll_utxo(client_shim: &ClientShim, statechain_id: &Uuid) -> Result<SwapID> {
    requests::postb(
        &client_shim,
        &String::from("swap/poll/utxo"),
        &StatechainID { id: *statechain_id },
    )
}

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

    let statecoin_data: StateCoinDataAPI = get_statecoin(&wallet.client_shim, &statechain_id)?;
    
    let proof_pub_key = match PublicKey::from_str(&statecoin_data.statecoin.data) {
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

pub fn swap_get_blinded_spend_signature(
    client_shim: &ClientShim,
    swap_id: &Uuid,
    statechain_id: &Uuid,
) -> Result<BlindedSpendSignature> {
    requests::postb(
        &client_shim,
        &String::from("swap/blinded-spend-signature"),
        &BSTMsg {
            swap_id: swap_id.to_owned().to_string(),
            statechain_id: statechain_id.to_owned().to_string(),
        },
    )
}

pub fn swap_second_message(
    wallet: &Wallet,
    swap_id: &Uuid,
    my_bst_data: &BSTRequestorData,
    blinded_spend_signature: &BlindedSpendSignature,
) -> Result<SCEAddress> {
    let s = my_bst_data.unblind_signature(blinded_spend_signature.to_owned());
    let bst = my_bst_data.make_blind_spend_token(s);

    requests::postb(
        &wallet.conductor_shim,
        &String::from("swap/second"),
        &SwapMsg2 {
            swap_id: swap_id.to_owned(),
            blinded_spend_token: bst,
        },
    )
}

// Loop throught the state chain ids
// Do transfer_receiver returning TransferFinalizedData if message is mine
fn do_transfer_receiver(
    mut wallet: &mut Wallet,
    batch_id: &Uuid,
    commit: &String,
    statechain_ids: &Vec<Uuid>,
    rec_se_addr: &SCEAddress, //my receiver address
) -> Result<transfer::TransferFinalizeData> {
    for statechain_id in statechain_ids {
        loop {
            match transfer::transfer_get_msg(wallet, &statechain_id) {
                Ok(mut msg) => {
                    if msg.rec_se_addr.proof_key == rec_se_addr.proof_key {
                        match transfer::transfer_receiver(
                            &mut wallet,
                            &mut msg,
                            &Some(BatchData {
                                id: batch_id.clone(),
                                commitment: commit.clone(),
                            }),
                        ) {
                            Ok(r) => return Ok(r),
                            Err(e) => return Err(e),
                        }
                    } else {
                        break;
                    }
                }
                Err(_) => (),
            };
            thread::sleep(time::Duration::from_secs(3));
        }
    }
    Err(CError::SwapError(
        "no transfer messages addressed to me".to_string(),
    ))
}

pub fn do_swap(
    mut wallet: &mut Wallet,
    statechain_id: &Uuid,
    swap_size: &u64,
    with_tor: bool,
) -> Result<SCEAddress> {
    if with_tor & (!wallet.client_shim.has_tor()  |! wallet.conductor_shim.has_tor()){
        return Err(CError::SwapError("tor not enabled".to_string()));
    }

    swap_register_utxo(wallet, statechain_id, swap_size)?;
    let swap_id;
    //Wait for swap to commence

    loop {
        match swap_poll_utxo(&wallet.conductor_shim, &statechain_id)?.id {
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
        match swap_info(&wallet.conductor_shim, &swap_id)? {
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

    let transfer_batch_sig = transfer::transfer_batch_sign(wallet, &statechain_id, &swap_id)?;

    let my_bst_data = swap_first_message(
        &wallet,
        &info,
        &statechain_id,
        &transfer_batch_sig,
        &address,
    )?;

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

    let bss = swap_get_blinded_spend_signature(&wallet.conductor_shim, &swap_id, &statechain_id)?;

    if with_tor {
        wallet.client_shim.new_tor_id()?;
        wallet.conductor_shim.new_tor_id()?;
    }

    let receiver_addr = swap_second_message(&wallet, &swap_id, &my_bst_data, &bss)?;

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

    let _ = transfer::transfer_sender(&mut wallet, statechain_id, receiver_addr)?;

    let mut commitment_data = statechain_id.to_string();
    let mut sorted_sc_ids = info.swap_token.statechain_ids.clone();
    sorted_sc_ids.sort();
    for id in sorted_sc_ids {
        commitment_data.push_str(&id.to_string());
    }

    let (commit, _nonce) = commitment::make_commitment(&commitment_data);

    let batch_id = &swap_id;

    let transfer_finalized_data = do_transfer_receiver(
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
    let bt_status = get_transfer_batch_status(&wallet.client_shim, &batch_id)?;

    if !bt_status.finalized {
        return Err(CError::SwapError(
            "batch transfer not finalized".to_string(),
        ));
    }
    transfer::transfer_receiver_finalize(&mut wallet, transfer_finalized_data)?;

    Ok(address)
}
