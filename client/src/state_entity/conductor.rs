//! Conductor
//! 
//! Interact with a swap conductor

use super::super::Result;

use crate::error::{CError, WalletErrorType};
use crate::state_entity::{
    api::{get_statechain, get_transfer_batch_status},
    transfer,
};
use crate::wallet::wallet::Wallet;
use crate::{utilities::requests, ClientShim};
use shared_lib::{state_chain::StateChainSig, structs::*};

use shared_lib::blinded_token::{BlindedSpendSignature, BSTRequestorData, BlindedSpentTokenMessage};
use shared_lib::{swap_data::*, commitment};

use bitcoin::PublicKey;
use std::str::FromStr;
use uuid::Uuid;
use std::{thread, time};

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
    transfer_batch_sig: &StateChainSig,
    new_address: &SCEAddress
) -> Result<BSTRequestorData> {
    let swap_token = swap_info.swap_token.clone();

    let state_chain_data: StateChainDataAPI = get_statechain(&wallet.client_shim, &state_chain_id)?;
    let state_chain = state_chain_data.chain;

    let proof_pub_key = match PublicKey::from_str(&state_chain.last().unwrap().data){
        Ok(v) => v,
        Err(e) => return Err(CError::SwapError(e.to_string()))
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
            transfer_batch_sig: transfer_batch_sig.to_owned(),
            address: new_address.to_owned(),
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

// Loop throught the state chain ids
// Do transfer_receiver returning TransferFinalizedData if message is mine
fn do_transfer_receiver(
    mut wallet: &mut Wallet,
    batch_id: &Uuid,
    commit: &String,
    statechain_ids: &Vec<Uuid>,
    rec_addr: &SCEAddress, //my receiver address
) -> Result<transfer::TransferFinalizeData> {
    for statechain_id in statechain_ids{
        loop {
            match transfer::transfer_get_msg(wallet, &statechain_id){
                Ok(mut msg) => {
                    if msg.rec_addr.proof_key == rec_addr.proof_key {
                        match transfer::transfer_receiver(
                            &mut wallet,
                            &mut msg,
                            &Some(BatchData {
                            id: batch_id.clone(),
                            commitment: commit.clone(),
                            }),
                        ){
                            Ok(r) => return Ok(r),
                            Err(e) => return Err(e),
                        }
                    } else {
                        break;
                    }
                },
                Err(_) => (),
            };
            thread::sleep(time::Duration::from_millis(1000));
        }
    }
    Err(CError::SwapError("no transfer messages addressed to me".to_string()))
}

pub fn do_swap(
    mut wallet: &mut Wallet,
    state_chain_id: &Uuid,
    swap_size: &u64,
    with_tor: bool
) -> Result<SCEAddress> {
    if with_tor &! wallet.client_shim.has_tor() {
        return Err(CError::SwapError("tor not enabled".to_string()))
    }

    swap_register_utxo(wallet, state_chain_id, swap_size)?;
    let swap_id;
    //Wait for swap to commence
    
    loop {
        match swap_poll_utxo(&wallet.client_shim, &state_chain_id)?{
            Some(v) => {
                swap_id = v;
                break;
            },
            None => {
                ()
            },
        }
        thread::sleep(time::Duration::from_millis(1000));
    }
    //Wait for swap info to become available
    let info: SwapInfo;

    loop {
        match swap_info(&wallet.client_shim, &swap_id)?{
            Some(v) => {
                info = v;
                break;
            },
            None => (),
        }
        thread::sleep(time::Duration::from_millis(1000));
    }
    
    let proof_key = wallet.se_proof_keys.get_new_key()?;
    
    let proof_key =
    bitcoin::secp256k1::PublicKey::from_slice(&proof_key.to_bytes().as_slice())?;

    let address = SCEAddress {tx_backup_addr: None, proof_key};

    let transfer_batch_sig = transfer::transfer_batch_sign(wallet, &state_chain_id, &swap_id)?;

    
    let my_bst_data = swap_first_message(&wallet, &info, &state_chain_id, &transfer_batch_sig, &address)?;

    //Wait until swap is in phase4 then transfer sender
    
    loop {
        match swap_poll_swap(&wallet.client_shim, &swap_id)?{
            Some(v) => {
                match v {
                    SwapStatus::Phase2 => {
                    break;
                },
                    _ => (),
                }
            },
            None => (),
        };
        thread::sleep(time::Duration::from_millis(1000));
    }

    let bss = swap_get_blinded_spend_signature(&wallet.client_shim, &swap_id, &state_chain_id)?;

    if with_tor {
        wallet.client_shim.new_tor_id()?;
    }

    let receiver_addr = swap_second_message(&wallet, &swap_id, &my_bst_data, &bss)?;


    //Wait until swap is in phase4 then transfer sender
    loop {
        match swap_poll_swap(&wallet.client_shim, &swap_id)?{
            Some(v) => {
                match v {
                    SwapStatus::Phase4 => {
                        break;
                    },
                    _ => (),
                }
            },
            None => (),
        };
        thread::sleep(time::Duration::from_millis(1000));
    }

    let _ = transfer::transfer_sender(
        &mut wallet,
        state_chain_id,
        receiver_addr,
    )?;

    thread::sleep(time::Duration::from_millis(1000));

    let (commit, _nonce) = commitment::make_commitment(&state_chain_id.to_string());

    let batch_id = &swap_id;

    thread::sleep(time::Duration::from_millis(1000));

        
    let transfer_finalized_data = do_transfer_receiver(
        wallet,
        batch_id,
        &commit,
        &info.swap_token.state_chain_ids,
        &address
    )?;
        

    //Wait until swap is in phase End
    loop {
        match swap_poll_swap(&wallet.client_shim, &swap_id)?{
            Some(v) => {
                match v {
                    SwapStatus::End => {
                        break;
                    },
                    _ => (),
                }
            },
            None => break,
        };
        thread::sleep(time::Duration::from_millis(10000));
    }

    //Confirm batch transfer status and finalize the transfer in the wallet
    let bt_status = get_transfer_batch_status(&wallet.client_shim, &batch_id)?;

    if !bt_status.finalized {
        return Err(CError::SwapError("batch transfer not finalized".to_string()));
    }
    transfer::transfer_receiver_finalize(&mut wallet, transfer_finalized_data)?;
    
    Ok(address)
}