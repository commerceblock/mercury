use core::time;
use std::thread;

use bitcoin::PrivateKey;
use shared_lib::structs::{SCEAddress, TransferMsg3, BatchData};
use uuid::Uuid;
use super::super::super::Result;

use crate::{wallet::wallet::Wallet, state_entity::transfer, error::CError};

use shared_lib::ecies::Encryptable;
use bitcoin_hashes::hex::FromHex;

// Loop throught the state chain ids
// Do transfer_receiver returning TransferFinalizedData if message is mine
pub fn do_transfer_receiver(
    priv_proof_key: &PrivateKey,
    mut wallet: &mut Wallet,
    batch_id: &Uuid,
    commit: &String,
    statechain_ids: &Vec<Uuid>,
    rec_se_addr: &SCEAddress, //my receiver address
) -> Result<transfer::BlindedTransferFinalizeData> {
    let mut msg: Option<TransferMsg3> = None;
    
    for statechain_id in statechain_ids {
        loop {
            match transfer::transfer_get_encrypted_msg(wallet, &statechain_id) {
                Ok(encrypted_msg3) => {
                    let encrypted_msg3_bytes = Vec::<u8>::from_hex(&encrypted_msg3).unwrap();
                    let msg3 = TransferMsg3::from_encrypted_bytes(priv_proof_key, &encrypted_msg3_bytes.as_slice());

                    match msg3 {
                        Ok(dec_msg) => {
                            msg = Some(dec_msg);
                            let mut msg = msg.clone().unwrap();
                            if msg.rec_se_addr.proof_key == rec_se_addr.proof_key {
                                match transfer::blinded_transfer_receiver(
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
                        },
                        Err(e) => { 
                            // the message is not for me
                            break;
                        },
                    }
                }
                Err(_) => (),
            };
            thread::sleep(time::Duration::from_secs(3));
        }

        if msg.is_some() {
            break;
        }
    }
    Err(CError::SwapError(
        "no transfer messages addressed to me".to_string(),
    ))
}