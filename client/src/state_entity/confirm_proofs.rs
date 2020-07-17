//! Confirm proofs
//!
//! Update the wallet proofs with the mainstay-attested proofs and verify

// update_proofs():
// 0. Initiate session - generate ID and perform authorisation
// 1. For each shared key in the wallet, update the proof if previously unconfirmed and a mainstay-confirmed proof is available
// 2. Return the number of successful/failed update attempts

use super::super::Result;
extern crate shared_lib;

use crate::wallet::wallet::Wallet;
use crate::wallet::shared_key::SharedKey;
use crate::state_entity::util::{verify_statechain_smt};
use super::api::{get_smt_proof, get_confirmed_smt_root};

/// Update wallet shared key proofs as required with mainstay-attested
/// ("confirmed") proofs. Returns a vector of shared_key_id of the keys 
/// that still have unconfirmed proofs.
pub fn confirm_proofs(wallet: &mut Wallet) -> Result<Vec<String>>
{   
    
    let mut failed = Vec::<String>::new();
    let mut keys_to_update = Vec::<&mut SharedKey>::new();
    let shim = wallet.client_shim.clone();

    
    // Verify proof key inclusion in SE sparse merkle tree
    println!("getting confirmed smt root");
    let root = match get_confirmed_smt_root(&wallet.client_shim)?{
        Some(root) => {
            //Get the funding txid and the corresponding funnding txid
            //for key in wallet.shared_keys_mutable() {
            for key in &mut wallet.shared_keys {
        
                match &mut key.smt_proof{
                    //Update proof if not confirmed in mainstay
                    Some(p)=> match p.root.is_confirmed(){
                        false => keys_to_update.push(key),
                        true => ()
                    },
                    //There should already be proofs for all shared keys
                    None => failed.push(key.id.clone()),
                };
            }
            root
        },
        None => {
            for key in &mut wallet.shared_keys {
                failed.push(key.id.clone());
            }
            println!("finished");
            return Ok(failed);
        }
    };

    
    for key in &mut keys_to_update {
       println!("getting smt proof");
       match get_smt_proof(&shim, &root, &key.funding_txid){
            Ok(proof) => {
                println!("got smt proof");
                match &key.proof_key {
                    Some(proof_key)=> match verify_statechain_smt(
                                        &Some(root.hash()),
                                        &proof_key.to_string(),
                                        &proof
                                        ) {
                                            false => failed.push(key.id.clone()),
                                            true =>  {
                                                // Update proof in Shared key
                                                println!("Add or update proof in Shared Key");
                                                key.update_proof(&root, &proof);
                                            }
                                        },
                    None => failed.push(key.id.clone())
                };
            },
            //Proof not in root yet
            Err(_) => failed.push(key.id.clone())
        }
    }

    println!("finished");
    Ok(failed)
}
