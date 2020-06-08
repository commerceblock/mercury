//! Util
//!
//! Utilities methods for state entity and mock classes

use super::Result;
use crate::structs::{BackUpTxPSM, WithdrawTxPSM};
use crate::error::SharedLibError;

use bitcoin::{TxIn, TxOut, Transaction, Address};
use bitcoin::hashes::sha256d::Hash;
use bitcoin::blockdata::script::Builder;
use bitcoin::{util::bip143::SighashComponents, blockdata::opcodes::OP_TRUE};

use std::str::FromStr;

/// network - move this to config
#[allow(dead_code)]
pub const RBF: u32 = 0xffffffff - 2;
pub const DUSTLIMIT: u64 = 100;
pub const FEE: u64 = 1000;


pub fn reverse_hex_str(hex_str: String) -> Result<String> {
    if hex_str.len() % 2 != 0 {
        return Err(SharedLibError::from(format!("Invalid sig hash - Odd number of characters. SigHash: {}",hex_str)))
    }
    let mut hex_str = hex_str.chars().rev().collect::<String>();
    let mut result = String::with_capacity(hex_str.len());
    unsafe {
        let hex_vec = hex_str.as_mut_vec();
        for i in (0..hex_vec.len()).step_by(2) {
            result.push(char::from(hex_vec[i+1]));
            result.push(char::from(hex_vec[i]));
        }
    }
    Ok(result)
}

/// rebuild backup tx and return sig hash from PrepareSignMessage data
pub fn rebuild_backup_tx(prepare_sign_msg: &BackUpTxPSM) -> Result<(Transaction, Hash)> {
    let txin = TxIn {
        previous_output: prepare_sign_msg.input,
        sequence: 0xFFFFFFFF,
        witness: Vec::new(),
        script_sig: bitcoin::Script::default(),
    };

    let tx_b = build_tx_b(
        &txin,
        &prepare_sign_msg.address,
        &prepare_sign_msg.amount
    )? ;

    let comp = SighashComponents::new(&tx_b);
    let sig_hash = comp.sighash_all(
        &txin,
        &Address::from_str(&prepare_sign_msg.spending_addr).unwrap().script_pubkey(),
        prepare_sign_msg.amount
    );
    Ok((tx_b, sig_hash))
}


/// rebuild withdraw tx and return sig hash from PrepareSignMessage data
pub fn rebuild_withdraw_tx(prepare_sign_msg: &WithdrawTxPSM) -> Result<(Transaction, Hash)> {
    let txin = TxIn {
        previous_output: prepare_sign_msg.input,
        sequence: 0xFFFFFFFF,
        witness: Vec::new(),
        script_sig: bitcoin::Script::default(),
    };

    let tx_w = build_tx_w(
        &txin,
        &prepare_sign_msg.address,
        &prepare_sign_msg.amount,
        &prepare_sign_msg.se_fee,
        &prepare_sign_msg.se_fee_addr
    )?;

    let comp = SighashComponents::new(&tx_w);
    let sig_hash = comp.sighash_all(
        &txin,
        &Address::from_str(&prepare_sign_msg.spending_addr).unwrap().script_pubkey(),
        prepare_sign_msg.amount
    );
    Ok((tx_w, sig_hash))
}


/// build funding tx spending inputs to p2wpkh address P for amount A
pub fn build_tx_0(inputs: &Vec<TxIn>, p_address: &String, amount: &u64, fee: &u64, fee_addr: &String, change_addr: &String, change_amount: &u64) -> Result<Transaction> {
    if FEE+fee >= *amount {
        return Err(SharedLibError::FormatError(String::from("Not enough value to cover fee.")));
    }
    let tx_0 = Transaction {
                version: 2,
                lock_time: 0,
                input: inputs.to_vec(),
                output: vec![
                    TxOut {
                        script_pubkey: Address::from_str(p_address)?.script_pubkey(),
                        value: *amount,
                    },
                    TxOut {
                        script_pubkey: Address::from_str(fee_addr)?.script_pubkey(),
                        value: *fee,
                    },
                    TxOut {
                        script_pubkey: Address::from_str(change_addr)?.script_pubkey(),
                        value: *change_amount-FEE,
                    }
                ],
            };
    Ok(tx_0)
}


/// build kick-off transaction spending funding tx to:
///     - amount A-D to p2wpkh address P, and
///     - amount D to script OP_TRUE
pub fn build_tx_k(funding_tx_in: &TxIn, p_address: &Address, amount: &u64) -> Result<Transaction> {
    if DUSTLIMIT >= *amount {
        return Err(SharedLibError::FormatError(String::from("Not enough value to cover fee.")));
    }
    let script = Builder::new().push_opcode(OP_TRUE).into_script();
    let tx_k = Transaction {
                input: vec![funding_tx_in.clone()],
                output: vec![
                    TxOut {
                        script_pubkey: p_address.script_pubkey(),
                        value: amount-DUSTLIMIT,
                    },
                    TxOut {
                        script_pubkey: script,
                        value: DUSTLIMIT,
                    }
                ],
                lock_time: 0,
                version: 2,
            };
    Ok(tx_k)
}

/// build backup tx spending P output of txK to given backup address
pub fn build_tx_b(txk_input: &TxIn, b_address: &String, amount: &u64) -> Result<Transaction> {
    if FEE >= *amount {
        return Err(SharedLibError::FormatError(String::from("Not enough value to cover fee.")));
    }
    let tx_b = Transaction {
                input: vec![txk_input.clone()],
                output: vec![
                    TxOut {
                        script_pubkey: Address::from_str(b_address)?.script_pubkey(),
                        value: amount-FEE,
                    }
                ],
                lock_time: 0,
                version: 2,
            };
    Ok(tx_b)
}


/// build withdraw tx spending funding tx to:
///     - amount-fee to receive address, and
///     - amount 'fee' to State Entity fee address 'fee_addr'
pub fn build_tx_w(funding_tx_in: &TxIn, rec_address: &String, amount: &u64, fee: &u64, fee_addr: &String) -> Result<Transaction> {
    if *fee+FEE >= *amount{
        return Err(SharedLibError::FormatError(String::from("Not enough value to cover fees.")));
    }
    let tx_0 = Transaction {
                version: 2,
                lock_time: 0,
                input: vec![funding_tx_in.clone()],
                output: vec![
                    TxOut {
                        script_pubkey: Address::from_str(rec_address)?.script_pubkey(),
                        value: amount-*fee-FEE,
                    },
                    TxOut {
                        script_pubkey: Address::from_str(fee_addr)?.script_pubkey(),
                        value: *fee,
                    }
                ],
            };
    Ok(tx_0)
}



#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use rand::rngs::OsRng;

    use bitcoin::{Amount,OutPoint, Script, Network};
    use bitcoin::util;
    use bitcoin::secp256k1::{Secp256k1, Message, key::SecretKey};
    use bitcoin::hashes::sha256d;

    const NETWORK: bitcoin::network::constants::Network = Network::Regtest;

    /// generate bitcoin::util::key key pair
    fn generate_keypair() -> (util::key::PrivateKey, util::key::PublicKey) {
        let secp = Secp256k1::new();
        let mut rng = OsRng::new().expect("OsRng");
        let secret_key = SecretKey::new(&mut rng);
        let priv_key = util::key::PrivateKey{
            compressed: false,
            network: NETWORK,
            key: secret_key
        };
        let pub_key = util::key::PublicKey::from_private_key(&secp, &priv_key);
        return (priv_key, pub_key)
    }

    #[test]
    fn transaction() {
        let secp = Secp256k1::new();

        let (priv_key, pub_key) = generate_keypair();
        let addr = Address::p2wpkh(&pub_key, NETWORK);
        let inputs =  vec![
            TxIn {
                previous_output: OutPoint { txid: sha256d::Hash::default(), vout: 0 },
                sequence: RBF,
                witness: Vec::new(),
                script_sig: Script::new(),
            }
        ];
        let amount = Amount::ONE_BTC.as_sat();
        let fee = 100;
        let fee_addr = String::from("bcrt1qjjwk2rk7nuxt6c79tsxthf5rpnky0sdhjr493x");
        let tx_0 = build_tx_0(&inputs, &addr.to_string(), &amount, &fee, &fee_addr, &addr.to_string(), &1000).unwrap();
        println!("{}", serde_json::to_string_pretty(&tx_0).unwrap());

        // Compute sighash
        let sighash = tx_0.signature_hash(0, &addr.script_pubkey(), amount as u32);
        // Makes signature.
        let msg = Message::from_slice(&sighash[..]).unwrap();
        let signature = secp.sign(&msg, &priv_key.key).serialize_der().to_vec();

        println!("signature: {:?}", signature);

        let tx_k = build_tx_k(tx_0.input.get(0).unwrap(), &addr, &amount).unwrap();
        println!("{}", serde_json::to_string_pretty(&tx_k).unwrap());

        let tx_1 = build_tx_b(&tx_k.input.get(0).unwrap(), &addr.to_string(), &amount).unwrap();
        println!("{}", serde_json::to_string_pretty(&tx_1).unwrap());
    }

    #[test]
    fn sign() {
        let secp = Secp256k1::new();
        let (priv_key, pub_key) = generate_keypair();
        let message = Message::from_slice(&[0xab; 32]).expect("32 bytes");

        let sig = secp.sign(&message, &priv_key.key);
        assert!(secp.verify(&message, &sig, &pub_key.key).is_ok());
    }
}
