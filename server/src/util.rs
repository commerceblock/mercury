//! Util
//!
//! Utilities methods for state entity and mock classes


use rand::rngs::OsRng;
use bitcoin::util;
use bitcoin::secp256k1::{ Secp256k1, key::SecretKey };

use bitcoin::blockdata::transaction::{ TxIn, TxOut, Transaction };
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::opcodes::OP_TRUE;
use bitcoin::util::{ address::Address, amount::Amount };
use bitcoin::network::constants::Network;


/// network - move this to config
pub const NETWORK: bitcoin::network::constants::Network = Network::Regtest;
#[allow(dead_code)]
const RBF: u32 = 0xffffffff - 2;
const DUSTLIMIT: u64 = 100;

/// generate bitcoin::util::key key pair
pub fn generate_keypair() -> (util::key::PrivateKey, util::key::PublicKey) {
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

/// build funding tx spending inputs to p2wpkh address P for amount A
pub fn build_tx_0(inputs: &Vec<TxIn>, p_address: &Address, amount: &Amount) -> Result<Transaction,()> {
    let tx_0 = Transaction {
                input: inputs.to_vec(),
                output: vec![
                    TxOut {
                        script_pubkey: p_address.script_pubkey(),
                        value: amount.as_sat(),
                    }
                ],
                lock_time: 0,
                version: 2,
            };
    Ok(tx_0)
}

/// build kick-off transaction spending funding tx to:
///     - amount A-D to p2wpkh address P, and
///     - amount D to script OP_TRUE
pub fn build_tx_k(funding_tx_in: &TxIn, p_address: &Address, amount: &Amount) -> Result<Transaction,()> {
    let script = Builder::new().push_opcode(OP_TRUE).into_script();
    let tx_k = Transaction {
                input: vec![funding_tx_in.clone()],
                output: vec![
                    TxOut {
                        script_pubkey: p_address.script_pubkey(),
                        value: amount.as_sat()-DUSTLIMIT,
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

/// build backup tx spending P output of txK to given backup address at maximum nSequence
pub fn build_tx_1(mut txk_input: TxIn, b_address: &Address, amount: &Amount) -> Result<Transaction,()> {
    txk_input.sequence = 65535;
    let tx_0 = Transaction {
                input: vec![txk_input],
                output: vec![
                    TxOut {
                        script_pubkey: b_address.script_pubkey(),
                        value: amount.as_sat(),
                    }
                ],
                lock_time: 0,
                version: 2,
            };
    Ok(tx_0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    use bitcoin::OutPoint;
    use bitcoin::blockdata::script::Script;
    use bitcoin::secp256k1::{Secp256k1, Message};
    use bitcoin::hashes::sha256d;

    use crate::util::generate_keypair;

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
        let amount = Amount::ONE_BTC;
        let tx_0 = build_tx_0(&inputs, &addr, &amount).unwrap();
        println!("{}", serde_json::to_string_pretty(&tx_0).unwrap());

        // Compute sighash
        let sighash = tx_0.signature_hash(0, &addr.script_pubkey(), amount.as_sat() as u32);
        // Makes signature.
        let msg = Message::from_slice(&sighash[..]).unwrap();
        let signature = secp.sign(&msg, &priv_key.key).serialize_der().to_vec();

        println!("signature: {:?}", signature);

        let tx_k = build_tx_k(tx_0.input.get(0).unwrap(), &addr, &amount).unwrap();
        println!("{}", serde_json::to_string_pretty(&tx_k).unwrap());

        let tx_1 = build_tx_1(tx_k.input.get(0).unwrap().clone(), &addr, &amount).unwrap();
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
