//! Util
//!
//! Utilities methods for state entity and mock classes

type Result<T> = std::result::Result<T, UtilError>;

use bitcoin::{TxIn, TxOut, Transaction, Address, Amount};
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::opcodes::OP_TRUE;

use rocket::http::{ Status, ContentType };
use rocket::Response;
use rocket::Request;
use rocket::response::Responder;

use std::error;
use std::fmt;
use std::io::Cursor;


/// network - move this to config
#[allow(dead_code)]
pub const RBF: u32 = 0xffffffff - 2;
const DUSTLIMIT: u64 = 100;
const FEE: u64 = 1000;

/// build funding tx spending inputs to p2wpkh address P for amount A
pub fn build_tx_0(inputs: &Vec<TxIn>, p_address: &Address, amount: &Amount) -> Result<Transaction> {
    let tx_0 = Transaction {
                input: inputs.to_vec(),
                output: vec![
                    TxOut {
                        script_pubkey: p_address.script_pubkey(),
                        value: amount.as_sat()-FEE,
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
pub fn build_tx_k(funding_tx_in: &TxIn, p_address: &Address, amount: &Amount) -> Result<Transaction> {
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

/// build backup tx spending P output of txK to given backup address
pub fn build_tx_b(txk_input: &TxIn, b_address: &Address, amount: &Amount) -> Result<Transaction> {
    let tx_0 = Transaction {
                input: vec![txk_input.clone()],
                output: vec![
                    TxOut {
                        script_pubkey: b_address.script_pubkey(),
                        value: amount.as_sat()-FEE,
                    }
                ],
                lock_time: 0,
                version: 2,
            };
    Ok(tx_0)
}

pub fn reverse_hex_str(hex_str: String) -> Result<String> {
    if hex_str.len() % 2 != 0 {
        return Err(UtilError::from(format!("Invalid sig hash - Odd number of characters. SigHash: {}",hex_str)))
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


/// Shared library Util specific errors
#[derive(Debug, Deserialize)]
pub enum UtilError {
    /// Generic error from string error message
    Generic(String),
    /// Invalid argument error
    FormatError(String)
}

impl From<String> for UtilError {
    fn from(e: String) -> UtilError {
        UtilError::Generic(e)
    }
}

impl fmt::Display for UtilError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            UtilError::Generic(ref e) => write!(f, "Error: {}", e),
            UtilError::FormatError(ref e) => write!(f,"Format Error: {}",e),
        }
    }
}

impl error::Error for UtilError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            _ => None,
        }
    }
}

impl Responder<'static> for UtilError {
    fn respond_to(self, _: &Request) -> ::std::result::Result<Response<'static>, Status> {
        Response::build()
            .header(ContentType::JSON)
            .sized_body(Cursor::new(format!("{}", self)))
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use rand::rngs::OsRng;

    use bitcoin::OutPoint;
    use bitcoin::util;
    use bitcoin::blockdata::script::Script;
    use bitcoin::secp256k1::{Secp256k1, Message, key::SecretKey};
    use bitcoin::hashes::sha256d;
    use bitcoin::network::constants::Network;

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

        let tx_1 = build_tx_b(&tx_k.input.get(0).unwrap(), &addr, &amount).unwrap();
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
