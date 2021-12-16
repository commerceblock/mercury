//! Util
//!
//! Utilities methods for state entity protocol shared library

use super::Result;
use crate::error::SharedLibError;
use crate::structs::{PrepareSignTxMsg, StateChainDataAPI, StateEntityFeeInfoAPI};
#[cfg(test)]
use crate::Verifiable;

use bitcoin::{
    hashes::sha256d::Hash,
    Txid,
    {util::bip143::SigHashCache, OutPoint},
    {Address, Network, Transaction, TxIn, TxOut}, consensus,
};

use curv::PK;
use std::str::FromStr;

#[allow(dead_code)]
pub const RBF: u32 = 0xffffffff - 2;
pub const DUSTLIMIT: u64 = 100;
/// Temporary - fees should be calculated dynamically
pub const FEE: u64 = 141;

pub fn reverse_hex_str(hex_str: String) -> Result<String> {
    if hex_str.len() % 2 != 0 {
        return Err(SharedLibError::from(format!(
            "Invalid sig hash - Odd number of characters. SigHash: {}",
            hex_str
        )));
    }
    let mut hex_str = hex_str.chars().rev().collect::<String>();
    let mut result = String::with_capacity(hex_str.len());
    unsafe {
        let hex_vec = hex_str.as_mut_vec();
        for i in (0..hex_vec.len()).step_by(2) {
            result.push(char::from(hex_vec[i + 1]));
            result.push(char::from(hex_vec[i]));
        }
    }
    Ok(result)
}

/// consensus serialize tx into hex string
pub fn transaction_serialise(tx: &Transaction) -> String {
    hex::encode(consensus::serialize(tx))
}
/// consensus deserialize tx into Transaction
pub fn transaction_deserialise(ser: &String) -> Result<Transaction> {
    let buf = match hex::decode(ser) {
        Ok(v) => v,
        Err(_) => return Err(SharedLibError::FormatError(String::from("Transaction hex failed to deserialise")))
    };
    match consensus::deserialize::<Transaction>(&buf) {
        Ok(v) => return Ok(v),
        Err(_) => return Err(SharedLibError::FormatError(String::from("Transaction hex failed to deserialise")))
    }
}

/// Get sig hash for some transaction input.
/// Arguments: tx, index of input, address being spent from and amount
pub fn get_sighash(
    tx: &Transaction,
    tx_index: &usize,
    address_pk: &PK,
    amount: &u64,
    network: &String,
) -> Hash {
    let mut comp = SigHashCache::new(tx);
    let pk_btc = bitcoin::secp256k1::PublicKey::from_slice(&address_pk.serialize())
        .expect("failed to convert public key");
    comp.signature_hash(
        tx_index.to_owned(),
        &bitcoin::Address::p2pkh(
            &bitcoin::util::key::PublicKey {
                compressed: true,
                key: pk_btc,
            },
            network.parse::<Network>().unwrap(),
        )
        .script_pubkey(),
        *amount,
        bitcoin::blockdata::transaction::SigHashType::All,
    )
    .as_hash()
}

/// Check withdraw tx is valid
pub fn tx_withdraw_verify(
    tx_psm: &PrepareSignTxMsg,
    fee_address: &[&str],
    fee_withdraw: &u64,
) -> Result<()> {
    if tx_psm.input_addrs.len() != tx_psm.input_amounts.len() {
        return Err(SharedLibError::FormatError(String::from(
            "Withdraw tx number of signing addresses != number of input amounts.",
        )));
    }
    
    // Check fee info
    let tx = transaction_deserialise(&tx_psm.tx_hex)?;
    let mut found = 0;
    for i in 0..fee_address.len(){
        // found a correct address
        if tx.output[1].script_pubkey == Address::from_str(&fee_address[i])?.script_pubkey() {
            found = 1;
        }
    }

    // didn't find a correct address
    if found == 0 {
        return Err(SharedLibError::FormatError(String::from(
            "Incorrect State Entity fee address.",
        )));
    }

    if tx.output[1].value != fee_withdraw.to_owned() {
        return Err(SharedLibError::FormatError(String::from(
            "Incorrect State Entity fee.",
        )));
    }
    Ok(())
}

/// Build funding tx spending inputs to p2wpkh address P for amount A
pub fn tx_funding_build(
    inputs: &Vec<TxIn>,
    p_address: &String,
    amount: &u64,
    fee: &u64,
    fee_addr: &String,
    change_addr: &String,
    change_amount: &u64,
) -> Result<Transaction> {
    if FEE + fee >= *amount {
        return Err(SharedLibError::FormatError(String::from(
            "Not enough value to cover fee.",
        )));
    }

    let mut outputs = vec![
        TxOut {
            script_pubkey: Address::from_str(p_address)?.script_pubkey(),
            value: *amount,
        },
        TxOut {
            script_pubkey: Address::from_str(change_addr)?.script_pubkey(),
            value: *change_amount - FEE,
        },
    ];

    if *fee != 0 {
        outputs.push(
            TxOut {
                script_pubkey: Address::from_str(fee_addr)?.script_pubkey(),
                value: *fee,
            });
    }

    let tx_0 = Transaction {
        version: 2,
        lock_time: 0,
        input: inputs.to_vec(),
        output: outputs
    };
    Ok(tx_0)
}

/// Build backup tx spending P output of funding tx to given backup address
pub fn tx_backup_build(
    funding_txid: &Txid,
    b_address: &Address,
    amount: &u64,
    locktime: &u32,
    fee: &u64,
    fee_addr: &String,
) -> Result<Transaction> {
    if *fee + FEE >= *amount {
        return Err(SharedLibError::FormatError(String::from(
            "Not enough value to cover fee.",
        )));
    }

    let txin = TxIn {
        previous_output: OutPoint {
            txid: *funding_txid,
            vout: 0,
        },
        sequence: 0xFFFFFFFE,
        witness: Vec::new(),
        script_sig: bitcoin::Script::default(),
    };

    let tx_b = Transaction {
        input: vec![txin.clone()],
        output: vec![
            TxOut {
                script_pubkey: b_address.script_pubkey(),
                value: amount - *fee - FEE,
            },
            TxOut {
                script_pubkey: Address::from_str(fee_addr)?.script_pubkey(),
                value: *fee,
            },
        ],
        lock_time: *locktime,
        version: 2,
    };
    Ok(tx_b)
}

/// Build withdraw tx spending funding tx to:
///     - amount-fee to receive address, and
///     - amount 'fee' to State Entity fee address 'fee_addr'

/*pub fn tx_withdraw_build(
    funding_txid: &Txid,
    rec_se_address: &Address,
    amount: &u64,
    fee: &u64,
    fee_addr: &String,
) -> Result<Transaction> {
*/

pub fn tx_withdraw_build(
    sc_infos: &Vec::<StateChainDataAPI>,
    rec_se_address: &Address,
    se_fee_info: &StateEntityFeeInfoAPI,
    tx_fee: &u64
) -> Result<Transaction> {
    let mut txins = Vec::<TxIn>::new();

    let amount = {
        let mut total = 0;
        for info in sc_infos {
            total += info.amount;

            let txin = TxIn {
                previous_output: OutPoint {
                    txid: info.utxo.txid,
                    vout: 0,
                },
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
                script_sig: bitcoin::Script::default(),
            };
            
            txins.push(txin);
        };
        total + se_fee_info.deposit as u64
    };

    let fee = (amount*se_fee_info.withdraw) / 10000 as u64;

    if fee + tx_fee >= amount {
        return Err(SharedLibError::FormatError(String::from(
            "Not enough value to cover fees.",
        )));
    }


    let tx_0 = Transaction {
        version: 2,
        lock_time: 0,
        input: txins,
        output: vec![
            TxOut {
                script_pubkey: rec_se_address.script_pubkey(),
                value: amount - fee - tx_fee,
            },
            TxOut {
                script_pubkey: Address::from_str(&se_fee_info.address)?.script_pubkey(),
                value: fee,
            },
        ],
    };
    Ok(tx_0)
}

pub mod keygen {
    pub use bitcoin::secp256k1::{key::SecretKey, Message, PublicKey, Secp256k1};
    pub use bitcoin::util;
    pub use bitcoin::{Amount, Network, OutPoint, Script};
    pub use rand::rngs::OsRng;
    pub const NETWORK: bitcoin::network::constants::Network = Network::Regtest;
    /// generate bitcoin::util::key key pair
    pub fn generate_keypair() -> (util::key::PrivateKey, util::key::PublicKey) {
        let secp = Secp256k1::new();
        let secret_key = generate_secret_key();
        let priv_key = util::key::PrivateKey {
            compressed: true,
            network: NETWORK,
            key: secret_key,
        };
        let pub_key = util::key::PublicKey::from_private_key(&secp, &priv_key);
        return (priv_key, pub_key);
    }

    pub fn generate_secp_keypair() -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let secret_key = generate_secret_key();
        let pub_key = PublicKey::from_secret_key(&secp, &secret_key);
        return (secret_key, pub_key);
    }

    pub fn generate_secret_key() -> SecretKey {
        let mut rng = OsRng::new().expect("OsRng");
        SecretKey::new(&mut rng)
    }
}

#[cfg(test)]
pub mod tests {
    use super::keygen::*;
    use super::*;
    use serde_json;

    #[test]
    fn transaction() {
        let secp = Secp256k1::new();

        let (priv_key, pub_key) = generate_keypair();

        let addr = match Address::p2wpkh(&pub_key, NETWORK) {
            Ok(r) => r,
            Err(e) => {
                assert!(false, "{}", e);
                return;
            }
        };

        let inputs = vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::default(),
                vout: 0,
            },
            sequence: RBF,
            witness: Vec::new(),
            script_sig: Script::new(),
        }];
        let amount = Amount::ONE_BTC.as_sat();
        let fee = 100;
        let fee_addr = String::from("bcrt1qjjwk2rk7nuxt6c79tsxthf5rpnky0sdhjr493x");
        let tx_0 = tx_funding_build(
            &inputs,
            &addr.to_string(),
            &amount,
            &fee,
            &fee_addr,
            &addr.to_string(),
            &1000,
        )
        .unwrap();
        println!("{}", serde_json::to_string_pretty(&tx_0).unwrap());

        // Compute sighash
        let sighash = tx_0.signature_hash(0, &addr.script_pubkey(), amount as u32);
        // Makes signature.
        let msg = Message::from_slice(&sighash[..]).unwrap();
        let signature = secp.sign(&msg, &priv_key.key).serialize_der().to_vec();

        println!("signature: {:?}", signature);

        // let tx_1 = tx_backup_build(&tx_k.input.get(0).unwrap(), &addr.to_string(), &amount).unwrap();
        // println!("{}", serde_json::to_string_pretty(&tx_1).unwrap());
    }

    #[test]
    fn sign() {
        let secp = Secp256k1::new();
        let (priv_key, pub_key) = generate_keypair();
        let message = Message::from_slice(&[0xab; 32]).expect("32 bytes");

        let sig = secp.sign(&message, &priv_key.key);
        assert!(sig.verify_btc(&pub_key, &message).is_ok());
    }
}
