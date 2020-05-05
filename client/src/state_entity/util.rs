//! Util
//!
//! Utilities methods for state entity and mock classes

use bitcoin::OutPoint;
use super::super::utilities::requests;
use super::super::Result;
use crate::wallet::wallet::Wallet;
use crate::ecdsa;

use bitcoin::util;
use bitcoin::{ Address, Amount, Transaction, TxIn, TxOut };
use bitcoin::util::bip143::SighashComponents;
use bitcoin::secp256k1::{ Secp256k1, key::SecretKey, Signature };
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::opcodes::OP_TRUE;
use bitcoin::network::constants::Network;
use bitcoin::hashes::sha256d;
use curv::{BigInt};
use curv::arithmetic::traits::Converter;
use curv::elliptic::curves::traits::ECPoint;

use rand::rngs::OsRng;
use std::str::FromStr;

/// network - move this to config
pub const NETWORK: bitcoin::network::constants::Network = Network::Regtest;
#[allow(dead_code)]
pub const RBF: u32 = 0xffffffff - 2;
const DUSTLIMIT: u64 = 100;
const FEE: u64 = 1000;

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

/// Get state chain by ID
pub fn get_statechain(wallet: &mut Wallet, state_chain_id: &String) -> Result<Vec<String>> {
    requests::post(&wallet.client_shim,&format!("api/statechain/{}",state_chain_id))
}

/// struct contains data necessary to caluculate tx input sighash
#[derive(Serialize, Deserialize, Debug)]
pub struct PrepareSignTxMessage {
    pub spending_addr: String, // address which funding tx funds are sent to
    pub input_txid: String,
    pub input_vout: u32,
    pub address: String,
    pub amount: u64,
    pub transfer: bool
}

/// Sign a transaction input with state entity shared wallet
pub fn cosign_tx_input(wallet: &mut Wallet, shared_wallet_id: &String, prepare_sign_msg: &PrepareSignTxMessage) -> Result<(String, Transaction)> {

    // message 1 - send back-up tx data for validation.
    let state_chain_id: String = requests::postb(&wallet.client_shim, &format!("prepare-sign/{}", shared_wallet_id), prepare_sign_msg)?;

    // Co-sign back-up tx
    // get sigHash and transform into message to be signed
    let txin = TxIn {
        previous_output: OutPoint {
            txid: sha256d::Hash::from_str(&prepare_sign_msg.input_txid).unwrap(),
            vout: prepare_sign_msg.input_vout
        },
        sequence: 0xFFFFFFFF,
        witness: Vec::new(),
        script_sig: bitcoin::Script::default(),
    };

    let tx = build_tx_b(
        &txin,
        &Address::from_str(&prepare_sign_msg.address).unwrap(),
        &Amount::from_sat(prepare_sign_msg.amount)
    ).unwrap();

    let mut tx_signed = tx.clone();
    let comp = SighashComponents::new(&tx);
    let sig_hash = comp.sighash_all(
        &tx.input[0],
        &Address::from_str(&prepare_sign_msg.spending_addr).unwrap().script_pubkey(),
        prepare_sign_msg.amount
    );

    let shared_wal = wallet.get_shared_wallet(&shared_wallet_id).expect("No shared wallet found for id");
    let address_derivation = shared_wal.addresses_derivation_map.get(&prepare_sign_msg.spending_addr).unwrap();
    let mk = &address_derivation.mk;

    // co-sign back up tranaction
    let signature = ecdsa::sign(
        &wallet.client_shim,
        BigInt::from_hex(&hex::encode(&sig_hash[..])),
        &mk,
        BigInt::from(0),
        BigInt::from(address_derivation.pos),
        &shared_wal.private_share.id,
    ).unwrap();

    let mut v = BigInt::to_vec(&signature.r);
    v.extend(BigInt::to_vec(&signature.s));

    let mut sig_vec = Signature::from_compact(&v[..])
        .unwrap()
        .serialize_der()
        .to_vec();
    sig_vec.push(01);

    let pk_vec = mk.public.q.get_element().serialize().to_vec();

    tx_signed.input[0].witness = vec![sig_vec, pk_vec];
    Ok((state_chain_id, tx_signed))
}

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
                        value: amount.as_sat()-DUSTLIMIT-FEE,
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

#[cfg(test)]
mod tests {
    use super::*;
    // use serde_json;

    use bitcoin::OutPoint;
    use bitcoin::blockdata::script::Script;
    use bitcoin::secp256k1::{Secp256k1, Message};
    use bitcoin::hashes::sha256d;

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
        // println!("{}", serde_json::to_string_pretty(&tx_0).unwrap());

        // Compute sighash
        let sighash = tx_0.signature_hash(0, &addr.script_pubkey(), amount.as_sat() as u32);
        // Makes signature.
        let msg = Message::from_slice(&sighash[..]).unwrap();
        let _signature = secp.sign(&msg, &priv_key.key).serialize_der().to_vec();

        let tx_k = build_tx_k(tx_0.input.get(0).unwrap(), &addr, &amount).unwrap();
        // println!("{}", serde_json::to_string_pretty(&tx_k).unwrap());

        let _tx_1 = build_tx_b(&tx_k.input.get(0).unwrap(), &addr, &amount).unwrap();
        // println!("{}", serde_json::to_string_pretty(&tx_1).unwrap());
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
