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
    // If there is no withdrawal fee there should be 1 output only
    if fee_withdraw.to_owned() == 0 {
        if tx.output.len() != 1 {
              return Err(SharedLibError::FormatError(format!(
                "Withdrawal fee is 0, expected withdrawal tx to have 1 output - withdrawal tx has {} outputs.",
            tx.output.len()
            )));
        }
        return Ok(())
    }

    let mut found = 0;
    let se_fee_script_pubkey = &tx.output[1].script_pubkey;
    
    for i in 0..fee_address.len(){
        let addr = &Address::from_str(&fee_address[i])?;
        let network = addr.network;
        match &Address::from_script(se_fee_script_pubkey, network) {
            Some(se_fee_addr) => {
                if &se_fee_addr == &addr {
                    // found a correct address
                    found = 1;
                }
            },
            None=> ()
        };
    }

    // didn't find a correct address
    if found == 0 {
        let fa: Vec<Address> = fee_address.into_iter().filter_map(|x| Address::from_str(*x).ok()).collect();
        //let fa_sp: Vec<bitcoin::blockdata::script::Script> = fa.into_iter().map(|x| x.script_pubkey()).collect();
        let se_fee_addr_bitcoin = &Address::from_script(se_fee_script_pubkey, Network::Bitcoin);
        let se_fee_addr_testnet = &Address::from_script(se_fee_script_pubkey, Network::Testnet);
        let se_fee_addr_regtest = &Address::from_script(se_fee_script_pubkey, Network::Regtest);
        return Err(SharedLibError::FormatError(format!(
            "Incorrect State Entity fee address. Expected one of {:?}, found bitcoin: {:?}, or testnet: {:?}, or regtest: {:?}", 
            &fa, &se_fee_addr_bitcoin, &se_fee_addr_testnet, &se_fee_addr_regtest)
        ));
    }

    if tx.output[1].value != fee_withdraw.to_owned() {
        return Err(SharedLibError::FormatError(format!(
            "Incorrect State Entity fee - expected {}, got {}",
            fee_withdraw,
            &tx.output[1].value
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

    let mut output = vec![TxOut {
                script_pubkey: rec_se_address.script_pubkey(),
                value: amount - fee - tx_fee,
    }];

    if fee > 0 {
        output.push(
            TxOut {
                script_pubkey: Address::from_str(&se_fee_info.address)?.script_pubkey(),
                value: fee,
            }
        );
    }

    let tx_0 = Transaction {
        version: 2,
        lock_time: 0,
        input: txins,
        output
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
    use uuid::Uuid;
    use crate::{structs::Protocol, state_chain::State};

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

    #[test]
    fn test_tx_withdraw_build() {
        let sc_infos = &vec![
            StateChainDataAPI {
                utxo: OutPoint {
                    txid: bitcoin::Txid::from_str("2834e7d92dbc48d7b1d99b47bd661ba3ef1d4bc9afc77976ee723c48aa879a03").unwrap(),
                    vout: 0,
                },
                amount: 10000,
                chain: vec![
                    State {
                        data: "026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e".to_string(),
                        next_state: None,
                    },
                ],
                locktime: 22345,
                confirmed: false,
            },
            StateChainDataAPI {
                utxo: OutPoint {
                    txid: bitcoin::Txid::from_str("9d119463ae82c44f7da202b6ad4b51450036257d1d220827f88e6ab92d248af4").unwrap(),
                    vout: 0,
                },
                amount: 10000,
                chain: vec![
                    State {
                        data: "022d7ea3d286541ed593e0158e315d73908646abcfa46aa56c12229a2910cce48c".to_string(),
                        next_state: None,
                    },
                ],
                locktime: 22345,
                confirmed: false,
            },
            StateChainDataAPI {
                utxo: OutPoint {
                    txid: bitcoin::Txid::from_str("fb5d9f5dace79eef8f048877b4fe0cbe6d399b28ba1869de22140617b1adc1aa").unwrap(),
                    vout: 0,
                },
                amount: 10000,
                chain: vec![
                    State {
                        data: "039afb8b85ba5c1b6664df7e68d4d79ea194e7022c76f0f9f3dadc3f94d8c79211".to_string(),
                        next_state: None,
                    },
                ],
                locktime: 22345,
                confirmed: false,
            },
        ];
        
        let rec_se_address = &bitcoin::Address::from_str(
            "bcrt1qc5ywjdp3xhxsfym5eaxqlr95ut62j8ym8mnf9n").unwrap();
        
        let se_fee_info = &StateEntityFeeInfoAPI {
            address: "bcrt1qjjwk2rk7nuxt6c79tsxthf5rpnky0sdhjr493x".to_string(),
            deposit: 40,
            withdraw: 40,
            interval: 100,
            initlock: 10000,
            wallet_version: "0.6.0".to_string(),
            wallet_message: "".to_string(),
        };

        let tx_fee = &141;

        let tx_withdraw_unsigned = tx_withdraw_build(
            sc_infos,
            rec_se_address,
            se_fee_info,
            tx_fee
        ).unwrap();
        // No withdrawal fee - two outputs
        assert_eq!(tx_withdraw_unsigned.output.len(), 2);
        assert_eq!(
            transaction_serialise(&tx_withdraw_unsigned), 
            "0200000003039a87aa483c72ee7679c7afc94b1defa31b66bd479bd9b1d748bc2dd9e734280000000000fffffffff48a242db96a8ef82708221d7d25360045514badb602a27d4fc482ae6394119d0000000000ffffffffaac1adb117061422de6918ba289b396dbe0cfeb47788048fef9ee7ac5d9f5dfb0000000000ffffffff025374000000000000160014c508e9343135cd049374cf4c0f8cb4e2f4a91c9b7800000000000000160014949d650ede9f0cbd63c55c0cbba6830cec47c1b700000000"
        );
    }

    #[test]
    fn test_tx_withdraw_build_zero_withdraw_fee() {
        let sc_infos = &vec![
            StateChainDataAPI {
                utxo: OutPoint {
                    txid: bitcoin::Txid::from_str("2834e7d92dbc48d7b1d99b47bd661ba3ef1d4bc9afc77976ee723c48aa879a03").unwrap(),
                    vout: 0,
                },
                amount: 10000,
                chain: vec![
                    State {
                        data: "026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e".to_string(),
                        next_state: None,
                    },
                ],
                locktime: 22345,
                confirmed: false,
            },
            StateChainDataAPI {
                utxo: OutPoint {
                    txid: bitcoin::Txid::from_str("9d119463ae82c44f7da202b6ad4b51450036257d1d220827f88e6ab92d248af4").unwrap(),
                    vout: 0,
                },
                amount: 10000,
                chain: vec![
                    State {
                        data: "022d7ea3d286541ed593e0158e315d73908646abcfa46aa56c12229a2910cce48c".to_string(),
                        next_state: None,
                    },
                ],
                locktime: 22345,
                confirmed: false,
            },
            StateChainDataAPI {
                utxo: OutPoint {
                    txid: bitcoin::Txid::from_str("fb5d9f5dace79eef8f048877b4fe0cbe6d399b28ba1869de22140617b1adc1aa").unwrap(),
                    vout: 0,
                },
                amount: 10000,
                chain: vec![
                    State {
                        data: "039afb8b85ba5c1b6664df7e68d4d79ea194e7022c76f0f9f3dadc3f94d8c79211".to_string(),
                        next_state: None,
                    },
                ],
                locktime: 22345,
                confirmed: false,
            },
        ];
        
        let rec_se_address = &bitcoin::Address::from_str(
            "bcrt1qc5ywjdp3xhxsfym5eaxqlr95ut62j8ym8mnf9n").unwrap();
        
        let se_fee_info = &StateEntityFeeInfoAPI {
            address: "bcrt1qjjwk2rk7nuxt6c79tsxthf5rpnky0sdhjr493x".to_string(),
            deposit: 40,
            withdraw: 0,
            interval: 100,
            initlock: 10000,
            wallet_version: "0.6.0".to_string(),
            wallet_message: "".to_string(),
        };

        let tx_fee = &0;

        let tx_withdraw_unsigned = tx_withdraw_build(
            sc_infos,
            rec_se_address,
            se_fee_info,
            tx_fee
        ).unwrap();
        // No withdrawal fee - one output only
        assert_eq!(tx_withdraw_unsigned.output.len(), 1);
        assert_eq!(
            transaction_serialise(&tx_withdraw_unsigned), 
            "0200000003039a87aa483c72ee7679c7afc94b1defa31b66bd479bd9b1d748bc2dd9e734280000000000fffffffff48a242db96a8ef82708221d7d25360045514badb602a27d4fc482ae6394119d0000000000ffffffffaac1adb117061422de6918ba289b396dbe0cfeb47788048fef9ee7ac5d9f5dfb0000000000ffffffff015875000000000000160014c508e9343135cd049374cf4c0f8cb4e2f4a91c9b00000000"
        );
    }

    const TX_WITHDRAW_UNSIGNED: &str = "020000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff02accc0e0000000000160014e8df018c7e326cc253faac7e46cdc51e68542c423075000000000000160014e8df018c7e326cc253faac7e46cdc51e68542c4200000000";
    const TX_WITHDRAW_UNSIGNED_ZERO_WITHDRAW_FEE: &str = "020000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0110cd0e0000000000160014e8df018c7e326cc253faac7e46cdc51e68542c4200000000";
    const TX_WITHDRAW_UNSIGNED_ZERO_WITHDRAW_FEE_TOO_MANY_OUTPUTS: &str = "020000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0210cd0e0000000000160014e8df018c7e326cc253faac7e46cdc51e68542c423075000000000000160014e8df018c7e326cc253faac7e46cdc51e68542c4200000000";
    
    #[test]
    fn test_tx_withdraw_verify() {
        let shared_key_ids = vec![Uuid::from_str("485a12a4-1de8-4da8-850b-e5e4c15fd56b").unwrap()];
        let fee_info = StateEntityFeeInfoAPI::example();        
        let public_key = PublicKey::from_slice(
            &[3,76,3,120,106,132,70,114,65,251,156,183,67,79,207,186,151,
                149,27,87,156,125,146,95,34,38,209,206,13,70,102,45,79,]
        ).unwrap();
        let proof_key = Some("02a95498bdde2c8c4078f01840b3bc8f4ae5bb1a90b880a621f50ce221bce3ddbe".to_string());
        let input_amounts = vec![100000];
        let input_addrs = vec![public_key];

        let tx_psm = PrepareSignTxMsg {
            shared_key_ids: shared_key_ids.clone(),
            protocol: Protocol::Withdraw,
            tx_hex: TX_WITHDRAW_UNSIGNED.to_string(),
            input_addrs,
            input_amounts,
            proof_key
        };

        let mut tx_psm_extra_input_addr = tx_psm.clone();
        tx_psm_extra_input_addr.input_addrs.push(public_key);

        let mut tx_psm_zero_fee = tx_psm.clone();
        tx_psm_zero_fee.tx_hex = TX_WITHDRAW_UNSIGNED_ZERO_WITHDRAW_FEE.to_string();
        
        let mut tx_psm_zero_fee_too_many_outputs = tx_psm.clone();
        tx_psm_zero_fee_too_many_outputs.tx_hex = TX_WITHDRAW_UNSIGNED_ZERO_WITHDRAW_FEE_TOO_MANY_OUTPUTS.to_string();

        //Ok
        let fee_withdraw = 30000;
        tx_withdraw_verify(&tx_psm, &[fee_info.address.as_str()], &fee_withdraw).unwrap();
        
        // Wrong number of inputs
        let expected_err = SharedLibError::FormatError(String::from(
                "Withdraw tx number of signing addresses != number of input amounts.",
            ));
        match tx_withdraw_verify(&tx_psm_extra_input_addr, &[fee_info.address.as_str()], &fee_withdraw) {
            Ok(_) => panic!("expected Err: {}", &expected_err),
            Err(err) => assert_eq!(&err, &expected_err)
        }
    
        // Wrong withdrawal fee
        let expected_err = SharedLibError::FormatError(String::from(
                "Incorrect State Entity fee - expected 30001, got 30000",
            ));
        match tx_withdraw_verify(&tx_psm, &[fee_info.address.as_str()], &(fee_withdraw+1)) {
            Ok(_) => panic!("expected Err: {}", &expected_err),
            Err(err) => assert_eq!(&err, &expected_err)
        }

        // Wrong fee address
        let expected_err = SharedLibError::FormatError(String::from(
                "Incorrect State Entity fee address.",
            ));
        match tx_withdraw_verify(&tx_psm, 
            &["bcrt1qjjwk2rk7nuxt6c79tsxthf5rpnky0sdhjr493x"], 
            &(fee_withdraw)
        ) {
            Ok(_) => panic!("expected Err: {}", &expected_err),
            Err(err) => assert_eq!(&err, &expected_err)
        }

        let mut tx_psm_deser = transaction_deserialise(&TX_WITHDRAW_UNSIGNED_ZERO_WITHDRAW_FEE.to_string()).unwrap();
        tx_psm_deser.output = vec![tx_psm_deser.output[0].clone()];


        // Zero withdrawal fee - ok
        tx_withdraw_verify(&tx_psm_zero_fee, &[fee_info.address.as_str()], &0).unwrap();

         // Zero withdrawal fee - too many outputs
        let expected_err = SharedLibError::FormatError(String::from(
                "Withdrawal fee is 0, expected withdrawal tx to have 1 output - withdrawal tx has 2 outputs.",
        ));
        match tx_withdraw_verify(&tx_psm_zero_fee_too_many_outputs, 
            &[fee_info.address.as_str()], 
            &0
        ) {
            Ok(_) => panic!("expected Err: {}", &expected_err),
            Err(err) => assert_eq!(&err, &expected_err)
        }
    }

}
