//! Wallet
//!
//! Basic Bitcoin wallet functionality. Full key owned by this wallet.

use super::super::Result;
use super::key_paths::{ KeyPathWithAddresses, KeyPath};
use crate::error::{ CError, WalletErrorType};
use crate::mocks::mock_electrum::MockElectrum;
use crate::wallet::shared_key::SharedKey;
use crate::ClientShim;

use bitcoin::{ Network, PublicKey };
use bitcoin::util::bip32::{ ExtendedPrivKey, ChildNumber };
use bitcoin::util::bip143::SighashComponents;
use bitcoin::secp256k1::{ All, Secp256k1, Message };
use curv::FE;
// use electrumx_client::{electrumx_client::ElectrumxClient, interface::Electrumx};
use uuid::Uuid;
use std::str::FromStr;
use serde_json::json;
use std::fs;

const WALLET_FILENAME: &str = "wallet/wallet.data";

#[derive(Debug, Deserialize, Clone)]
pub struct GetBalanceResponse {
    pub address: String,
    pub confirmed: u64,
    pub unconfirmed: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GetListUnspentResponse {
    pub height: usize,
    pub tx_hash: String,
    pub tx_pos: usize,
    pub value: usize,
    pub address: String,
}

#[derive(Debug, Deserialize)]
pub struct GetWalletBalanceResponse {
    pub confirmed: u64,
    pub unconfirmed: u64,
}


/// Address generated for State Entity transfer protocol
#[derive(Deserialize, Debug)]
pub struct StateEntityAddress {
    pub backup_addr: String,
    pub proof_key: PublicKey,
}

/// Standard Bitcoin Wallet
pub struct Wallet {
    pub id: String,
    pub network: String,
    secp: Secp256k1<All>,
    // pub electrumx_client: ElectrumxClient,
    electrumx_client: MockElectrum,
    pub client_shim: ClientShim,

    pub master_priv_key: ExtendedPrivKey,
    pub keys: KeyPathWithAddresses, // Keys for general usage
    pub se_backup_keys: KeyPathWithAddresses, // keys for use in State Entity back up transactions
    pub se_proof_keys: KeyPath, // for use as State Entity proof keys

    pub shared_keys: Vec<SharedKey> // vector of keys co-owned with state entities
}
impl Wallet {
    pub fn new(seed: &[u8], network: &String, client_shim: ClientShim) -> Wallet {
        let secp = Secp256k1::new();
        let master_priv_key = ExtendedPrivKey::new_master(network.parse::<Network>().unwrap(), seed).unwrap();

        let keys_master_ext_key = master_priv_key.ckd_priv(&secp, ChildNumber::from_hardened_idx(0).unwrap()).unwrap();
        let keys = KeyPathWithAddresses::new(keys_master_ext_key);

        let se_backup_keys_master_ext_key = master_priv_key.ckd_priv(&secp, ChildNumber::from_hardened_idx(1).unwrap()).unwrap();
        let se_backup_keys = KeyPathWithAddresses::new(se_backup_keys_master_ext_key);

        let se_proof_keys_master_ext_key = master_priv_key.ckd_priv(&secp, ChildNumber::from_hardened_idx(2).unwrap()).unwrap();
        let se_proof_keys = KeyPath::new(se_proof_keys_master_ext_key);

        Wallet {
            id: Uuid::new_v4().to_string(),
            network: network.to_string(),
            secp,
            electrumx_client: MockElectrum::new(),
            client_shim,
            master_priv_key,
            keys,
            se_backup_keys,
            se_proof_keys,
            shared_keys: vec!()
        }
    }

    /// serialize wallet to json
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "id": self.id,
            "network": self.network,
            "master_priv_key": self.master_priv_key.to_string(),
            "keys_pos": self.keys.last_derived_pos,
            "se_backup_keys_pos": self.se_backup_keys.last_derived_pos,
            "se_proof_keys_pos": self.se_proof_keys.last_derived_pos,
            "shared_keys": serde_json::to_string(&self.shared_keys).unwrap()
        })
    }

    /// load wallet from jon
    pub fn from_json(json: serde_json::Value, client_shim: ClientShim) -> Result<Self> {
        let secp = Secp256k1::new();
        let network = json["network"].as_str().unwrap().to_string();

        // master extended keys
        let mut master_priv_key = ExtendedPrivKey::from_str(json["master_priv_key"].as_str().unwrap()).unwrap();
        master_priv_key.network = network.parse::<Network>().unwrap();

        // keys
        let mut keys_master_ext_key = master_priv_key.ckd_priv(&secp, ChildNumber::from_hardened_idx(0).unwrap()).unwrap();
        keys_master_ext_key.network = network.parse::<Network>().unwrap();
        let keys = KeyPathWithAddresses::new(keys_master_ext_key);

        // se_backup_keys
        let mut se_backup_keys_master_ext_key = master_priv_key.ckd_priv(&secp, ChildNumber::from_hardened_idx(1).unwrap()).unwrap();
        se_backup_keys_master_ext_key.network = network.parse::<Network>().unwrap();
        let se_backup_keys = KeyPathWithAddresses::new(se_backup_keys_master_ext_key);

        // se_proof_keys
        let mut se_proof_keys_master_ext_key = master_priv_key.ckd_priv(&secp, ChildNumber::from_hardened_idx(2).unwrap()).unwrap();
        se_proof_keys_master_ext_key.network = network.parse::<Network>().unwrap();
        let se_proof_keys = KeyPath::new(se_proof_keys_master_ext_key);


        let mut wallet = Wallet {
            id: json["id"].as_str().unwrap().to_string(),
            network: network,
            secp,
            electrumx_client: MockElectrum::new(),
            client_shim,
            master_priv_key,
            keys: keys,
            se_backup_keys,
            se_proof_keys,
            shared_keys: vec!()
        };

        // re-derive keys which have been previously derived
        for _ in 0..json["keys_pos"].as_u64().unwrap() {
            wallet.keys.get_new_bitcoin_address()?;
        }
        for _ in 0..json["se_backup_keys_pos"].as_u64().unwrap() {
            wallet.se_backup_keys.get_new_bitcoin_address()?;
        }
        for _ in 0..json["se_proof_keys_pos"].as_u64().unwrap() {
            wallet.se_proof_keys.get_new_key()?;
        }

        let shared_keys_str = &json["shared_keys"].as_str().unwrap();
        if shared_keys_str.len() != 2 { // is not empty
            let shared_keys:Vec<SharedKey> = serde_json::from_str(shared_keys_str).unwrap();
            wallet.shared_keys = shared_keys;
        }

        debug!("(wallet id: {}) Loaded wallet to memory", wallet.id);
        Ok(wallet)
    }

    /// save to disk
    pub fn save_to(&self, filepath: &str) {
        let wallet_json = self.to_json().to_string();
        fs::write(filepath, wallet_json).expect("Unable to save wallet!");
        debug!("(wallet id: {}) Saved wallet to disk", self.id);
    }
    pub fn save(&self) {
        self.save_to(WALLET_FILENAME)
    }

    /// load wallet from disk
    pub fn load_from(filepath: &str, client_shim: ClientShim) -> Result<Wallet> {
        let data = fs::read_to_string(filepath).expect("Unable to load wallet!");
        let serde_json_data = serde_json::from_str(&data).unwrap();
        let wallet: Wallet = Wallet::from_json(serde_json_data, client_shim)?;
        debug!("(wallet id: {}) Loaded wallet to memory", wallet.id);
        Ok(wallet)
    }
    pub fn load(client_shim: ClientShim) -> Result<Wallet> {
        Ok(Wallet::load_from(WALLET_FILENAME, client_shim)?)
    }

    pub fn get_new_state_entity_address(&mut self) -> Result<StateEntityAddress> {
        let backup_addr = self.se_backup_keys.get_new_bitcoin_address()?;
        let proof_key = self.se_proof_keys.get_new_key()?;
        Ok(StateEntityAddress{
            backup_addr: backup_addr.to_string(),
            proof_key
        })
    }

    /// Sign inputs with given addresses derived by this wallet. input_indices, addresses and amoumts lists
    /// must be in order of appearance in TxIn[] list
    pub fn sign_tx(
        &mut self,
        transaction: &bitcoin::Transaction,
        input_indices: Vec<usize>,
        addresses: Vec<bitcoin::Address>,
        amounts: Vec<bitcoin::Amount>
    ) -> bitcoin::Transaction {

        let mut signed_transaction = transaction.clone();
        for (iter, input_index) in input_indices.iter().enumerate() {

            // get key corresponding to address
            let address = addresses.get(iter).unwrap();
            let key_derivation = self.keys
                .get_address_derivation(&address.to_string())
                .ok_or(CError::WalletError(WalletErrorType::KeyNotFound))
                .unwrap();
            let pk = key_derivation.public_key.unwrap().key;
            let sk = key_derivation.private_key.key;

            let comp = SighashComponents::new(&transaction);
            let sig_hash = comp.sighash_all(
                &transaction.input[*input_index],
                &bitcoin::Address::p2pkh(
                    &to_bitcoin_public_key(pk),
                    self.get_bitcoin_network()).script_pubkey(),
                amounts.get(iter).unwrap().as_sat()
            );

            let msg = Message::from_slice(&sig_hash).unwrap();
            let signature = self.secp.sign(&msg, &sk).serialize_der();

            let mut with_hashtype = signature.to_vec();
            with_hashtype.push(1);
            signed_transaction.input[*input_index].witness.clear();
            signed_transaction.input[*input_index].witness.push(with_hashtype);
            signed_transaction.input[*input_index].witness.push(pk.serialize().to_vec());
        }
        return signed_transaction
    }

    /// create new 2P-ECDSA key with state entity
    pub fn gen_shared_key(&mut self, id: &String) -> Result<&SharedKey> {
        let shared_key = SharedKey::new(id, &self.client_shim)?;
        self.shared_keys.push(shared_key);
        Ok(self.shared_keys.last().unwrap())
    }

    /// create new 2P-ECDSA key with predeinfed private key
    pub fn gen_shared_key_fixed_secret_key(&mut self, id: &String, secret_key: &FE) -> Result<()> {
        self.shared_keys.push(
            SharedKey::new_fixed_secret_key(id, &self.client_shim, secret_key)?);
        Ok(())
    }

    /// Get shared key by id. Return None if no shared key with given id.
    pub fn get_shared_key(&self, id: &String) -> Result<&SharedKey> {
        for shared in &self.shared_keys {
            if shared.id == *id {
                return Ok(shared);
            }
        }
        Err(CError::WalletError(WalletErrorType::SharedKeyNotFound))
    }

    /// Get mutable reference to shared key by id. Return None if no shared key with given id.
    pub fn get_shared_key_mut(&mut self, id: &String) -> Result<&mut SharedKey> {
        for shared in &mut self.shared_keys {
            if shared.id == *id {
                return Ok(shared);
            }
        }
        Err(CError::WalletError(WalletErrorType::SharedKeyNotFound))
    }

    /// return balance of address
    fn get_address_balance(&self, address: &bitcoin::Address) -> GetBalanceResponse {
        let resp = self.electrumx_client.get_balance(&address.to_string()).unwrap();
        GetBalanceResponse {
            confirmed: resp.confirmed,
            unconfirmed: resp.unconfirmed,
            address: address.to_string(),
        }
    }

    /// return list of all addresses derived from keys in wallet
    fn get_all_wallet_addresses(&self) -> Vec<bitcoin::Address> {
        let mut addresses = self.keys.get_all_addresses();
        addresses.append(&mut self.se_backup_keys.get_all_addresses());
        addresses
    }

    fn get_all_addresses_balance(&self) -> Vec<GetBalanceResponse> {
        let response: Vec<GetBalanceResponse> = self
            .get_all_wallet_addresses()
            .into_iter()
            .map(|a| self.get_address_balance(&a))
            .collect();
        response
    }

    /// Return total balance of addresses in wallet.
    pub fn get_balance(&mut self) -> GetWalletBalanceResponse {
        let mut aggregated_balance = GetWalletBalanceResponse {
            confirmed: 0,
            unconfirmed: 0,
        };
        for b in self.get_all_addresses_balance() {
            aggregated_balance.unconfirmed += b.unconfirmed;
            aggregated_balance.confirmed += b.confirmed;
        }
        aggregated_balance
    }


    /// List unspent outputs for addresses derived by this wallet.
    pub fn list_unspent(&self) -> Vec<GetListUnspentResponse> {
        let response: Vec<GetListUnspentResponse> = self
            .get_all_wallet_addresses()
            .into_iter()
            .map(|a| self.list_unspent_for_addresss(a.to_string()))
            .flatten()
            .collect();
        response
    }

    /* PRIVATE */
    fn list_unspent_for_addresss(&self, address: String) -> Vec<GetListUnspentResponse> {
        let resp = self.electrumx_client.get_list_unspent(&address).unwrap();
        resp.into_iter()
            .map(|u| GetListUnspentResponse {
                value: u.value,
                height: u.height,
                tx_hash: u.tx_hash,
                tx_pos: u.tx_pos,
                address: address.clone(),
            })
            .collect()
    }

    pub fn to_p2wpkh_address(&self, pub_key: &PublicKey) -> bitcoin::Address {
        bitcoin::Address::p2wpkh(
            &to_bitcoin_public_key(pub_key.key),
            self.get_bitcoin_network()
        )
    }

    pub fn get_bitcoin_network(&self) -> Network {
        self.network.parse::<Network>().unwrap()
    }
}

// type conversion
pub fn to_bitcoin_public_key(pk: curv::PK) -> bitcoin::util::key::PublicKey {
    bitcoin::util::key::PublicKey {
        compressed: true,
        key: pk
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    extern crate shared_lib;
    use shared_lib::util::{build_tx_0,RBF};
    use bitcoin::{ Amount, TxIn, OutPoint, Script };
    use bitcoin::hashes::sha256d;

    const TEST_WALLET_FILENAME: &str = "test-assets/wallet.data";

    fn gen_wallet() -> Wallet {
        Wallet::new(
            &[0xcd; 32],
            &"regtest".to_string(),
            ClientShim::new("http://localhost:8000".to_string(), None)
        )
    }

    #[test]
    fn load_wallet_test() {
        Wallet::load_from(TEST_WALLET_FILENAME,ClientShim::new("http://localhost:8000".to_string(), None)).unwrap();
    }

    #[test]
    fn test_to_and_from_json() {
        let mut wallet = gen_wallet();

        let addr1 = wallet.keys.get_new_bitcoin_address().unwrap();
        let addr2 = wallet.keys.get_new_bitcoin_address().unwrap();
        let backup_addr1 = wallet.se_backup_keys.get_new_bitcoin_address().unwrap();
        let backup_addr2 = wallet.se_backup_keys.get_new_bitcoin_address().unwrap();
        let proof_key1 = wallet.se_proof_keys.get_new_key().unwrap();
        let proof_key2 = wallet.se_proof_keys.get_new_key().unwrap();


        let wallet_json = wallet.to_json();
        let wallet_rebuilt = super::Wallet::from_json(wallet_json,ClientShim::new("http://localhost:8000".to_string(), None)).unwrap();

        assert_eq!(wallet.id,wallet_rebuilt.id);
        assert_eq!(wallet.network,wallet_rebuilt.network);
        assert_eq!(wallet.master_priv_key.chain_code,wallet_rebuilt.master_priv_key.chain_code);
        assert_eq!(wallet.master_priv_key.private_key.to_bytes(),wallet_rebuilt.master_priv_key.private_key.to_bytes());

        assert_eq!(wallet.keys.ext_priv_key.private_key.to_bytes(),wallet_rebuilt.keys.ext_priv_key.private_key.to_bytes());
        assert_eq!(wallet.keys.last_derived_pos,wallet_rebuilt.keys.last_derived_pos);
        assert!(wallet_rebuilt.keys.addresses_derivation_map.contains_key(&addr1.to_string()));
        assert!(wallet_rebuilt.keys.addresses_derivation_map.contains_key(&addr2.to_string()));

        assert_eq!(wallet.se_backup_keys.ext_priv_key.private_key.to_bytes(),wallet_rebuilt.se_backup_keys.ext_priv_key.private_key.to_bytes());
        assert_eq!(wallet.se_backup_keys.last_derived_pos,wallet_rebuilt.se_backup_keys.last_derived_pos);
        assert!(wallet_rebuilt.se_backup_keys.addresses_derivation_map.contains_key(&backup_addr1.to_string()));
        assert!(wallet_rebuilt.se_backup_keys.addresses_derivation_map.contains_key(&backup_addr2.to_string()));

        assert_eq!(wallet.se_proof_keys.ext_priv_key.private_key.to_bytes(),wallet_rebuilt.se_proof_keys.ext_priv_key.private_key.to_bytes());
        assert_eq!(wallet.se_proof_keys.last_derived_pos,wallet_rebuilt.se_proof_keys.last_derived_pos);
        assert!(wallet_rebuilt.se_proof_keys.keys_derivation_map.contains_key(&proof_key1));
        assert!(wallet_rebuilt.se_proof_keys.keys_derivation_map.contains_key(&proof_key2));

    }

    #[test]
    fn test_tx_signing() {
        let expected_witness = vec!(
            vec!(48, 69, 2, 33, 0, 160, 126, 206, 105, 176, 150, 236, 242, 189, 105, 206, 12, 40, 22, 147, 118, 191, 134, 251, 249, 25, 124, 148, 137, 94, 95, 100, 220, 119, 61, 255, 135, 2, 32, 56, 190, 214, 206, 17, 200, 58, 104, 6, 175, 255, 47, 99, 37, 199, 202, 207, 132, 20, 41, 129, 137, 130, 169, 206, 6, 78, 88, 54, 61, 150, 136, 1),
             vec!(2, 145, 240, 85, 194, 87, 237, 58, 108, 126, 70, 191, 113, 117, 144, 204, 110, 61, 193, 180, 151, 116, 239, 66, 61, 192, 114, 7, 52, 117, 95, 213, 9)
        );

        let mut wallet = gen_wallet();
        let addr = wallet.keys.get_new_bitcoin_address().unwrap();

        let inputs =  vec![
            TxIn {
                previous_output: OutPoint {
                    txid: sha256d::Hash::from_str(&String::from("e0a97cb38e7e73617ef75a57eaf2841eb06833407c0eae08029bd04ea7e6115a")).unwrap(),
                    vout: 1 },
                sequence: RBF,
                witness: Vec::new(),
                script_sig: Script::new(),
            }
        ];
        let amount = Amount::ONE_BTC;

        let tx = build_tx_0(&inputs, &addr, &amount).unwrap();
        let signed_tx  = wallet.sign_tx(&tx, vec!(0), vec!(addr), vec!(amount));
        let witness = &signed_tx.input.get(0).unwrap().witness;

        assert_eq!(hex::encode(witness.get(0).unwrap()), hex::encode(expected_witness.get(0).unwrap()));
        assert_eq!(hex::encode(witness.get(1).unwrap()), hex::encode(expected_witness.get(1).unwrap()));
    }

    #[test]
    fn test_mocks() {
        let mut wallet = gen_wallet();
        let _ = wallet.keys.get_new_bitcoin_address();
        let _ = wallet.keys.get_new_bitcoin_address();
        println!("balances: {:?}",wallet.get_all_addresses_balance());
        println!("list unspent: {:?}",wallet.list_unspent());
    }
}
