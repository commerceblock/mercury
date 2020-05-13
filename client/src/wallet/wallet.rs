//! Wallet
//!
//! Basic Bitcoin wallet functionality. Full key owned by this wallet.

use super::super::Result;
use crate::error::{ CError, WalletErrorType::SharedKeyNotFound};
use crate::mocks::mock_electrum::MockElectrum;
use crate::wallet::shared_key::SharedKey;
use crate::ClientShim;

use bitcoin::{ Network, PublicKey, PrivateKey };
use bitcoin::util::bip32::{ ExtendedPubKey, ExtendedPrivKey, ChildNumber };
use bitcoin::util::bip143::SighashComponents;
use bitcoin::secp256k1::{ All, Secp256k1, Message };
use curv::FE;
// use electrumx_client::{electrumx_client::ElectrumxClient, interface::Electrumx};
use uuid::Uuid;
use std::collections::HashMap;
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

#[derive(Debug, Copy, Clone)]
pub struct AddressDerivation {
    pub pos: u32,
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
}
impl AddressDerivation {
    pub fn new(pos: u32, private_key: PrivateKey, public_key: PublicKey) -> Self {
        AddressDerivation { pos, private_key, public_key }
    }
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
    pub electrumx_client: MockElectrum,
    pub client_shim: ClientShim,
    pub master_priv_key: ExtendedPrivKey,
    pub master_pub_key: ExtendedPubKey,
    pub last_derived_pos: u32,
    pub addresses_derivation_map: HashMap<String, AddressDerivation>,
    pub shared_keys: Vec<SharedKey> // vector of keys co-owned with state entities
}
impl Wallet {
    pub fn new(seed: &[u8], network: &String, client_shim: ClientShim) -> Wallet {
        let secp = Secp256k1::new();
        let master_priv_key = ExtendedPrivKey::new_master(network.parse::<Network>().unwrap(), seed).unwrap();
        let master_pub_key = ExtendedPubKey::from_private(&secp, &master_priv_key);
        Wallet {
            id: Uuid::new_v4().to_string(),
            network: network.to_string(),
            secp,
            electrumx_client: MockElectrum::new(),
            client_shim,
            master_priv_key,
            master_pub_key,
            last_derived_pos: 0,
            addresses_derivation_map: HashMap::new(),
            shared_keys: vec!()
        }
    }

    /// serialize wallet to json
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "id": self.id,
            "network": self.network,
            "master_priv_key": self.master_priv_key.to_string(),
            "master_pub_key": self.master_pub_key.to_string(),
            "last_derived_pos": self.last_derived_pos,
            "shared_keys": serde_json::to_string(&self.shared_keys).unwrap()
        })
    }

    /// load wallet from jon
    pub fn from_json(json: serde_json::Value, network: &String, client_shim: ClientShim) -> Result<Self> {
        let secp = Secp256k1::new();
        let mut master_priv_key = ExtendedPrivKey::from_str(json["master_priv_key"].as_str().unwrap()).unwrap();
        master_priv_key.network = network.parse::<Network>().unwrap();
        let mut master_pub_key = ExtendedPubKey::from_str(json["master_pub_key"].as_str().unwrap()).unwrap();
        master_pub_key.network = network.parse::<Network>().unwrap();

        let mut wallet = Wallet {
            id: json["id"].as_str().unwrap().to_string(),
            network: json["network"].as_str().unwrap().to_string(),
            secp,
            electrumx_client: MockElectrum::new(),
            client_shim,
            master_priv_key,
            master_pub_key,
            last_derived_pos: 0,
            addresses_derivation_map: HashMap::new(),
            shared_keys: vec!()
        };
        for _ in 0..json["last_derived_pos"].as_u64().unwrap() {
            wallet.get_new_bitcoin_address()?;
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
    pub fn load_from(filepath: &str, network: &String, client_shim: ClientShim) -> Result<Wallet> {
        let data = fs::read_to_string(filepath).expect("Unable to load wallet!");
        let serde_json_data = serde_json::from_str(&data).unwrap();
        let wallet: Wallet = Wallet::from_json(serde_json_data, network, client_shim)?;
        debug!("(wallet id: {}) Loaded wallet to memory", wallet.id);
        Ok(wallet)
    }
    pub fn load(network: &String, client_shim: ClientShim) -> Result<Wallet> {
        Ok(Wallet::load_from(WALLET_FILENAME, network, client_shim)?)
    }

    /// generate new address
    pub fn get_new_bitcoin_address(&mut self) -> Result<bitcoin::Address> {
        let new_ext_priv_key = self.derive_new_key()?;
        let new_ext_pub_key = ExtendedPubKey::from_private(&self.secp, &new_ext_priv_key);

        let address = self.to_p2wpkh_address(&new_ext_pub_key.public_key);
        self.last_derived_pos += 1;

        self.addresses_derivation_map
            .insert(address.to_string(),
                AddressDerivation::new(self.last_derived_pos, new_ext_priv_key.private_key, new_ext_pub_key.public_key));

        Ok(address)
    }

    pub fn get_new_state_entity_address(&mut self) -> Result<StateEntityAddress> {
        let new_ext_priv_key = self.derive_new_key().unwrap();
        let new_ext_pub_key = ExtendedPubKey::from_private(&self.secp, &new_ext_priv_key);
        let proof_key_addr = self.to_p2wpkh_address(&new_ext_pub_key.public_key);
        self.last_derived_pos += 1;
        self.addresses_derivation_map
            .insert(proof_key_addr.to_string(),
                AddressDerivation::new(self.last_derived_pos, new_ext_priv_key.private_key, new_ext_pub_key.public_key));
        Ok(StateEntityAddress{
            backup_addr: self.get_new_bitcoin_address()?.to_string(),
            proof_key: new_ext_pub_key.public_key
        })
    }

    /// Derive new child key from master extended key
    fn derive_new_key(&mut self) -> Result<ExtendedPrivKey> {
        match self.master_priv_key.ckd_priv(&self.secp, ChildNumber::from_hardened_idx(self.last_derived_pos).unwrap()) {
            Ok(res) => Ok(res),
            Err(e) => Err(CError::from(e))
        }
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
            let address_derivation = self
                .addresses_derivation_map
                .get(&address.to_string())
                .unwrap();
            let pk = address_derivation.public_key.key;
            let sk = address_derivation.private_key.key;

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
        Err(CError::WalletError(SharedKeyNotFound))
    }

    /// Get mutable reference to shared key by id. Return None if no shared key with given id.
    pub fn get_shared_key_mut(&mut self, id: &String) -> Result<&mut SharedKey> {
        for shared in &mut self.shared_keys {
            if shared.id == *id {
                return Ok(shared);
            }
        }
        Err(CError::WalletError(SharedKeyNotFound))
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

    fn get_all_addresses_balance(&self) -> Vec<GetBalanceResponse> {
        let response: Vec<GetBalanceResponse> = self
            .get_all_addresses()
            .into_iter()
            .map(|a| self.get_address_balance(&a))
            .collect();
        response
    }
    /// Return all addresses derived by this wallet.
    pub fn get_all_addresses(&self) -> Vec<bitcoin::Address> {
        let mut addrs = Vec::new();
        for (addr, _) in &self.addresses_derivation_map {
            addrs.push(bitcoin::Address::from_str(&addr).unwrap());
        }
        addrs
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
    /// Get address derivation information. Return None if address not derived by this wallet.
    pub fn get_address(&self, address: &String) -> Option<AddressDerivation> {
        match self.addresses_derivation_map.get(address) {
            Some(entry) => Some(*entry),
            None => None
        }
    }

    /// List unspent outputs for addresses derived by this wallet.
    pub fn list_unspent(&self) -> Vec<GetListUnspentResponse> {
        let response: Vec<GetListUnspentResponse> = self
            .get_all_addresses()
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
        Wallet::load_from(TEST_WALLET_FILENAME,&"regtest".to_string(),ClientShim::new("http://localhost:8000".to_string(), None)).unwrap();
    }

    #[test]
    fn test_to_and_from_json() {
        let mut wallet = gen_wallet();
        let addr1 = wallet.get_new_bitcoin_address().unwrap();
        let addr2 = wallet.get_new_bitcoin_address().unwrap();
        let wallet_json = wallet.to_json();
        let wallet_rebuilt = super::Wallet::from_json(wallet_json,&"regtest".to_string(),ClientShim::new("http://localhost:8000".to_string(), None)).unwrap();
        assert_eq!(wallet.id,wallet_rebuilt.id);
        assert_eq!(wallet.network,wallet_rebuilt.network);
        assert_eq!(wallet.master_priv_key.chain_code,wallet_rebuilt.master_priv_key.chain_code);
        assert_eq!(wallet.master_priv_key.private_key.to_bytes(),wallet_rebuilt.master_priv_key.private_key.to_bytes());
        assert_eq!(wallet.master_pub_key.chain_code,wallet_rebuilt.master_pub_key.chain_code);
        assert_eq!(wallet.master_pub_key.public_key,wallet_rebuilt.master_pub_key.public_key);
        assert_eq!(wallet.last_derived_pos,wallet_rebuilt.last_derived_pos);
        assert!(wallet_rebuilt.addresses_derivation_map.contains_key(&addr1.to_string()));
        assert!(wallet_rebuilt.addresses_derivation_map.contains_key(&addr2.to_string()));
    }

    #[test]
    fn test_basic_addr_generation() {
        let mut wallet = gen_wallet();
        let addr1 = wallet.get_new_bitcoin_address().unwrap();
        assert!(wallet.get_address(&addr1.to_string()).is_some());
        assert!(wallet.get_address(&String::from("test")).is_none());
        let _ = wallet.get_new_bitcoin_address();
        let _ = wallet.get_new_bitcoin_address();
        assert_eq!(wallet.get_all_addresses().len(),3);
    }

    #[test]
    fn test_tx_signing() {
        let expected_witness = vec!(
            vec!(48, 69, 2, 33, 0, 150, 253, 50, 55, 46, 20, 32, 126, 52, 91, 106, 70, 140, 77, 48, 63, 61, 120, 207, 38, 4, 9, 76, 213, 188, 236, 65, 29, 66, 167, 102, 172, 2, 32, 119, 56, 58, 56, 123, 138, 4, 59, 69, 218, 221, 81, 178, 173, 248, 8, 25, 133, 158, 109, 82, 1, 160, 89, 246, 61, 126, 152, 69, 134, 236, 116, 1),
             vec!(3, 117, 86, 76, 139, 78, 224, 113, 7, 64, 95, 108, 244, 182, 62, 233, 254, 158, 251, 233, 160, 11, 195, 122, 213, 124, 230, 51, 124, 162, 241, 219, 112)
        );

        let mut wallet = gen_wallet();
        let addr = wallet.get_new_bitcoin_address().unwrap();

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
        let _ = wallet.get_new_bitcoin_address();
        let _ = wallet.get_new_bitcoin_address();
        println!("balances: {:?}",wallet.get_all_addresses_balance());
        println!("list unspent: {:?}",wallet.list_unspent());
    }

}
