//! Wallet
//!
//! Basic Bitcoin wallet functionality. Full key owned by this wallet.

use crate::mocks::mock_electrum::MockElectrum;
use crate::wallet::shared_wallet::SharedWallet;
use crate::ClientShim;

use bitcoin::Network;
use bitcoin::util::bip32::{ ExtendedPubKey, ExtendedPrivKey, ChildNumber };
use bitcoin::util::key::{ PublicKey, PrivateKey };
use bitcoin::util::bip143::SighashComponents;
use bitcoin::secp256k1::{ All, Secp256k1, Message };

// use electrumx_client::{electrumx_client::ElectrumxClient, interface::Electrumx};
use uuid::Uuid;
use std::collections::HashMap;
use std::str::FromStr;

// TODO: move that to a config file and point to CommerceBlock's electrum server addresses
// const ELECTRUM_HOST: &str = "ec2-34-219-15-143.us-west-2.compute.amazonaws.com:60001";

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
    pub shared_wallets: Vec<SharedWallet> // vector of wallets co-owned with state entities
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
            shared_wallets: vec!()
        }
    }

    pub fn gen_shared_wallet(&mut self) -> &SharedWallet {
        self.shared_wallets.push(SharedWallet::new(&self.client_shim, &self.network));
        self.shared_wallets.last().unwrap()
    }

    // TODO: make serializable so wallet can be stored

    // pub fn save_to(&self, filepath: &str) {
    //     let wallet_json = serde_json::to_string(self).unwrap();
    //     fs::write(filepath, wallet_json).expect("Unable to save wallet!");
    //     debug!("(wallet id: {}) Saved wallet to disk", self.id);
    // }
    // pub fn save(&self) {
    //     self.save_to(WALLET_FILENAME)
    // }
    // pub fn load_from(filepath: &str) -> SharedWallet {
    //     let data = fs::read_to_string(filepath).expect("Unable to load wallet!");
    //     let wallet: SharedWallet = serde_json::from_str(&data).unwrap();
    //     debug!("(wallet id: {}) Loaded wallet to memory", wallet.id);
    //     wallet
    // }
    // pub fn load() -> SharedWallet {
    //     SharedWallet::load_from(WALLET_FILENAME)
    // }

    /// generate new address
    pub fn get_new_bitcoin_address(&mut self) -> bitcoin::Address {
        let new_ext_priv_key = self.derive_new_key().unwrap();
        let new_ext_pub_key = ExtendedPubKey::from_private(&self.secp, &new_ext_priv_key);

        let address = self.to_p2wpkh_address(&new_ext_pub_key.public_key);
        self.last_derived_pos += 1;

        self.addresses_derivation_map
            .insert(address.to_string(),
                AddressDerivation::new(self.last_derived_pos, new_ext_priv_key.private_key, new_ext_pub_key.public_key));

        address
    }

    /// Derive new child key from master extended key
    fn derive_new_key(&mut self) -> Result<ExtendedPrivKey, bitcoin::util::bip32::Error> {
        self.master_priv_key.ckd_priv(&self.secp, ChildNumber::from_hardened_idx(self.last_derived_pos).unwrap())
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

    /// return alance of address
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

    fn get_bitcoin_network(&self) -> Network {
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
    use crate::state_entity::util::*;
    use bitcoin::{ Amount, TxIn, OutPoint, Script };
    use bitcoin::hashes::sha256d;

    fn gen_wallet() -> Wallet {
        Wallet::new(
            &[0xcd; 32],
            &"regtest".to_string(),
            ClientShim::new("http://localhost:8000".to_string(), None)
        )
    }
    #[test]
    fn test_basic_addr_generation() {
        let mut wallet = gen_wallet();
        let addr1 = wallet.get_new_bitcoin_address();
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
        let addr = wallet.get_new_bitcoin_address();

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
