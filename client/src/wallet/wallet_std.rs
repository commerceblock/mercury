//! Wallet
//!
//! Basic Bitcoin wallet functionality. Full key owned by this wallet.

use bitcoin::Network;
use bitcoin::util::bip32::{ ExtendedPubKey, ExtendedPrivKey, ChildNumber };
use bitcoin::util::key::{ PublicKey, PrivateKey };
use bitcoin::util::bip143::SighashComponents;
use bitcoin::secp256k1::{ All, Secp256k1, Message };
use electrumx_client::{electrumx_client::ElectrumxClient, interface::Electrumx};
use uuid::Uuid;

use std::collections::HashMap;
use std::str::FromStr;

// TODO: move that to a config file and double check electrum server addresses
const ELECTRUM_HOST: &str = "ec2-34-219-15-143.us-west-2.compute.amazonaws.com:60001";
//const ELECTRUM_HOST: &str = "testnetnode.arihanc.com:51001";
const WALLET_FILENAME: &str = "wallet/wallet.data";
const BACKUP_FILENAME: &str = "wallet/backup.data";

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

/// standard Wallet - fully owned private keys
pub struct WalletStd {
    pub id: String,
    pub network: Network,
    secp: Secp256k1<All>,
    pub master_priv_key: ExtendedPrivKey,
    pub master_pub_key: ExtendedPubKey,
    pub last_derived_pos: u32,
    pub addresses_derivation_map: HashMap<String, AddressDerivation>,
}
impl WalletStd {
    pub fn new(seed: &[u8], network: Network) -> WalletStd {
        let id = Uuid::new_v4().to_string();
        let secp = Secp256k1::new();
        let master_priv_key = ExtendedPrivKey::new_master(network, seed).unwrap();
        let master_pub_key = ExtendedPubKey::from_private(&secp, &master_priv_key);
        let last_derived_pos = 0;
        let addresses_derivation_map = HashMap::new();
        WalletStd {
            id,
            network,
            secp,
            master_priv_key,
            master_pub_key,
            last_derived_pos,
            addresses_derivation_map,
        }
    }

    /// generate new address
    pub fn get_new_bitcoin_address(&mut self) -> bitcoin::Address {
        let new_ext_priv_key = self.derive_new_key().unwrap();
        let new_ext_pub_key = ExtendedPubKey::from_private(&self.secp, &new_ext_priv_key);

        let address = self.to_bitcoin_address(&new_ext_pub_key.public_key);
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
                    self.network).script_pubkey(),
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

    fn get_address_balance(address: &bitcoin::Address) -> GetBalanceResponse {
        let mut client = ElectrumxClient::new(ELECTRUM_HOST).unwrap();

        let resp = client.get_balance(&address.to_string()).unwrap();

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
            .map(|a| Self::get_address_balance(&a))
            .collect();

        response
    }

    // return all addresses derived by thi wallet
    pub fn get_all_addresses(&self) -> Vec<bitcoin::Address> {
        let mut addrs = Vec::new();
        for (addr, _) in &self.addresses_derivation_map {
            addrs.push(bitcoin::Address::from_str(&addr).unwrap());
        }
        addrs
    }
    // check if address was derived by this wallet
    pub fn get_address(&self, address: &String) -> Option<AddressDerivation> {
        match self.addresses_derivation_map.get(address) {
            Some(entry) => Some(*entry),
            None => None
        }
    }

    pub fn to_bitcoin_address(&self, pub_key: &PublicKey) -> bitcoin::Address {
        bitcoin::Address::p2wpkh(
            &to_bitcoin_public_key(pub_key.key),
            self.network
        )
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

    #[test]
    fn test_basic_addr_generation() {
        let mut wallet = WalletStd::new(&[0xcd; 32], NETWORK);
        let addr1 = wallet.get_new_bitcoin_address();
        assert!(wallet.get_address(&addr1.to_string()).is_some());
        assert!(wallet.get_address(&String::from("test")).is_none());
        let _ = wallet.get_new_bitcoin_address();
        assert_eq!(wallet.get_all_addresses().len(),2);
    }

    #[test]
    fn test_tx_signing() {
        let expected_witness = vec!(
            vec!(48, 68, 2, 32, 85, 82, 16, 117, 122, 82, 141, 162, 187, 160, 80, 104, 77, 172, 4, 68, 34, 194, 73, 33, 162, 160, 106, 185, 248, 73, 185, 63, 78, 104, 219, 196, 2, 32, 16, 187, 211, 131, 57, 148, 236, 70, 173, 88, 40, 248, 129, 239, 188, 123, 43, 8, 232, 251, 176, 134, 167, 188, 186, 191, 193, 123, 206, 37, 135, 26, 1),
             vec!(3, 117, 86, 76, 139, 78, 224, 113, 7, 64, 95, 108, 244, 182, 62, 233, 254, 158, 251, 233, 160, 11, 195, 122, 213, 124, 230, 51, 124, 162, 241, 219, 112)
        );

        let mut wallet = WalletStd::new(&[0xcd; 32], NETWORK);
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
}
