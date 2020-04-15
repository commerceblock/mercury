//! state_entity
//!
//! State Entity implementation

use crate::storage::se_mock::{ StateChain, MockStorage };

/// State struct representing an active UTXO shared by state entity and Owner
#[allow(dead_code)]
pub struct State {
    id: u32,
    utxo: String,
    key: String,
    state_chain: StateChain
    // owner_auth:
}
/// State Entity main
pub struct StateEntity {
    /// storage
    pub storage: MockStorage
}


/// state entity interface
pub trait StateEntityInterface {
   /// statechain despoit
   fn deposit() -> String;
   /// statchain transfer
   fn transfer() -> String;
}


// Mock Owner stuff can be used for testing if needed.
use bitcoin::util;
use crate::util::generate_keypair;

/// public/private key pairs.
#[allow(dead_code)]
pub struct KeyPair {
    priv_key: util::key::PrivateKey,
    pub_key: util::key::PublicKey
}


impl KeyPair {
    /// generate random key pair
    pub fn new() -> Self {
        let key_pair = generate_keypair();
        KeyPair{ priv_key: key_pair.0, pub_key: key_pair.1 }
    }
}

/// Rpc implementation of Owner
#[allow(dead_code)]
pub struct MockOwner {
    /// Rpc client instance
    id: u32,
    /// Keys
    keys: Vec<KeyPair>
}

impl MockOwner {
    /// Init with single key
    pub fn new() -> Self {
        MockOwner{ id: 1, keys: vec![KeyPair::new()] }
    }
    /// generate new key and add to self.keys
    pub fn new_key(&mut self) {
        let key_pair = generate_keypair();
        self.keys.push(KeyPair{ priv_key: key_pair.0, pub_key: key_pair.1 })
    }
}

// use this to implement and test client side of protocol
impl StateEntityInterface for MockOwner {
    // deposit protocol
    fn deposit() -> String {
        return String::from("deposit")
    }
    // transfer protocol
    fn transfer() -> String {
        return String::from("transfer")
    }
}
