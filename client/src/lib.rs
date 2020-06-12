extern crate centipede;
extern crate config;
extern crate curv;
extern crate kms;
extern crate multi_party_ecdsa;
extern crate reqwest;
extern crate zk_paillier;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate log;

#[macro_use]
extern crate failure;

extern crate bitcoin;
extern crate electrumx_client;
extern crate hex;
extern crate itertools;
extern crate uuid;

pub mod ecdsa;
pub mod wallet;
pub mod schnorr;
pub mod state_entity;
pub mod error;
pub mod electrum;
pub mod bitcoin_core;

mod utilities;

type Result<T> = std::result::Result<T, error::CError>;

#[derive(Debug, Clone)]
pub struct ClientShim {
    pub client: reqwest::Client,
    pub auth_token: Option<String>,
    pub endpoint: String,
}

impl ClientShim {
    pub fn new(endpoint: String, auth_token: Option<String>) -> ClientShim {
        let client = reqwest::Client::new();
        ClientShim {
            client,
            auth_token,
            endpoint,
        }
    }
}
