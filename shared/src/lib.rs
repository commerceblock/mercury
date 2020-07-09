//
extern crate hex;
extern crate bitcoin;
extern crate bitcoin_hashes;
extern crate kms;
extern crate rocket;
extern crate rocket_contrib;
extern crate rocksdb;
extern crate uuid;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate log;

pub mod mocks;

extern crate itertools;

extern crate reqwest;
extern crate base64;
extern crate merkletree;
extern crate arrayvec;
extern crate chrono;

#[macro_use]
extern crate crypto;

extern crate is_odd;

pub mod error;
pub mod state_chain;
pub mod structs;
pub mod mainstay;
pub mod commitment;
pub mod util;

type Result<T> = std::result::Result<T, error::SharedLibError>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Root {
    pub id: u32,
    pub value: Option<[u8;32]>
}
