//
extern crate hex;
extern crate bitcoin;
extern crate kms;
extern crate rocket;
extern crate rocket_contrib;
extern crate rocksdb;
extern crate uuid;
extern crate chrono;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

pub mod mocks;
pub mod error;
pub mod state_chain;
pub mod structs;
pub mod commitment;
pub mod util;

type Result<T> = std::result::Result<T, error::SharedLibError>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Root {
    pub id: u32,
    pub value: Option<[u8;32]>
}
