#![allow(unused_parens)]
#![recursion_limit = "128"]
#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;
extern crate chrono;
extern crate config;
extern crate curv;
extern crate kms;
extern crate multi_party_ecdsa;
extern crate uuid;
extern crate zk_paillier;
#[macro_use]
extern crate failure;

extern crate error_chain;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate log;

#[cfg(test)]
extern crate floating_duration;

extern crate crypto;
extern crate jsonwebtoken as jwt;
extern crate rusoto_dynamodb;
extern crate serde_dynamodb;

extern crate hex;
extern crate shared_lib;
use shared_lib::mainstay;

#[cfg(test)]
#[macro_use]
extern crate serial_test;

pub mod error;
pub mod protocol;
pub mod server;
pub mod storage;
pub mod tests;

use rocket_contrib::databases::r2d2_postgres::{PostgresConnectionManager, TlsMode};
use rocket_contrib::databases::r2d2;


type Result<T> = std::result::Result<T, error::SEError>;
use rocket_contrib::databases::postgres;

#[database("postgres_w")]
pub struct DatabaseW(postgres::Connection);
#[database("postgres_r")]
pub struct DatabaseR(postgres::Connection);

struct Database {
    pub db_connection: fn()->r2d2::PooledConnection<PostgresConnectionManager>
}

pub struct StateChainEntity {
    pub electrum_server: String,
    pub network: String,
    pub testing_mode: bool,  // set for testing mode
    pub fee_address: String, // receive address for fee payments
    pub fee_deposit: u64,    // satoshis
    pub fee_withdraw: u64,   // satoshis
    pub block_time: u64,
    pub batch_lifetime: u64,
    pub punishment_duration: u64,
    pub mainstay_config: Option<mainstay::Config>,
    pub smt_db_loc: String,
    pub database: Database
}


