//! StateEntity Utils
//!
//! StateEntity protocol utilities. DB structs, info api calls and other miscellaneous functions

use super::{{Result,Config},
    storage::db};
extern crate shared_lib;
use shared_lib::{
    structs::*};
use std::{thread, time};
use rocksdb::{Direction, IteratorMode};

use crate::error::{SEError,DBErrorType::NoDataForID};
use crate::rpc_client::*;
use crate::utils::*;

//use bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoin::{Transaction,
    hashes::sha256d};
use bitcoin::consensus::encode;

use rocket_contrib::json::Json;
use rocket::State;

use std::sync::{Arc};

pub fn watch_node(config: &Config) {

    let interval = time::Duration::from_millis(30000);

    let rpc_path = config.bitcoind;
    let rpc_path_parts: Vec<&str> = rpc_path.split('@').collect();
    if rpc_path_parts.len() != 2 {
        panic!("Invalid bitcoind RPC path")
    };

    let rpc_client = Arc::new(RPCClient::new(rpc_path_parts[0], rpc_path_parts[1]));

    loop {

        let info = rpc_client.make_rpc_call("getblockchaininfo", &[], false).unwrap();
        let best_block_hash = info["bestblockhash"].as_str().unwrap();
        let blocks = info["blocks"].as_u32().unwrap();

        // find valid backup transactions
        let mut iter = config.db.iterator(IteratorMode::Start); // Always iterates forward
        for (key, value) in iter {
            if value.locktime.to_u32() <= blocks {
                // TODO: check if confirmed, if it is then delete transaction, and continue

                let tx = value.tx;
                let tx_ser = "\"".to_string() + &encode::serialize_hex(tx) + "\"";
                let senttx = rpc_client.make_rpc_call("sendrawtransaction", &[&tx_ser], true).unwrap();
            } 
        }
    }
}
