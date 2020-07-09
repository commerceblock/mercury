//! StateEntity Utils
//!
//! StateEntity protocol utilities. DB structs, info api calls and other miscellaneous functions

use super::super::{{Result,Config},
    storage::db};
extern crate shared_lib;
use shared_lib::{
    structs::*};

use crate::routes::util::{StateEntityStruct};
use crate::routes::transfer::finalize_batch;
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

#[post("/watch/status", format = "json")]
pub fn get_status(
    state: State<Config>,
) -> Result<Json<WatcherStatusAPI>> {

    let rpc_path = state.bitcoind;
    let rpc_path_parts: Vec<&str> = rpc_path.split('@').collect();
    if rpc_path_parts.len() != 2 {
        panic!("Invalid bitcoind RPC path")
    };

    let rpc_client = Arc::new(RPCClient::new(rpc_path_parts[0], rpc_path_parts[1]));

    let info = rpc_client.make_rpc_call("getblockchaininfo", &[], false).unwrap();
    let best_block_hash = info["bestblockhash"].as_str().unwrap();
    let blocks = info["blocks"].as_u64().unwrap();

//    let rpc_auth: Vec<&str> = rpc_path_parts[1].split(':').collect();
//    let rpc = Client::new(rpc_path_parts[0].to_string(),
//                          Auth::UserPass(rpc_auth[0].to_string(),
//                                         rpc_auth[1].to_string())).unwrap();
//    let best_block_hash = rpc.get_best_block_hash().to_string().unwrap();
//    blocks = rpc.get_block_count();

    Ok(Json(WatcherStatusAPI {
        blockhash: best_block_hash.to_string(),
        height: blocks,
        count: 142,
    }))
}

#[post("/watch/send", format = "json", data = "<master_tx_msg>")]
pub fn sendtx(
    state: State<Config>,
    master_tx_msg: Json<MasterTxMsg>,
) -> Result<Json<WatchTxConfirm>> {

    let tx: Transaction = encode::deserialize(&hex_to_vec(&master_tx_msg.hex.as_str()).unwrap()).unwrap();

    let tx_valid = true;
    let txindex = 0;

    let txid = tx.input[0].previous_output.txid.to_string();
    let uid = "".to_string();
    let nlocktime = tx.lock_time;

    let mut prev_tx: WatcherStruct =
            db::get(&state.db, &txid, &uid, &StateEntityStruct::WatcherStruct)?
                .ok_or(SEError::DBError(NoDataForID, txid.to_string()))?;

    if prev_tx.locktime < nlocktime {
        tx_valid = false;
    }

    txindex = prev_tx.index.clone() + 1;

    db::insert(
        &state.db,
        &txid,
        &uid,
        &StateEntityStruct::WatcherStruct,
        &WatcherStruct {
            tx: tx.clone(),
            index: txindex,
            locktime: nlocktime
        }
    )?;

    if tx_valid {
        info!("RECIEVED: UXTO: {}",txid.to_string());
        debug!("RECIEVED: UXTO: {}",txid.to_string());
    }

    Ok(Json(WatchTxConfirm {
        confirmed: tx_valid,
        index: txindex
    }))
}

#[post("/watch/query", format = "json", data = "<query_tx_msg>")]
pub fn querytx(
    state: State<Config>,
    query_tx_msg: Json<QueryTxMsg>,
) -> Result<Json<QueryTxReturn>> {
    Ok(Json(QueryTxReturn {
        latest: true,
        status: 10001
    }))
}
