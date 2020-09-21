pub use super::Result;
extern crate shared_lib;
use crate::Database;
use crate::PGDatabase;
use crate::config::Config;

use std::{thread, time};

use bitcoincore_rpc::{Auth, Client, RpcApi, Error};
use bitcoin::consensus;
use jsonrpc;

const SCAN_INTERVAL: u64 = 60000; // check blockchain once per minute

pub fn watch_node(rpc_path: String) {

    let config_rs = Config::load().unwrap();
    let mut sc_entity = PGDatabase::get_new();

    sc_entity.set_connection_from_config(&config_rs);

    //check interval 
    let interval = time::Duration::from_millis(SCAN_INTERVAL);
    let rpc_path_parts: Vec<&str> = rpc_path.split('@').collect();
    if rpc_path_parts.len() != 2 {
        panic!("Invalid bitcoind RPC path")
    };

    let rpc_cred: Vec<&str> = rpc_path_parts[0].split(':').collect();
    if rpc_cred.len() != 2 {
        panic!("Invalid bitcoind RPC credentials")
    };

    let rpc = Client::new(rpc_path_parts[1].to_string(),
                          Auth::UserPass(rpc_cred[0].to_string(),
                                         rpc_cred[1].to_string())).unwrap();

    // main watch loop
    loop {
        // get current block height
        let bestblockcount = rpc.get_block_count();
        let blocks = bestblockcount.unwrap() as i64;

        debug!("WATCH: Bitcoin block height {}", blocks);

        //get all backup transactions with loctimes less than or equal to the current block height
        let txs = sc_entity.get_current_backup_txs(blocks).unwrap();

        debug!("WATCH: Stored backup txs now valid {}", txs.len().to_string() );

        //loop over txs
        for tx in &txs {
            debug!("WATCH: TxID: {}",consensus::encode::serialize_hex(&tx.tx.txid()));

            let txinfo = rpc.send_raw_transaction(&consensus::serialize(&tx.tx));
            match txinfo {
                Ok(ret) => {
                    info!(
                        "Backup transaction txid {} successfully broadcast.",
                        ret
                    );
                    continue;
                }
                Err(Error::JsonRpc(jsonrpc::error::Error::Rpc(ref rpcerr)))
                    if rpcerr.code == -27 =>  // "transaction already in block chain"
                        {
                            // transaction successfully confirmed - remove from backup DB
                            sc_entity.remove_backup_tx(&tx.id);
                            info!(
                                "Backup txid {} already confirmed. ID {} removed from BackupTx database.",
                                tx.tx.txid(),
                                tx.id
                            );
                            continue;
                        }
                Err(e) => {
                    info!(
                        "Error sending backup tx {}",
                        tx.tx.txid()
                    );
                    continue;
                }
            }
        }
        thread::sleep(interval);
    }
}