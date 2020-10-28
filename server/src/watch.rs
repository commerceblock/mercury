pub use super::Result;
extern crate shared_lib;
use crate::config::Config;
use std::{thread, time};
use crate::Database;
use bitcoincore_rpc::Error;
use bitcoin::consensus;
use jsonrpc;
use cfg_if::cfg_if;

const SCAN_INTERVAL: u64 = 60000; // check blockchain once per minute

pub fn watch_node(rpc_path: String) -> Result<()> {

    let config_rs = Config::load().unwrap();

    cfg_if! {
        if #[cfg(any(test,feature="mockdb"))]{
            use crate::MockDatabase;
            let mut tx_db = MockDatabase::new();
        } else {
            use crate::PGDatabase;
            let mut tx_db = PGDatabase::get_new();
        }
    }

    //set db connection
    tx_db.set_connection_from_config(&config_rs)?;

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

    cfg_if! {
        if #[cfg(any(test,feature="mockbitcoinrpc"))]{
            use shared_lib::mocks::mock_client::MockBitcoinClient;
            let mut rpc = MockBitcoinClient::new();
        } else {
            use bitcoincore_rpc::{Auth, Client, RpcApi};
            let rpc = Client::new(rpc_path_parts[1].to_string(),
                          Auth::UserPass(rpc_cred[0].to_string(),
                                         rpc_cred[1].to_string())).unwrap();
        }
    }

    // main watch loop
    loop {
        // get current block height
        let bestblockcount = rpc.get_block_count();
        let blocks = bestblockcount.unwrap() as i64;

        debug!("WATCH: Bitcoin block height {}", blocks);

        //get all backup transactions with loctimes less than or equal to the current block height
        let txs = tx_db.get_current_backup_txs(blocks).unwrap();

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
                            tx_db.remove_backup_tx(&tx.id)?;
                            info!(
                                "Backup txid {} already confirmed. ID {} removed from BackupTx database.",
                                tx.tx.txid(),
                                tx.id
                            );
                            continue;
                        }
                Err(e) => {
                    info!(
                        "Error sending backup tx {} {}",
                        tx.tx.txid(),e
                    );
                    continue;
                }
            }
        }

        thread::sleep(interval);
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use bitcoin::Transaction;
    use std::str::FromStr;
    use crate::MockDatabase;
    use uuid::Uuid;
    use crate::structs::BackupTxID;
    use shared_lib::{mocks::mock_client::MockClient};
    use bitcoin::consensus::encode;

    #[test]
    fn test_watch_send() {
        let backup_tx_1_raw: Vec::<u8> = hex::decode("02000000000101b91e2b8e26ae7f93cea773c5d74f7722982134ebbf32ca9b627981a5546ef4c7000000001716001472d64fcb0be3dff555fc87b3d054a1ccb48ac059feffffff0200c2eb0b0000000017a9141040c0c1b81e2e00aec47ef01c2d3a6116ca513d8748b723180100000017a914d5dd335a7721cf03b1f5df5bdf22c63c0e1e472887024730440220167f84b7e579153ff83a480eadc4225ad1c67322ad0e8d5f32d317ce61a6c26802206fff7f176b6780f00cf9d63ea759658e4ca0302dc2204c02bf3ee52e032e051001210297fd944ebb0de31b629a99a14d53fb8c83e5791f714892f72b74751cfd097c1765000000").unwrap();
        let backup_tx_2_raw: Vec::<u8> = hex::decode("020000000001010a742dc732ef1ea6a71c042b7fa212457b52438ba5c3b8552b8a4fd74e86a0f601000000171600147a91e5a412a6a826897067654fffb1557741285efeffffff0240860f240100000017a9140dbb4870526bb96a42ebe19dc86d84a34addc5d48700e1f5050000000017a9141040c0c1b81e2e00aec47ef01c2d3a6116ca513d8702483045022100e7d13322ee719ae8fb7775cafec98137d8d3c42e340cda7750679a06308744f602206154f097a7bc625c688db343633cdafa9e48455d90630d21edf8e036faa0ddbf0121034ea2ae3c24aea00b262c557675d82b66d9aa0f2bc14dfa7d82d1983efb0456c984000000").unwrap();

        let backup_tx_1: Transaction = encode::deserialize(&backup_tx_1_raw).unwrap();
        let backup_tx_2: Transaction = encode::deserialize(&backup_tx_2_raw).unwrap();

        let id_1 = Uuid::from_str("001203c9-93f0-46f9-abda-0678c891b2d3").unwrap();
        let id_2 = Uuid::from_str("93ad2134-ffd3-869d-beef-8da52c985aa1").unwrap();

        let backup_1 = BackupTxID { tx: backup_tx_1, id: id_1 };
        let backup_2 = BackupTxID { tx: backup_tx_2, id: id_2 };
        let mut backup_txs: Vec<BackupTxID> = Vec::new();
        backup_txs.push(backup_1);
        backup_txs.push(backup_2);

        let mut db = MockDatabase::new();
        db.expect_get_current_backup_txs().returning(move |_| {Ok(backup_txs.clone())});
        db.expect_remove_backup_tx().returning(|_| Ok(()));
        let mut rpc = MockClient::new();

        assert_eq!(rpc.get_block_count().unwrap(), 147 as u64);

    }
}
