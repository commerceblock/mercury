pub use super::Result;
extern crate shared_lib;
use crate::config::Config;
use std::{thread, time};
use crate::Database;
use bitcoincore_rpc::{Auth, Client, RpcApi, Error};
use bitcoin::consensus;
use jsonrpc;
use cfg_if::cfg_if;

const SCAN_INTERVAL: u64 = 60000; // check blockchain once per minute

pub fn watch_node(rpc_path: String) -> Result<()> {

    let config_rs = Config::load().unwrap();

    cfg_if! {
        if #[cfg(any(test,feature="mockdb"))]{
            use crate::MockDatabase;
            let mut sc_entity = MockDatabase::new();
        } else {
            use crate::PGDatabase;
            let mut sc_entity = PGDatabase::get_new();
        }
    }

    //set db connection
    sc_entity.set_connection_from_config(&config_rs)?;

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
        if #[cfg(any(test,feature="mockdb"))]{
            use shared_lib::mocks::mock_client::MockClient;
            let mut rpc = MockClient::new();
        } else {
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
                            sc_entity.remove_backup_tx(&tx.id)?;
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

        cfg_if! {
            if #[cfg(any(test,feature="mockdb"))]{
                break;
            }
        }

        thread::sleep(interval);
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::protocol::util::{
        mocks,
        tests::{test_sc_entity, BACKUP_TX_NOT_SIGNED, BACKUP_TX_SIGNED},
    };
    use bitcoin::Transaction;
    use std::str::FromStr;

    #[test]
    fn test_deposit_init() {
        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_create_user_session().returning(|_, _, _| Ok(()));

        let sc_entity = test_sc_entity(db);

        // Invalid proof key
        match sc_entity.deposit_init(DepositMsg1 {
            auth: String::from("auth"),
            proof_key: String::from(""),
        }) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("Proof key not in correct format.")),
        }
        // Invalid proof key
        match sc_entity.deposit_init(DepositMsg1 {
            auth: String::from("auth"),
            proof_key: String::from(
                "65aab40995d3ed5d03a0567b04819ff12641b84c17f5e9d5dd075571e18346",
            ),
        }) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("Proof key not in correct format.")),
        }

        assert!(sc_entity
            .deposit_init(DepositMsg1 {
                auth: String::from("auth"),
                proof_key: String::from(
                    "026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e"
                )
            })
            .is_ok());
    }

    #[test]
    fn test_deposit_confirm() {
        let user_id = Uuid::from_str("001203c9-93f0-46f9-abda-0678c891b2d3").unwrap();
        let proof_key =
            String::from("026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e");
        let tx_backup: Transaction = serde_json::from_str(&BACKUP_TX_NOT_SIGNED).unwrap();
        let tx_backup_signed = serde_json::from_str::<Transaction>(&BACKUP_TX_SIGNED).unwrap();

        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_get_user_auth().returning(move |_| Ok(user_id));
        db.expect_root_get_current_id().returning(|| Ok(1 as i64));
        db.expect_get_root().returning(|_| Ok(None));
        db.expect_root_update().returning(|_| Ok(1));
        // First return unsigned back up tx
        db.expect_get_backup_transaction_and_proof_key()
            .times(1)
            .returning(move |_| Ok((tx_backup.clone(), "".to_string())));
        // Second time return signed back up tx
        db.expect_get_backup_transaction_and_proof_key()
            .returning(move |_| Ok((tx_backup_signed.clone(), proof_key.clone())));
        db.expect_create_statechain().returning(|_, _, _, _| Ok(()));
        db.expect_create_backup_transaction()
            .returning(|_, _| Ok(()));
        db.expect_update_statechain_id().returning(|_, _| Ok(()));

        let sc_entity = test_sc_entity(db);

        // Backup tx not signed error
        match sc_entity.deposit_confirm(DepositMsg2 {
            shared_key_id: user_id,
        }) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("Signed Back up transaction not found.")),
        }

        // Clean protocol run
        let _m = mocks::ms::post_commitment().create();         //Mainstay post commitment mock
        assert!(sc_entity
            .deposit_confirm(DepositMsg2 {
                shared_key_id: user_id
            })
            .is_ok());
    }
}
