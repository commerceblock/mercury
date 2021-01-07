//! Daemon
//!
//! Daemon is a UnixServer with loaded Wallet struct. It is accessed via server_request method
//! which is itself exposed to JavaScript via Neon-binding.

use super::Result;
use crate::wallet;
use crate::{
    state_entity,
    {error::CError, get_config, state_entity::api::get_statechain_fee_info, ClientShim, Tor}, error::WalletErrorType,
};

use daemon_engine::{JsonCodec, UnixConnection, UnixServer};
use serde::{Deserialize, Serialize};
use tokio::prelude::*;
use tokio::{run, spawn};

use rand::Rng;
use state_entity::api::get_statechain;
use uuid::Uuid;
use wallet::wallet::{DEFAULT_TEST_WALLET_LOC, ElectrumxBox, DEFAULT_WALLET_LOC};
use crate::utilities::encoding;

/// Example request object
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DaemonRequest {
    LifeCheck,
    // Wallet fns
    GenAddressBTC,
    GenAddressSE,
    GetWalletBalance,
    GetStateChainsInfo,
    GetListUnspent,
    // State Entity fns
    GetBackup(Uuid),
    GetFeeInfo,
    GetStateChain(Uuid),
    Deposit(u64),
    Withdraw(Uuid),
    TransferSender(Uuid, String),
    TransferReceiver(String),
    Swap(Uuid, u64, bool),
}

/// Example response object
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DaemonResponse {
    None,
    Value(String),
    Error(String),
}

impl DaemonResponse {
    pub fn to_string(&self) -> String {
        format!("{:?}", self)
    }

    // Values and Errors serialized to string for pasing to JS
    pub fn value_to_deamon_response<T>(value: Result<T>) -> DaemonResponse
    where
        T: Serialize,
    {
        match value {
            // Values and Errors serialized to string for pasing to JS
            Ok(val) => DaemonResponse::Value(serde_json::to_string(&val).unwrap()),
            Err(e) => DaemonResponse::Error(serde_json::to_string(&e).unwrap()),
        }
    }
}

/// Start Wallet's UnixServer process
pub fn run_wallet_daemon(force_testing_mode: bool) -> Result<()> {
    // Check if server already running
    if let Ok(_) = query_wallet_daemon(DaemonRequest::LifeCheck) {
        panic!("Wallet daemon already running.")
    }

    println!("Configuring and building WalletStateManager...");

        let _ = env_logger::try_init();

        let conf_rs = get_config().unwrap();
        let endpoint: String = conf_rs.get("endpoint").unwrap();
        let electrum_server: String = conf_rs.get("electrum_server").unwrap();
        let mut testing_mode: bool = conf_rs.get("testing_mode").unwrap();
        if force_testing_mode {
            testing_mode = true;
        }
        let network: String = conf_rs.get("network").unwrap();
        let daemon_address: String = conf_rs.get("daemon_address").unwrap();

        let mut tor = Tor::from_config(&conf_rs);
        let tor = match tor.enable {
            true => {
                tor.control_password = conf_rs
                    .get("tor_control_password")
                    .expect("tor enabled - tor_control_password required");
                Some(tor)
            }
            false => None,
        };
        println!("config tor: {:?}", tor);

        let client_shim = ClientShim::new(endpoint, None, tor);

        let wallet_data_loc = if testing_mode {
            println!("Testing mode enabled.");
            DEFAULT_TEST_WALLET_LOC
        } else {
            DEFAULT_WALLET_LOC
        };

        // Try load wallet. If no wallet make new.
        let mut wallet = match wallet::wallet::Wallet::load(wallet_data_loc, client_shim.clone()) {
            Ok(wallet) => wallet,
            Err(e) => match e {
                CError::WalletError(ref error_type) => match error_type {
                    WalletErrorType::WalletFileNotFound => {
                        println!("No wallet file found. Creating new wallet...");

                        let seed = if testing_mode {
                            [0xcd; 32]              // Defaults to generic seed
                        } else {
                            rand::thread_rng().gen() // Generate fresh seed
                        };

                        let wallet = wallet::wallet::Wallet::new(&seed, &network, wallet_data_loc, client_shim);
                        wallet.save();
                        wallet
                    },
                    _ => return Err(e)
                },
                _ => return Err(e)
            }
        };

        // Set electrumx client. Default is Mock
        if testing_mode == false {
            if electrum_server.len() > 0 {
                // Use mock electrum server if no server address provided
                wallet.set_electrumx_client(ElectrumxBox::new(electrum_server).unwrap())
            // Throw if electrumx server error.
            } else {
                println!("No Electrum server address provided. Defaulted to Mock Electrum server.")
            }
        }

    let server = future::lazy(move || {
        let mut s = UnixServer::<JsonCodec<DaemonResponse, DaemonRequest>>::new(
            &daemon_address,
            JsonCodec::new(),
        )
        .unwrap();


        let server_handle = s
            .incoming()
            .unwrap()
            .for_each(move |r| {
                let data = r.data();
                match data {
                    DaemonRequest::LifeCheck => r.send(DaemonResponse::None),
                    DaemonRequest::GenAddressBTC => {
                        debug!("Daemon: GenAddressBTC");
                        let address = wallet.keys.get_new_address();
                        wallet.save();
                        r.send(DaemonResponse::value_to_deamon_response(address))
                    }
                    DaemonRequest::GenAddressSE => {
                        debug!("Daemon: GenAddressSE");
                        let address = wallet.get_new_state_entity_address();
                        let bech32 = encoding::encode_address(address.unwrap());
                        wallet.save();
                        r.send(DaemonResponse::value_to_deamon_response(bech32))
                    }
                    DaemonRequest::GetWalletBalance => {
                        debug!("Daemon: GetWalletBalance");
                        let balance = wallet.get_all_addresses_balance();
                        r.send(DaemonResponse::value_to_deamon_response(balance))
                    }
                    DaemonRequest::GetBackup(statechain_id) => {
                        debug!("Daemon: GetBackup");
                        let backup_tx = wallet.get_backup_tx(&statechain_id);
                        r.send(DaemonResponse::value_to_deamon_response(backup_tx))
                    }                    
                    DaemonRequest::GetStateChainsInfo => {
                        debug!("Daemon: GetStateChainsInfo");
                        let balance = wallet.get_state_chains_info();
                        r.send(DaemonResponse::value_to_deamon_response(balance))
                    }
                    DaemonRequest::GetListUnspent => {
                        debug!("Daemon: GetListUnspent");
                        let list_unspent = wallet.list_unspent();
                        r.send(DaemonResponse::value_to_deamon_response(list_unspent))
                    }
                    DaemonRequest::GetFeeInfo => {
                        debug!("Daemon: GetFeeInfo");
                        let fee_info_res = get_statechain_fee_info(&wallet.client_shim);
                        r.send(DaemonResponse::value_to_deamon_response(fee_info_res))
                    }
                    DaemonRequest::GetStateChain(statechain_id) => {
                        debug!("Daemon: GetStateChain");
                        let fee_info_res = get_statechain(&wallet.client_shim, &statechain_id);
                        r.send(DaemonResponse::value_to_deamon_response(fee_info_res))
                    }
                    DaemonRequest::Deposit(amount) => {
                        debug!("Daemon: Deposit");
                        let deposit_res = state_entity::deposit::deposit(&mut wallet, &amount);
                        wallet.save();
                        r.send(DaemonResponse::value_to_deamon_response(deposit_res))
                    }
                    DaemonRequest::Withdraw(statechain_id) => {
                        debug!("Daemon: Withdraw");
                        let deposit_res =
                            state_entity::withdraw::withdraw(&mut wallet, &statechain_id);
                        wallet.save();
                        r.send(DaemonResponse::value_to_deamon_response(deposit_res))
                    }
                    DaemonRequest::TransferSender(statechain_id, receiver_addr) => {
                        debug!("Daemon: TransferSender");
                        let sce_address = encoding::decode_address(receiver_addr,&network).unwrap();
                        let transfer_sender_resp = state_entity::transfer::transfer_sender(
                            &mut wallet,
                            &statechain_id,
                            sce_address,
                        );
                        let encoded_message = encoding::encode_message(transfer_sender_resp.unwrap());
                        wallet.save();
                        r.send(DaemonResponse::value_to_deamon_response(
                            encoded_message,
                        ))
                    }
                    DaemonRequest::TransferReceiver(transfer_msg_bech32) => {
                        debug!("Daemon: TransferReceiver");
                        let mut transfer_msg = encoding::decode_message(transfer_msg_bech32,&network).unwrap();
                        let transfer_receiver_resp = state_entity::transfer::transfer_receiver(
                            &mut wallet,
                            &mut transfer_msg,
                            &None,
                        );
                        wallet.save();
                        r.send(DaemonResponse::value_to_deamon_response(
                            transfer_receiver_resp,
                        ))
                    }
                    DaemonRequest::Swap(statechain_id, swap_size, force_no_tor) => {
                        debug!(
                            "Daemon: Swapping {} with swap size {}",
                            statechain_id, swap_size
                        );
                        state_entity::conductor::do_swap(
                            &mut wallet,
                            &statechain_id,
                            &swap_size,
                            force_no_tor,
                        )
                        .unwrap();
                        wallet.save();
                        r.send(DaemonResponse::None)
                    }
                }
                .wait()
                .unwrap();

                Ok(())
            })
            .map_err(|_e| ());
        spawn(server_handle);
        Ok(())
    });

    println!("Running wallet StateManager...");
    run(server);

    Ok(())
}

/// Create UnixConnection and make example request to UnixServer
pub fn query_wallet_daemon(cmd: DaemonRequest) -> Result<DaemonResponse> {
    let conf_rs = get_config().unwrap();
    let daemon_address: String = conf_rs.get("daemon_address")?;

    let client = UnixConnection::<JsonCodec<DaemonRequest, DaemonResponse>>::new(
        &daemon_address,
        JsonCodec::new(),
    )
    .wait()?;
    let (tx, rx) = client.split();

    if let Err(_) = tx.send(cmd).wait() {
        return Err(CError::Generic(
            "Failed to send request to UnixServer.".to_string(),
        ));
    }

    let resp = rx.map(|resp| -> DaemonResponse { resp }).wait().next();
    Ok(resp.unwrap().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{thread, time::Duration};
    use std::fs;

    #[test]
    #[serial]
    fn test_loading_wallet_from_file() {
        // Clear or create empty test_invalid_wallet_format_wallet.data file
        let _ = fs::write(DEFAULT_TEST_WALLET_LOC, "");
        match run_wallet_daemon(true) {
            Ok(_) => assert!(false, "Expected WalletFileInvalid error"),
            Err(e) => assert_eq!(e, CError::WalletError(WalletErrorType::WalletFileInvalid))
        }
        // Valid JSON with fields missing
        let _ = fs::write(DEFAULT_TEST_WALLET_LOC, "{'id':'f6847b5e-ac79-4d57-8eae-8fcdadcb2017'}");
        match run_wallet_daemon(true) {
            Ok(_) => assert!(false, "Expected WalletFileInvalid error"),
            Err(e) => assert_eq!(e, CError::WalletError(WalletErrorType::WalletFileInvalid))
        }

        // Remove test-wallet.data file
        let _ = fs::remove_file(DEFAULT_TEST_WALLET_LOC);
        // Test fresh wallet created
        thread::spawn(|| {
            let _ = run_wallet_daemon(true);
        });
        thread::sleep(Duration::from_millis(1000));

        let gen_addr_request = query_wallet_daemon(DaemonRequest::GenAddressBTC);
        assert!(gen_addr_request.is_ok());
        // Should generate 1st address of test wallet.
        assert_eq!(gen_addr_request.unwrap(), DaemonResponse::Value(serde_json::to_string("tb1qghtup486tj8vgz2l5pkh8hqw8wzdudralnw74e").unwrap()));
    }
}
