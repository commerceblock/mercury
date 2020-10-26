//! Daemon
//!
//! Daemon is a UnixServer with loaded Wallet struct. It is accessed via server_request method
//! which is itself exposed to JavaScript via Neon-binding.

use super::Result;
use crate::wallet;
use crate::{state_entity,
    {state_entity::api::get_statechain_fee_info, ClientShim, error::CError, get_config, Tor}};

use tokio::prelude::*;
use tokio::{spawn, run};
use serde::{Serialize, Deserialize};
use daemon_engine::{UnixServer, UnixConnection, JsonCodec};

use wallet::wallet::ElectrumxBox;
use uuid::Uuid;
use shared_lib::structs::{TransferMsg3, SCEAddress};
use state_entity::api::get_statechain;
use rand::Rng;


/// Example request object
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DaemonRequest {
    LifeCheck,
    // Wallet fns
    GenAddressBTC,
    GenAddressSE(String),
    GetWalletBalance,
    GetStateChainsInfo,
    GetListUnspent,
    // State Entity fns
    GetFeeInfo,
    GetStateChain(Uuid),
    Deposit(u64),
    Withdraw(Uuid),
    TransferSender(Uuid, SCEAddress),
    TransferReceiver(TransferMsg3),
    Swap(Uuid, u64, bool)
}

/// Example response object
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DaemonResponse {
    None,
    Value(String),
    Error(String)
}

impl DaemonResponse {
    pub fn to_string(&self) -> String {
        format!("{:?}",self)
    }

    // Values and Errors serialized to string for pasing to JS
    pub fn value_to_deamon_response<T>(value: Result<T>) -> DaemonResponse
    where T: Serialize
    {
        match value { // Values and Errors serialized to string for pasing to JS
            Ok(val) => DaemonResponse::Value(serde_json::to_string(&val).unwrap()),
            Err(e) => DaemonResponse::Error(serde_json::to_string(&e).unwrap())
        }

    }
}

/// Start Wallet's UnixServer process
pub fn make_wallet_daemon() -> Result<()> {
    // Check if server already running
    if let Ok(_) = query_wallet_daemon(DaemonRequest::LifeCheck) {
        panic!("Wallet daemon already running.")
    }

    println!("Configuring and building WalletStateManager...");
    let server = future::lazy(move || {
        let _ = env_logger::try_init();


        let conf_rs = get_config().unwrap();
        let endpoint: String = conf_rs.get("endpoint").unwrap();
        let electrum_server: String = conf_rs.get("electrum_server").unwrap();
        let testing_mode: bool = conf_rs.get("testing_mode").unwrap();
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

        // Try load wallet. If no wallet make new.
        let mut wallet = match wallet::wallet::Wallet::load(client_shim.clone()) {
            Ok(wallet) => wallet,
            Err(_) => {
                println!("No wallet file found. Creating new...");

                // Defaults to generic seed
                let mut seed: [u8; 32] = [0xcd; 32];

                if testing_mode == false {
                    seed = rand::thread_rng().gen(); // Generate fresh seed
                };

                let wallet = wallet::wallet::Wallet::new(&seed, &network, client_shim);
                wallet.save();
                wallet
            }
        };

        // Set electrumx client. Default is Mock
        if testing_mode == false {
            if electrum_server.len() > 0 {   // Use mock electrum server if no server address provided
                wallet.set_electrumx_client(ElectrumxBox::new(electrum_server).unwrap()) // Throw if electrumx server error.
            } else {
                println!("No Electrum server address provided. Defaulted to Mock Electrum server.")
            }
        }

        let mut s = UnixServer::<JsonCodec<DaemonResponse, DaemonRequest>>::new(&daemon_address, JsonCodec::new()).unwrap();

        let server_handle = s
            .incoming()
            .unwrap()
            .for_each(move |r| {
                let data = r.data();
                match data {
                    DaemonRequest::LifeCheck => {
                        r.send(DaemonResponse::None)
                    },
                    DaemonRequest::GenAddressBTC => {
                        debug!("Daemon: GenAddressBTC");
                        let address = wallet.keys.get_new_address();
                        r.send(DaemonResponse::value_to_deamon_response(address))
                    },
                    DaemonRequest::GenAddressSE(txid) => {
                        debug!("Daemon: GenAddressSE");
                        let address = wallet.get_new_state_entity_address(&txid);
                        r.send(DaemonResponse::value_to_deamon_response(address))
                    },
                    DaemonRequest::GetWalletBalance => {
                        debug!("Daemon: GetWalletBalance");
                        let balance = wallet.get_all_addresses_balance();
                        r.send(DaemonResponse::value_to_deamon_response(balance))
                    },
                    DaemonRequest::GetStateChainsInfo => {
                        debug!("Daemon: GetStateChainsInfo");
                        let balance = wallet.get_state_chains_info();
                        r.send(DaemonResponse::value_to_deamon_response(balance))
                    },
                    DaemonRequest::GetListUnspent => {
                        debug!("Daemon: GetListUnspent");
                        let list_unspent = wallet.list_unspent();
                        r.send(DaemonResponse::value_to_deamon_response(list_unspent))
                    },
                    DaemonRequest::GetFeeInfo => {
                        debug!("Daemon: GetFeeInfo");
                        let fee_info_res = get_statechain_fee_info(&wallet.client_shim);
                        r.send(DaemonResponse::value_to_deamon_response(fee_info_res))
                    },
                    DaemonRequest::GetStateChain(state_chain_id) => {
                        debug!("Daemon: GetStateChain");
                        let fee_info_res = get_statechain(&wallet.client_shim, &state_chain_id);
                        r.send(DaemonResponse::value_to_deamon_response(fee_info_res))
                    }
                    DaemonRequest::Deposit(amount) => {
                        debug!("Daemon: Deposit");
                        let deposit_res = state_entity::deposit::deposit(&mut wallet, &amount);
                        r.send(DaemonResponse::value_to_deamon_response(deposit_res))
                    },
                    DaemonRequest::Withdraw(state_chain_id) => {
                        debug!("Daemon: Withdraw");
                        let deposit_res = state_entity::withdraw::withdraw(&mut wallet, &state_chain_id);
                        r.send(DaemonResponse::value_to_deamon_response(deposit_res))
                    },
                    DaemonRequest::TransferSender(state_chain_id, receiver_addr) => {
                        debug!("Daemon: TransferSender");
                        let transfer_sender_resp = state_entity::transfer::transfer_sender(&mut wallet, &state_chain_id, receiver_addr);
                        r.send(DaemonResponse::value_to_deamon_response(transfer_sender_resp))
                    },
                    DaemonRequest::TransferReceiver(mut transfer_msg) => {
                        debug!("Daemon: TransferReceiver");
                        let transfer_receiver_resp = state_entity::transfer::transfer_receiver(&mut wallet, &mut transfer_msg, &None);
                        r.send(DaemonResponse::value_to_deamon_response(transfer_receiver_resp))
                    },
                    DaemonRequest::Swap(state_chain_id, swap_size, force_no_tor) => {
                        debug!("Daemon: Swapping {} with swap size {}", state_chain_id, swap_size);
                        state_entity::conductor::do_swap(
                            &mut wallet,
                            &state_chain_id,
                            &swap_size,
                            force_no_tor
                        ).unwrap();
                        r.send(DaemonResponse::None)
                    }
                }.wait()
                .unwrap();

                wallet.save();
                Ok(())
            }).map_err(|_e| ());
        spawn(server_handle);
        Ok(())
    });

    println!("Running wallet UnixServer...");
    run(server);

    Ok(())
}


/// Create UnixConnection and make example request to UnixServer
pub fn query_wallet_daemon(cmd: DaemonRequest) -> Result<DaemonResponse> {
    let conf_rs = get_config().unwrap();
    let daemon_address: String = conf_rs.get("daemon_address")?;

    let client = UnixConnection::<JsonCodec<DaemonRequest, DaemonResponse>>::new(&daemon_address, JsonCodec::new()).wait()?;
    let (tx, rx) = client.split();

    if let Err(_) = tx.send(cmd).wait() {
        return Err(CError::Generic("Failed to send request to UnixServer.".to_string()));
    }

    let resp = rx.map(|resp| -> DaemonResponse {
       resp
    }).wait().next();
    Ok(resp.unwrap().unwrap())
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::{thread, time::Duration};

    #[test]
    fn test_make_server() {
        let request = query_wallet_daemon(DaemonRequest::GenAddressBTC);
        assert!(request.is_err());

        thread::spawn(|| {
            let _ = make_wallet_daemon();
        });
        thread::sleep(Duration::from_millis(200));

        let request = query_wallet_daemon(DaemonRequest::GenAddressBTC);
        assert!(request.is_ok());
    }
}
