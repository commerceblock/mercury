#[macro_use]
extern crate clap;
use clap::App;

use client_lib::state_entity;
use client_lib::wallet::wallet;
use client_lib::ClientShim;
use shared_lib::{
    mocks::mock_electrum::MockElectrum,
    structs::{SCEAddress, TransferMsg3},
};

use bitcoin::consensus;
use serde::{Deserialize, Serialize};
use electrumx_client::{electrumx_client::ElectrumxClient, interface::Electrumx};
use std::str::FromStr;
use uuid::Uuid;
use config::Config as ConfigRs;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub endpoint: String,
    pub electrum_server: String,
    pub testing_mode: bool
}

impl Default for Config {
    fn default() -> Config {
        Config {
            endpoint: "https://localhost:8000".to_string(),
            electrum_server: "127.0.0.1:60401".to_string(),
            testing_mode: true
        }
    }
}

fn main() {
    let yaml = load_yaml!("../cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    let mut conf_rs = ConfigRs::new();
    let _ = conf_rs
        // First merge struct default config
        .merge(ConfigRs::try_from(&Config::default()).unwrap()).unwrap();
    conf_rs
        // Add in `./Settings.toml`
        .merge(config::File::with_name("Settings").required(false))
        .unwrap()
        // Add in settings from the environment (with prefix "APP")
        // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
        .merge(config::Environment::with_prefix("MERC"))
        .unwrap();
    let se_endpoint: String = conf_rs.get("endpoint").unwrap();
    let electrum_server_addr: String = conf_rs.get("electrum_server").unwrap();
    let testing_mode: bool = conf_rs.get("testing_mode").unwrap();

    // TODO: random generating of seed and allow input of mnemonic phrase
    let seed = [0xcd; 32];
    let client_shim = ClientShim::new(se_endpoint.to_string(), None).unwrap();

    let electrum: Box<dyn Electrumx> = if testing_mode {
        Box::new(MockElectrum::new())
    } else {
        Box::new(ElectrumxClient::new(electrum_server_addr).unwrap())
    };

    let network = "testnet".to_string();

    if let Some(_matches) = matches.subcommand_matches("create-wallet") {
        println!("Network: [{}], Creating wallet", network);
        let wallet = wallet::Wallet::new(&seed, &network, client_shim, electrum);
        wallet.save();
        println!("Network: [{}], Wallet saved to disk", &network);
    } else if let Some(matches) = matches.subcommand_matches("wallet") {
        let mut wallet = wallet::Wallet::load(client_shim, electrum).unwrap();

        if matches.is_present("new-address") {
            let address = wallet.keys.get_new_address().unwrap();
            println!(
                "\nNetwork: [{}], \n\nAddress: [{}]\n",
                network,
                address.to_string()
            );
            wallet.save();
        } else if matches.is_present("get-balance") {
            println!("\nNetwork: [{}],", network);
            let (addrs, balances) = wallet.get_all_addresses_balance();
            if addrs.len() > 0 {
                println!("\n\nWallet balance: \n\nAddress:\t\t\t\t\tConfirmed:\tUnconfirmed:");
                for (i, _) in addrs.iter().enumerate() {
                    println!(
                        "{}\t{}\t\t{}",
                        addrs[i], balances[i].confirmed, balances[i].unconfirmed
                    );
                }
                println!();
            }
            let (_, state_chain_ids, bals) = wallet.get_state_chains_info();
            if state_chain_ids.len() > 0 {
                println!("\n\nState Entity balance: \n\nStateChain ID:\t\t\t\t\tConfirmed:\tUnconfirmed:");
                for (i, bal) in bals.into_iter().enumerate() {
                    println!(
                        "{}\t\t{}\t\t{}",
                        state_chain_ids[i], bal.confirmed, bal.unconfirmed
                    );
                }
                println!();
            }
        } else if matches.is_present("list-unspent") {
            let (_, unspent_list) = wallet.list_unspent();
            let mut hashes: Vec<String> = vec![];
            for unspent_for_addr in unspent_list {
                for unspent in unspent_for_addr {
                    hashes.push(unspent.tx_hash);
                }
            }
            println!(
                "\nNetwork: [{}], \n\nUnspent tx hashes: \n{}\n",
                network,
                hashes.join("\n")
            );
        } else if matches.is_present("se-addr") {
            if let Some(matches) = matches.subcommand_matches("se-addr") {
                let funding_txid: &str = matches.value_of("txid").unwrap();
                let se_address = wallet
                    .get_new_state_entity_address(&funding_txid.to_string())
                    .unwrap();
                wallet.save();
                println!(
                    "\nNetwork: [{}], \n\nNew State Entity address: \n{:?}",
                    network,
                    serde_json::to_string(&se_address).unwrap()
                );
            }
        } else if matches.is_present("deposit") {
            if let Some(matches) = matches.subcommand_matches("deposit") {
                let amount: &str = matches.value_of("amount").unwrap();
                let (_, state_chain_id, funding_txid, tx_b, _, _) = state_entity::deposit::deposit(
                    &mut wallet,
                    &amount.to_string().parse::<u64>().unwrap(),
                )
                .unwrap();
                wallet.save();
                println!(
                    "\nNetwork: [{}], \n\nDeposited {} satoshi's. \nState Chain ID: {}",
                    network, amount, state_chain_id
                );
                println!("\nFunding Txid: {}", funding_txid);
                println!(
                    "\nBackup Transaction hex: {}",
                    hex::encode(consensus::serialize(&tx_b))
                );
            }
        } else if matches.is_present("withdraw") {
            if let Some(matches) = matches.subcommand_matches("withdraw") {
                let shared_key_id: &str = matches.value_of("id").unwrap();
                let (txid, state_chain_id, amount) = state_entity::withdraw::withdraw(
                    &mut wallet,
                    &Uuid::from_str(&shared_key_id).unwrap(),
                )
                .unwrap();
                wallet.save();
                println!(
                    "\nNetwork: [{}], \nWithdrawn {} satoshi's. \nFrom StateChain ID: {}",
                    network, amount, state_chain_id
                );

                println!("\nWithdraw Txid: {}", txid);
            }
        } else if matches.is_present("transfer-sender") {
            if let Some(matches) = matches.subcommand_matches("transfer-sender") {
                let shared_key_id: &str = matches.value_of("id").unwrap();
                let receiver_addr: SCEAddress =
                    serde_json::from_str(matches.value_of("addr").unwrap()).unwrap();
                let transfer_msg = state_entity::transfer::transfer_sender(
                    &mut wallet,
                    &Uuid::from_str(&shared_key_id).unwrap(),
                    receiver_addr,
                )
                .unwrap();
                wallet.save();
                println!(
                    "\nNetwork: [{}], \n\nTransfer initiated for StateChain ID: {}.",
                    network, shared_key_id
                );
                println!(
                    "\nTransfer message: {:?}",
                    serde_json::to_string(&transfer_msg).unwrap()
                );
            }
        } else if matches.is_present("transfer-receiver") {
            if let Some(matches) = matches.subcommand_matches("transfer-receiver") {
                let transfer_msg: TransferMsg3 =
                    serde_json::from_str(matches.value_of("message").unwrap()).unwrap();
                let finalized_data =
                    state_entity::transfer::transfer_receiver(&mut wallet, &transfer_msg, &None)
                        .unwrap();
                wallet.save();
                println!(
                    "\nNetwork: [{}], \n\nTransfer complete for StateChain ID: {}.",
                    network, finalized_data.state_chain_id
                );
            }

        // backup
        } else if matches.is_present("backup") {
            println!("Backup not currently implemented.")
        // let escrow = escrow::Escrow::load();
        //
        // println!("Backup private share pending (it can take some time)...");
        //
        // let start = Instant::now();
        // wallet.backup(escrow);
        //
        // println!("Backup key saved in escrow (Took: {})", TimeFormat(start.elapsed()));
        } else if matches.is_present("verify") {
            println!("Backup verification not currently implemented.")

        // let escrow = escrow::Escrow::load();
        //
        // println!("verify encrypted backup (it can take some time)...");
        //
        // let start = Instant::now();
        // wallet.verify_backup(escrow);
        //
        // println!(" (Took: {})", TimeFormat(start.elapsed()));
        } else if matches.is_present("restore") {
            println!("Restoring not currently implemented.")

        // let escrow = escrow::Escrow::load();
        //
        // println!("backup recovery in process 📲 (it can take some time)...");
        //
        // let start = Instant::now();
        // wallet::Wallet::recover_and_save_share(escrow, &network, &client_shim);
        //
        // println!(" Backup recovered 💾(Took: {})", TimeFormat(start.elapsed()));
        } else if matches.is_present("send") {
            println!("Send not currently implemented.")

            // if let Some(matches) = matches.subcommand_matches("send") {
            //     let to: &str = matches.value_of("to").unwrap();
            //     let amount_btc: &str = matches.value_of("amount").unwrap();
            //     let txid = wallet.send(
            //         to.to_string(),
            //         amount_btc.to_string().parse::<f32>().unwrap(),
            //         &client_shim,
            //     );
            //     wallet.save();
            //     println!(
            //         "Network: [{}], Sent {} BTC to address {}. Transaction ID: {}",
            //         network, amount_btc, to, txid
            //     );
            // }
        }

    // Api
    } else if let Some(matches) = matches.subcommand_matches("state-entity") {
        if matches.is_present("get-statechain") {
            if let Some(matches) = matches.subcommand_matches("get-statechain") {
                let id: &str = matches.value_of("id").unwrap();
                let state_chain_info =
                    state_entity::api::get_statechain(&client_shim, &Uuid::from_str(&id).unwrap())
                        .unwrap();
                println!("\nStateChain with Id {} info: \n", id);

                println!(
                    "amount: {}\nutxo:\n\ttxid: {},\n\tvout: {}",
                    state_chain_info.amount, state_chain_info.utxo.txid, state_chain_info.utxo.vout
                );
                println!("StateChain: ");
                for state in state_chain_info.chain.clone() {
                    println!("\t{:?}", state);
                }
                println!();
            }
        } else if matches.is_present("fee-info") {
            let fee_info = state_entity::api::get_statechain_fee_info(&client_shim).unwrap();
            println!("State Entity fee info: \n\n{}", fee_info);
        }
    }
}
