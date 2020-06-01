#[macro_use]
extern crate clap;
use clap::App;

use client_lib::ClientShim;
use client_lib::wallet::wallet;
use client_lib::state_entity;
use wallet::GetBalanceResponse;

use bitcoin::consensus;
use std::collections::HashMap;
use shared_lib::structs::{TransferMsg3, StateEntityAddress};

fn main() {
    let yaml = load_yaml!("../cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    let mut settings = config::Config::default();
    settings
        // Add in `./Settings.toml`
        .merge(config::File::with_name("Settings"))
        .unwrap()
        // Add in settings from the environment (with prefix "APP")
        // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
        .merge(config::Environment::new())
        .unwrap();
    let hm = settings.try_into::<HashMap<String, String>>().unwrap();
    let endpoint = hm.get("endpoint").unwrap();

    // TODO: random generating of seed and allow input of mnemonic phrase
    let seed = [0xcd; 32];
    let client_shim = ClientShim::new(endpoint.to_string(), None);
    let network = "regtest".to_string();

    if let Some(_matches) = matches.subcommand_matches("create-wallet") {
        println!("Network: [{}], Creating wallet", network);
        let wallet = wallet::Wallet::new(&seed, &network, client_shim);
        wallet.save();
        println!("Network: [{}], Wallet saved to disk", &network);

    } else if let Some(matches) = matches.subcommand_matches("wallet") {
        let mut wallet: wallet::Wallet = wallet::Wallet::load(client_shim).unwrap();

        if matches.is_present("new-address") {
            let address = wallet.keys.get_new_address().unwrap();
            println!("\nNetwork: [{}], \n\nAddress: [{}]", network, address.to_string());
            wallet.save();

        } else if matches.is_present("get-balance") {
            println!("\nNetwork: [{}],",network);
            let addr_balances: Vec<GetBalanceResponse> = wallet.get_all_addresses_balance();
            let state_chain_balances: Vec<GetBalanceResponse> = wallet.get_state_chain_balances();
            if addr_balances.len() > 0 {
                println!("\n\nWallet balance: \n\nAddress:\t\t\t\t\tConfirmed:\tUnconfirmed:");
                for addr in addr_balances.into_iter() {
                    println!("{}\t{}\t\t{}", addr.address, addr.confirmed, addr.unconfirmed);
                }
            }
            if state_chain_balances.len() > 0 {
                println!("\n\nState Entity balance: \n\nShared Key ID:\t\t\t\t\tConfirmed:\tUnconfirmed:");
                for addr in state_chain_balances.into_iter() {
                    println!("{}\t\t{}\t\t{}", addr.address, addr.confirmed, addr.unconfirmed);
                }
            }

        } else if matches.is_present("list-unspent") {
            let unspent = wallet.list_unspent();
            let hashes: Vec<String> = unspent.into_iter().map(|u| u.tx_hash).collect();

            println!(
                "\nNetwork: [{}], \n\nUnspent tx hashes: \n{}\n",
                network,
                hashes.join("\n")
            );

        } else if matches.is_present("se-addr") {
            if let Some(matches) = matches.subcommand_matches("se-addr") {
                let funding_txid: &str = matches.value_of("txid").unwrap();
                let se_address = wallet.get_new_state_entity_address(&funding_txid.to_string()).unwrap();
                wallet.save();
                println!(
                    "\nNetwork: [{}], \n\nNew State Entity address: \n{:?}",
                    network, se_address
                );
            }

        } else if matches.is_present("deposit") {
            if let Some(matches) = matches.subcommand_matches("deposit") {
                let amount: &str = matches.value_of("amount").unwrap();
                let (shared_key_id, state_chain_id, tx_0, _, _) = state_entity::deposit::deposit(
                    &mut wallet,
                    &amount.to_string().parse::<u64>().unwrap(),
                ).unwrap();
                wallet.save();
                println!(
                    "\nNetwork: [{}], \n\nDeposited {} satoshi's. \nShared Key ID: {} \nState Chain ID: {}",
                    network, amount, shared_key_id, state_chain_id
                );
                println!("\nFunding Transaction hex: {}",hex::encode(consensus::serialize(&tx_0)));
            }

        } else if matches.is_present("withdraw") {
            if let Some(matches) = matches.subcommand_matches("withdraw") {
                let shared_key_id: &str = matches.value_of("key").unwrap();
                let (tx_w, state_chain_id, amount) = state_entity::withdraw::withdraw(
                    &mut wallet,
                    &shared_key_id.to_string()
                ).unwrap();
                wallet.save();
                println!(
                    "\nNetwork: [{}], \nWithdrawn {} satoshi's. \nFrom State Chain ID: {}",
                    network, amount, state_chain_id
                );

                println!("\nWithdraw Transaction hex: {}",hex::encode(consensus::serialize(&tx_w)));
            }

        } else if matches.is_present("transfer-sender") {
            if let Some(matches) = matches.subcommand_matches("transfer-sender") {
                let shared_key_id: &str = matches.value_of("key").unwrap();
                let receiver_addr: &str = matches.value_of("addr").unwrap();
                let receiver_proof_key: &str = matches.value_of("proof_key").unwrap();
                let transfer_msg = state_entity::transfer::transfer_sender(
                    &mut wallet,
                    &shared_key_id.to_string(),
                    StateEntityAddress {
                        backup_tx_addr: receiver_addr.to_owned(),
                        proof_key: receiver_proof_key.to_owned(),
                    },
                ).unwrap();
                wallet.save();
                println!(
                    "\nNetwork: [{}], \n\nTransfer initiated for Shared Key ID: {}.",
                    network, shared_key_id
                );
                println!("\nTransfer message: {:?}",serde_json::to_string(&transfer_msg).unwrap());
            }

        } else if matches.is_present("transfer-receiver") {
            if let Some(matches) = matches.subcommand_matches("transfer-receiver") {
                let transfer_msg: TransferMsg3 = serde_json::from_str(matches.value_of("message").unwrap()).unwrap();
                let new_shared_key_id = state_entity::transfer::transfer_receiver(
                    &mut wallet,
                    &transfer_msg
                ).unwrap();
                wallet.save();
                println!(
                    "\nNetwork: [{}], \n\nTransfer complete for Shared Key ID: {}.",
                    network, new_shared_key_id
                );
            }

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
            println!("Backup not currently implemented.")

            // let escrow = escrow::Escrow::load();
            //
            // println!("verify encrypted backup (it can take some time)...");
            //
            // let start = Instant::now();
            // wallet.verify_backup(escrow);
            //
            // println!(" (Took: {})", TimeFormat(start.elapsed()));

        } else if matches.is_present("restore") {
            println!("Backup not currently implemented.")

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
    }
}
