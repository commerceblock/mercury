extern crate bitcoin;
extern crate clap;
extern crate client_lib;
extern crate electrumx_client;
extern crate shared_lib;
extern crate uuid;

use client_lib::{
    daemon::{query_wallet_daemon, DaemonRequest, DaemonResponse},
    state_entity::transfer::TransferFinalizeData,
};
use shared_lib::{util::transaction_deserialise, structs::{
    PrepareSignTxMsg, StateChainDataAPI, StateEntityFeeInfoAPI, CoinValueInfo, RecoveryDataMsg
}};

use bitcoin::util::key::PublicKey;
use bitcoin::{consensus, Transaction};
use clap::{load_yaml, App};
use electrumx_client::response::{GetBalanceResponse, GetListUnspentResponse};
use std::str::FromStr;
use uuid::Uuid;
use std::collections::HashMap;

fn main() {
    let yaml = load_yaml!("../cli.yml");
    let matches = App::from_yaml(yaml).get_matches();
    let _ = env_logger::try_init();

    if let Some(matches) = matches.subcommand_matches("wallet") {
        if matches.is_present("new-address") {
            let address: String = match query_wallet_daemon(DaemonRequest::GenAddressBTC).unwrap() {
                DaemonResponse::Value(val) => val,
                DaemonResponse::Error(e) => panic!("{}", e.to_string()),
                DaemonResponse::None => panic!("None value returned."),
            };

            println!("\nBTC Address: [{}]\n", address);
        } else if matches.is_present("se-addr") {
            let address: String =
                match query_wallet_daemon(DaemonRequest::GenAddressSE).unwrap() {
                    DaemonResponse::Value(val) => val,
                    DaemonResponse::Error(e) => panic!("{}", e.to_string()),
                    DaemonResponse::None => panic!("None value returned."),
                };
            println!("\nMercury Address: {:?}\n", address.to_string());
        } else if matches.is_present("get-balance") {
            let (addrs, balances): (Vec<bitcoin::Address>, Vec<GetBalanceResponse>) =
                match query_wallet_daemon(DaemonRequest::GetWalletBalance).unwrap() {
                    DaemonResponse::Value(val) => serde_json::from_str(&val).unwrap(),
                    DaemonResponse::Error(e) => panic!("{}", e.to_string()),
                    DaemonResponse::None => panic!("None value returned."),
                };
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
            let (_, statechain_ids, bals, lktimes): (Vec<Uuid>, Vec<Uuid>, Vec<GetBalanceResponse>, Vec<u32>) =
                match query_wallet_daemon(DaemonRequest::GetStateChainsInfo).unwrap() {
                    DaemonResponse::Value(val) => serde_json::from_str(&val).unwrap(),
                    DaemonResponse::Error(e) => panic!("{}", e.to_string()),
                    DaemonResponse::None => panic!("None value returned."),
                };
            if statechain_ids.len() > 0 {
                println!("\n\nState Entity balance: \n\nStateChain ID:\t\t\t\t\tConfirmed:\tUnconfirmed:\tLocktime:");
                for (i, bal) in bals.into_iter().enumerate() {
                    println!(
                        "{}\t\t{}\t\t{}\t\t{}",
                        statechain_ids[i], bal.confirmed, bal.unconfirmed,lktimes[i]
                    );
                }
                println!();
            }
        } else if matches.is_present("get-backup") {
            if let Some(matches) = matches.subcommand_matches("get-backup") {
                let statechain_id = Uuid::from_str(matches.value_of("id").unwrap()).unwrap();
                let txhex: String =
                    match query_wallet_daemon(DaemonRequest::GetBackup(statechain_id)).unwrap() {
                        DaemonResponse::Value(val) => val,
                        DaemonResponse::Error(e) => panic!("{}", e.to_string()),
                        DaemonResponse::None => panic!("None value returned."),
                    };

                println!("\nBackup Tx: {}\n", txhex);
            }
        } else if matches.is_present("list-unspent") {
            let (_, unspent_list): (Vec<bitcoin::Address>, Vec<Vec<GetListUnspentResponse>>) =
                match query_wallet_daemon(DaemonRequest::GetListUnspent).unwrap() {
                    DaemonResponse::Value(val) => serde_json::from_str(&val).unwrap(),
                    DaemonResponse::Error(e) => panic!("{}", e.to_string()),
                    DaemonResponse::None => panic!("None value returned."),
                };
            let mut hashes: Vec<String> = vec![];
            for unspent_for_addr in unspent_list {
                for unspent in unspent_for_addr {
                    hashes.push(unspent.tx_hash);
                }
            }
            println!("\nUnspent tx hashes: \n{}\n", hashes.join("\n"));
        } else if matches.is_present("deposit") {
            if let Some(matches) = matches.subcommand_matches("deposit") {
                let amount = u64::from_str(matches.value_of("amount").unwrap()).unwrap();
                let (_, statechain_id, funding_txid, tx_b, _, _): (
                    Uuid,
                    Uuid,
                    String,
                    Transaction,
                    PrepareSignTxMsg,
                    PublicKey,
                ) = match query_wallet_daemon(DaemonRequest::Deposit(amount)).unwrap() {
                    DaemonResponse::Value(val) => serde_json::from_str(&val).unwrap(),
                    DaemonResponse::Error(e) => panic!("{}", e.to_string()),
                    DaemonResponse::None => panic!("None value returned."),
                };
                println!(
                    "\nDeposited {} satoshi's. \nState Chain ID: {}",
                    amount, statechain_id
                );
                println!("\nFunding Txid: {}", funding_txid);
                println!(
                    "\nBackup Transaction hex: {}",
                    hex::encode(consensus::serialize(&tx_b))
                );
            }
        } else if matches.is_present("withdraw") {
            if let Some(matches) = matches.subcommand_matches("withdraw") {
                let statechain_id = Uuid::from_str(matches.value_of("id").unwrap()).unwrap();
                let (txid, statechain_id, amount): (String, Uuid, u64) =
                    match query_wallet_daemon(DaemonRequest::Withdraw(statechain_id)).unwrap() {
                        DaemonResponse::Value(val) => serde_json::from_str(&val).unwrap(),
                        DaemonResponse::Error(e) => panic!("{}", e.to_string()),
                        DaemonResponse::None => panic!("None value returned."),
                    };
                println!(
                    "\nWithdrawn {} satoshi's. \nFrom StateChain ID: {}",
                    amount, statechain_id
                );
                println!("\nWithdraw Txid: {}", txid);
            }
        } else if matches.is_present("transfer-sender") {
            if let Some(matches) = matches.subcommand_matches("transfer-sender") {
                let statechain_id = Uuid::from_str(matches.value_of("id").unwrap()).unwrap();
                let receiver_addr: String = matches.value_of("addr").unwrap().to_string();
                let transfer_msg: String = match query_wallet_daemon(
                    DaemonRequest::TransferSender(statechain_id, receiver_addr),
                )
                .unwrap()
                {
                    DaemonResponse::Value(val) => serde_json::from_str(&val).unwrap(),
                    DaemonResponse::Error(e) => panic!("{}", e.to_string()),
                    DaemonResponse::None => panic!("None value returned."),
                };
                println!(
                    "\nTransfer initiated for StateChain ID: {}.",
                    statechain_id
                );
                println!(
                    "\nTransfer message: {:?}",
                    transfer_msg.to_string()
                );
            }
        } else if matches.is_present("transfer-receiver") {
            if let Some(matches) = matches.subcommand_matches("transfer-receiver") {
                let transfer_msg: String = matches.value_of("message").unwrap().to_string();
                let finalized_data: TransferFinalizeData =
                    match query_wallet_daemon(DaemonRequest::TransferReceiver(transfer_msg))
                        .unwrap()
                    {
                        DaemonResponse::Value(val) => serde_json::from_str(&val).unwrap(),
                        DaemonResponse::Error(e) => panic!("{}", e.to_string()),
                        DaemonResponse::None => panic!("None value returned."),
                    };

                let tx = transaction_deserialise(&finalized_data.tx_backup_psm.tx_hex).unwrap();
                println!(
                    "\nTransfer complete for StateChain ID: {}.",
                    finalized_data.statechain_id
                );

                println!(
                    "\nValue: {}",
                    tx.output[0].value
                );

                println!(
                    "\nLocktime: {}",
                    tx.lock_time
                );

                println!(
                    "\nBackup Transaction hex: {}",
                    finalized_data.tx_backup_psm.tx_hex
                );
            }
        } else if matches.is_present("transfer-any") {
            if let Some(matches) = matches.subcommand_matches("transfer-any") {
                let receiver_addr: String = matches.value_of("addr").unwrap().to_string();
                let transfer_msg: String = match query_wallet_daemon(
                    DaemonRequest::TransferAny(receiver_addr),
                )
                .unwrap()
                {
                    DaemonResponse::Value(val) => serde_json::from_str(&val).unwrap(),
                    DaemonResponse::Error(e) => panic!("{}", e.to_string()),
                    DaemonResponse::None => panic!("None value returned."),
                };
                println!("{}",transfer_msg);
            }
        } else if matches.is_present("swap") {
            if let Some(matches) = matches.subcommand_matches("swap") {
                let statechain_id =
                    Uuid::from_str(matches.value_of("state-chain-id").unwrap()).unwrap();
                let swap_size = u64::from_str(matches.value_of("swap-size").unwrap()).unwrap();
                let force_no_tor: bool = matches.is_present("force-no-tor");
                match query_wallet_daemon(DaemonRequest::Swap(
                    statechain_id,
                    swap_size,
                    force_no_tor,
                ))
                .unwrap()
                {
                    DaemonResponse::Error(e) => panic!("{}", e.to_string()),
                    _ => {}
                };
                println!("\nSwap complete from StateChain ID: {}.", statechain_id);
            }
        }
    //
    //     // backup
    //     } else if matches.is_present("backup") {
    //         println!("Backup not currently implemented.")
    //     } else if matches.is_present("verify") {
    //         println!("Backup verification not currently implemented.")
    //     } else if matches.is_present("restore") {
    //         println!("Restoring not currently implemented.")

    //     } else if matches.is_present("send") {
    //         println!("Send not currently implemented.")
    //
    //         // if let Some(matches) = matches.subcommand_matches("send") {
    //         //     let to: &str = matches.value_of("to").unwrap();
    //         //     let amount_btc: &str = matches.value_of("amount").unwrap();
    //         //     let txid = wallet.send(
    //         //         to.to_string(),
    //         //         amount_btc.to_string().parse::<f32>().unwrap(),
    //         //         &client_shim,
    //         //     );
    //         //     wallet.save();
    //         //     println!(
    //         //         "Network: [{}], Sent {} BTC to address {}. Transaction ID: {}",
    //         //         network, amount_btc, to, txid
    //         //     );
    //         // }
    //     }
    //
    // // Api
    } else if let Some(matches) = matches.subcommand_matches("state-entity") {
        if matches.is_present("get-statechain") {
            if let Some(matches) = matches.subcommand_matches("get-statechain") {
                let statechain_id = Uuid::from_str(matches.value_of("id").unwrap()).unwrap();
                let state_chain_info: StateChainDataAPI = match query_wallet_daemon(
                    DaemonRequest::GetStateChain(statechain_id),
                )
                .unwrap()
                {
                    DaemonResponse::Value(val) => serde_json::from_str(&val).unwrap(),
                    DaemonResponse::Error(e) => panic!("{}", e.to_string()),
                    DaemonResponse::None => panic!("None value returned."),
                };
                println!("\nStateChain with Id {} info: \n", statechain_id);
                println!(
                    "amount: {}\nutxo:\n\ttxid: {},\n\tvout: {},\nlocktime: {}",
                    state_chain_info.amount, state_chain_info.utxo.txid, state_chain_info.utxo.vout, state_chain_info.locktime,
                );
                println!("StateChain: ");
                for state in state_chain_info.chain.clone() {
                    println!("\t{:?}", state);
                }
                println!();
            }
        } else if matches.is_present("fee-info") {
            let fee_info: StateEntityFeeInfoAPI =
                match query_wallet_daemon(DaemonRequest::GetFeeInfo).unwrap() {
                    DaemonResponse::Value(val) => serde_json::from_str(&val).unwrap(),
                    DaemonResponse::Error(e) => panic!("{}", e.to_string()),
                    DaemonResponse::None => panic!("None value returned."),
                };
            println!("State Entity fee info: \n\n{}", fee_info);
        } else if matches.is_present("recover-statecoin") {
            if let Some(matches) = matches.subcommand_matches("recover-statecoin") {
                let publickey_hex = matches.value_of("pk").unwrap();
                let recovery_info: Vec<RecoveryDataMsg> = match query_wallet_daemon(
                    DaemonRequest::GetRecoveryData(publickey_hex.to_string()),
                )
                .unwrap()
                {
                    DaemonResponse::Value(val) => serde_json::from_str(&val).unwrap(),
                    DaemonResponse::Error(e) => panic!("{}", e.to_string()),
                    DaemonResponse::None => panic!("None value returned."),
                };
                if recovery_info.len()==0 {
                    println!("No StateCoin data for given key.");
                    return
                }
                println!("\nStateChain ID {}", recovery_info[0].statechain_id);
                println!("\nShared key ID {}", recovery_info[0].shared_key_id);
                println!("\nBackup tx: {} \n", recovery_info[0].tx_hex);
            }
        } else if matches.is_present("coins-info") {
            let coins_info: CoinValueInfo =
                match query_wallet_daemon(DaemonRequest::GetCoinsInfo).unwrap() {
                    DaemonResponse::Value(val) => serde_json::from_str(&val).unwrap(),
                    DaemonResponse::Error(e) => panic!("{}", e.to_string()),
                    DaemonResponse::None => panic!("None value returned."),
                };
            println!("Coin amounts histogram: \n\n{:?}", coins_info);
        } else if matches.is_present("groups-info") {
            let swap_groups: HashMap<String,u64> =
                match query_wallet_daemon(DaemonRequest::GetSwapGroups).unwrap() {
                    DaemonResponse::Value(val) => serde_json::from_str(&val).unwrap(),
                    DaemonResponse::Error(e) => panic!("{}", e.to_string()),
                    DaemonResponse::None => panic!("None value returned."),
                };
            println!("Swap group registrations: \n\n{:?}", swap_groups);
        }
    }
}
