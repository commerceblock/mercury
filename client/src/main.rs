use shared_lib::structs::{SCEAddress, TransferMsg3, PrepareSignTxMsg, StateChainDataAPI, StateEntityFeeInfoAPI};
use client_lib::{state_entity::transfer::TransferFinalizeData, daemon::{make_unix_conn_call, DaemonRequest, DaemonResponse}};

use bitcoin::{Transaction, consensus};
use bitcoin::util::key::PublicKey;
use std::str::FromStr;
use uuid::Uuid;
use clap::{load_yaml, App};
use electrumx_client::response::{GetListUnspentResponse, GetBalanceResponse};

fn main() {
    let yaml = load_yaml!("../cli.yml");
    let matches = App::from_yaml(yaml).get_matches();
    let _ = env_logger::try_init();

    if let Some(_matches) = matches.subcommand_matches("wallet") {
        if matches.is_present("new-address") {
            let address: String = match make_unix_conn_call(DaemonRequest::GenAddressBTC).unwrap() {
                DaemonResponse::Value(val) => val,
                DaemonResponse::Error(e) => panic!(e.to_string()),
                DaemonResponse::None => panic!("None value returned.")
            };

            println!(
                "\nAddress: [{}]\n",
                address
            );
        } else if matches.is_present("se-addr") {
            if let Some(matches) = matches.subcommand_matches("se-addr") {
                let funding_txid = matches.value_of("txid").unwrap().to_string();
                let address: String = match make_unix_conn_call(DaemonRequest::GenAddressSE(funding_txid)).unwrap() {
                    DaemonResponse::Value(val) => val,
                    DaemonResponse::Error(e) => panic!(e.to_string()),
                    DaemonResponse::None => panic!("None value returned.")
                };

                println!(
                    "\nAddress: {:?}\n",
                    address
                );
            }
        } else if matches.is_present("get-balance") {
            let (addrs, balances): (Vec<bitcoin::Address>, Vec<GetBalanceResponse>)
                = match make_unix_conn_call(DaemonRequest::GetWalletBalance).unwrap() {
                    DaemonResponse::Value(val) => serde_json::from_str(&val).unwrap(),
                    DaemonResponse::Error(e) => panic!(e.to_string()),
                    DaemonResponse::None => panic!("None value returned.")
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
            let (_, state_chain_ids, bals): (Vec<Uuid>, Vec<Uuid>, Vec<GetBalanceResponse>)
                = match make_unix_conn_call(DaemonRequest::GetStateChainsInfo).unwrap() {
                    DaemonResponse::Value(val) => serde_json::from_str(&val).unwrap(),
                    DaemonResponse::Error(e) => panic!(e.to_string()),
                    DaemonResponse::None => panic!("None value returned.")
            };
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
            let (_, unspent_list): (Vec<bitcoin::Address>, Vec<Vec<GetListUnspentResponse>>)
                = match make_unix_conn_call(DaemonRequest::GetListUnspent).unwrap() {
                    DaemonResponse::Value(val) => serde_json::from_str(&val).unwrap(),
                    DaemonResponse::Error(e) => panic!(e.to_string()),
                    DaemonResponse::None => panic!("None value returned.")
            };
            let mut hashes: Vec<String> = vec![];
            for unspent_for_addr in unspent_list {
                for unspent in unspent_for_addr {
                    hashes.push(unspent.tx_hash);
                }
            }
            println!(
                "\nUnspent tx hashes: \n{}\n",
                hashes.join("\n")
            );
        } else if matches.is_present("deposit") {
            if let Some(matches) = matches.subcommand_matches("deposit") {
                let amount = u64::from_str(matches.value_of("amount").unwrap()).unwrap();
                let (_, state_chain_id, funding_txid, tx_b, _, _): (Uuid, Uuid, String, Transaction, PrepareSignTxMsg, PublicKey)
                    = match make_unix_conn_call(DaemonRequest::Deposit(amount)).unwrap() {
                        DaemonResponse::Value(val) => serde_json::from_str(&val).unwrap(),
                        DaemonResponse::Error(e) => panic!(e.to_string()),
                        DaemonResponse::None => panic!("None value returned.")
                };
                println!("\nDeposited {} satoshi's. \nState Chain ID: {}", amount, state_chain_id);
                println!("\nFunding Txid: {}", funding_txid);
                println!("\nBackup Transaction hex: {}",hex::encode(consensus::serialize(&tx_b)));
            }
        } else if matches.is_present("withdraw") {
            if let Some(matches) = matches.subcommand_matches("withdraw") {
                let state_chain_id = Uuid::from_str(matches.value_of("id").unwrap()).unwrap();
                let (txid, state_chain_id, amount): (String, Uuid, u64)
                    = match make_unix_conn_call(DaemonRequest::Withdraw(state_chain_id)).unwrap() {
                        DaemonResponse::Value(val) => serde_json::from_str(&val).unwrap(),
                        DaemonResponse::Error(e) => panic!(e.to_string()),
                        DaemonResponse::None => panic!("None value returned.")
                };
                println!("\nWithdrawn {} satoshi's. \nFrom StateChain ID: {}",amount, state_chain_id);
                println!("\nWithdraw Txid: {}", txid);
            }
        } else if matches.is_present("transfer-sender") {
            if let Some(matches) = matches.subcommand_matches("transfer-sender") {
                let state_chain_id = Uuid::from_str(matches.value_of("id").unwrap()).unwrap();
                let receiver_addr: SCEAddress =
                    serde_json::from_str(matches.value_of("addr").unwrap()).unwrap();
                let transfer_msg3: TransferMsg3
                    = match make_unix_conn_call(DaemonRequest::TransferSender(state_chain_id, receiver_addr)).unwrap() {
                        DaemonResponse::Value(val) => serde_json::from_str(&val).unwrap(),
                        DaemonResponse::Error(e) => panic!(e.to_string()),
                        DaemonResponse::None => panic!("None value returned.")
                };
                println!("\nTransfer initiated for StateChain ID: {}.",state_chain_id);
                println!("\nTransfer message: {:?}",serde_json::to_string(&transfer_msg3).unwrap());
            }
        } else if matches.is_present("transfer-receiver") {
            if let Some(matches) = matches.subcommand_matches("transfer-receiver") {
                let transfer_msg3: TransferMsg3 = serde_json::from_str(matches.value_of("message").unwrap()).unwrap();
                let finalized_data: TransferFinalizeData
                    = match make_unix_conn_call(DaemonRequest::TransferReceiver(transfer_msg3)).unwrap() {
                        DaemonResponse::Value(val) => serde_json::from_str(&val).unwrap(),
                        DaemonResponse::Error(e) => panic!(e.to_string()),
                        DaemonResponse::None => panic!("None value returned.")
                };
                println!("\nTransfer complete for StateChain ID: {}.", finalized_data.state_chain_id);
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
                let state_chain_id = Uuid::from_str(matches.value_of("id").unwrap()).unwrap();
                let state_chain_info: StateChainDataAPI
                    = match make_unix_conn_call(DaemonRequest::GetStateChain(state_chain_id)).unwrap() {
                        DaemonResponse::Value(val) => serde_json::from_str(&val).unwrap(),
                        DaemonResponse::Error(e) => panic!(e.to_string()),
                        DaemonResponse::None => panic!("None value returned.")
                };
                println!("\nStateChain with Id {} info: \n", state_chain_id);
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
            let fee_info: StateEntityFeeInfoAPI
                = match make_unix_conn_call(DaemonRequest::GetFeeInfo).unwrap() {
                    DaemonResponse::Value(val) => serde_json::from_str(&val).unwrap(),
                    DaemonResponse::Error(e) => panic!(e.to_string()),
                    DaemonResponse::None => panic!("None value returned.")
            };
            println!("State Entity fee info: \n\n{}", fee_info);
        }
    }
}
