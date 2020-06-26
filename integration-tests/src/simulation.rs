//! Simulation
//!
//! Test spawns a server and randomly performs deposits, transfers, withdrawals and batch-transfers.

extern crate server_lib;
extern crate client_lib;
extern crate shared_lib;
extern crate bitcoin;

use crate::{run_transfer, gen_wallet_with_deposit, spawn_server};
use client_lib::{state_entity, wallet::wallet::Wallet};
use rand::Rng;
use std::str::FromStr;

pub fn run_simulation() {
    spawn_server();

    // Begin with a few clients
    let mut wallets = vec!();
    new_deposit(&mut wallets);
    new_deposit(&mut wallets);
    new_deposit(&mut wallets);

    let mut loops = 0;
    loop {
        let rand = rand::thread_rng().gen_range(0, 3);
        match rand {
            0 => new_deposit(&mut wallets),
            1 => random_transfer(&mut wallets),
            2 => random_withdraw(&mut wallets),
            _ => {}
        }

        loops+=1;
        if loops < 10 {
            break;
        }
    }
}

/// Generate random 1000 <= amount <= 20000
pub fn random_amount() -> u64 {
    u64::from_str(&format!("{}000",rand::thread_rng().gen_range(1, 21))).unwrap()
}

pub fn new_deposit(wallets: &mut Vec<Wallet>) {
    wallets.push(gen_wallet_with_deposit(random_amount()))
}

pub fn random_transfer(wallets: &mut Vec<Wallet>) {
    let sender_index = rand::thread_rng().gen_range(0, wallets.len());
    let receiver_index = rand::thread_rng().gen_range(0, wallets.len());

    // Get sender wallets available state chains
    let state_chains_info = wallets[sender_index].get_state_chains_info();
    if state_chains_info.0.len() == 0 {
        println!("Transfer failed - no funds in wallet {}",sender_index);
        return
    }
    // Pick random state chain to transfer
    let state_chain_index =  rand::thread_rng().gen_range(0, state_chains_info.0.len());
    let shared_key_id = state_chains_info.0.get(state_chain_index).unwrap();

    println!("Transfer {} between {} and {}.",state_chains_info.2.get(state_chain_index).unwrap().confirmed,sender_index,receiver_index);

    let new_shared_key_id = run_transfer(
        wallets,
        sender_index,
        receiver_index,
        &shared_key_id
    );

    // check shared key is marked spent in sender and unspent in sender
    assert!(!wallets[sender_index].get_shared_key(shared_key_id).unwrap().unspent);
    assert!(wallets[receiver_index].get_shared_key(&new_shared_key_id).unwrap().unspent);
}

pub fn random_withdraw(wallets: &mut Vec<Wallet>) {
    let wallet_index = rand::thread_rng().gen_range(0, wallets.len());

    // Get random wallet owned state chains
    let state_chains_info = wallets[wallet_index].get_state_chains_info();
    let state_chain_index = rand::thread_rng().gen_range(0, state_chains_info.0.len());
    let shared_key_id = state_chains_info.0.get(state_chain_index).unwrap();

    println!("Withdraw {} from wallet {}.",state_chains_info.2.get(state_chain_index).unwrap().confirmed,wallet_index);

    state_entity::withdraw::withdraw(&mut wallets[wallet_index], &shared_key_id).unwrap();
    // Check marked spent in wallet
    assert!(!wallets[wallet_index].get_shared_key(&shared_key_id).unwrap().unspent);
}


#[cfg(test)]
mod tests {

    use super::run_simulation;

    #[allow(dead_code)]
    // #[test]
    fn run() {
        run_simulation();
    }

}
