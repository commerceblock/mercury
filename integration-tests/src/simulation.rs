//! Simulation
//!
//! Test spawns a server and randomly performs deposits, transfers, withdrawals and batch-transfers.

extern crate server_lib;
extern crate client_lib;
extern crate shared_lib;
extern crate bitcoin;

use crate::{run_transfer, gen_wallet_with_deposit, spawn_server};
use client_lib::wallet::wallet::Wallet;
use rand::Rng;
use std::str::FromStr;

pub fn run_simulation() {
    spawn_server();
    
    // Begin with a few clients
    let mut wallets = vec!();
    new_deposit(&mut wallets);
    new_deposit(&mut wallets);
    new_deposit(&mut wallets);


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

    // Pick random state chain to transfer
    let state_chain_index =  rand::thread_rng().gen_range(0, state_chains_info.0.len());
    let shared_key_id = state_chains_info.0.get(state_chain_index).unwrap();

    run_transfer(
        wallets,
        sender_index,
        receiver_index,
        &shared_key_id
    );
}

#[cfg(test)]
mod tests {

    use super::run_simulation;

    #[test]
    fn run() {
        run_simulation();
    }

}
