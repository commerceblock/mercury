pub mod test;
pub mod batch_transfer_test;
pub mod simulation;

use client_lib::*;
use client_lib::wallet::wallet::Wallet;
use client_lib::state_entity::transfer::TransferFinalizeData;

use server_lib::server;
use shared_lib::{
    mocks::mock_electrum::MockElectrum,
    structs::{BatchData, PrepareSignTxMsg}, commitment::make_commitment, state_chain::StateChainSig};
use rand::random;
use bitcoin::{Transaction, PublicKey};
use std::{thread, time};
use std::time::Instant;
use floating_duration::TimeFormat;

/// Spawn a fresh StateChain entity server
pub fn spawn_server() {
    // Rocket server is blocking, so we spawn a new thread.
    thread::spawn(move || {
        server::get_server().launch();
    });

    let five_seconds = time::Duration::from_millis(2000);
    thread::sleep(five_seconds);
}

/// Create a wallet and generate some addresses
pub fn gen_wallet() -> Wallet {
    let mut wallet = Wallet::new(
        &[0xcd; 32],
        &"regtest".to_string(),
        ClientShim::new("http://localhost:8000".to_string(), None),
        Box::new(MockElectrum::new())
    );

    let _ = wallet.keys.get_new_address();
    let _ = wallet.keys.get_new_address();

    wallet
}

/// Create a wallet, generate some addresses and make deposit to SCE
pub fn gen_wallet_with_deposit(amount: u64) -> Wallet {
    let mut wallet = Wallet::new(
        &[0xcd; 32],
        &"regtest".to_string(),
        ClientShim::new("http://localhost:8000".to_string(), None),
        Box::new(MockElectrum::new())
    );

    let _ = wallet.keys.get_new_address();
    let _ = wallet.keys.get_new_address();

    run_deposit(&mut wallet, &amount);

    wallet
}

/// Run deposit on a wallet for some amount
/// Returns shared_key_id, state_chain_id, funding txid, signed backup tx, back up transacion data and proof_key
pub fn run_deposit(wallet: &mut Wallet, amount: &u64) -> (String, String, String, Transaction, PrepareSignTxMsg, PublicKey)  {
    let start = Instant::now();
    let resp = state_entity::deposit::deposit(
        wallet,
        amount
    ).unwrap();
    println!("(Deposit Took: {})", TimeFormat(start.elapsed()));

    resp
}

/// Run withdraw of shared key ID given
pub fn run_withdraw(wallet: &mut Wallet, shared_key_id: &String) -> (String, String, u64) {
    let start = Instant::now();
    let resp = state_entity::withdraw::withdraw(wallet, &shared_key_id).unwrap();
    println!("(Withdraw Took: {})", TimeFormat(start.elapsed()));

    resp
}

/// Run a transfer between two wallets. Input vector of wallets with sender and receiver indexes in vector.
/// Return new shared key id.
pub fn run_transfer(wallets: &mut Vec<Wallet>, sender_index: usize, receiver_index: usize, shared_key_id: &String) -> String {

    let (_, funding_txid, _, _, _) = wallets[sender_index].get_shared_key_info(shared_key_id).unwrap();
    let receiver_addr = wallets[receiver_index].get_new_state_entity_address(&funding_txid).unwrap();

    let start = Instant::now();
    let tranfer_sender_resp =
        state_entity::transfer::transfer_sender(
            &mut wallets[sender_index],
            shared_key_id,
            receiver_addr.clone(),
    ).unwrap();

    let new_shared_key_id  =
        state_entity::transfer::transfer_receiver(
            &mut wallets[receiver_index],
            &tranfer_sender_resp,
            &None
        ).unwrap().new_shared_key_id;

    println!("(Transfer Took: {})", TimeFormat(start.elapsed()));

    return new_shared_key_id;
}

/// Run a transfer with commitments between two wallets. Input vector of wallets with sender and receiver indexes in vector.
/// Return new shared key id, commitments and nonces.
pub fn run_transfer_with_commitment(
    wallets: &mut Vec<Wallet>,
    sender_index: usize,
    receiver_index: usize,
    funding_txid: &String,
    shared_key_id: &String,
    state_chain_id: &String,
    batch_id: &String
) -> (TransferFinalizeData, String, [u8;32]) {
    let start = Instant::now();

    let receiver_addr = wallets[receiver_index].get_new_state_entity_address(&funding_txid).unwrap();

    let tranfer_sender_resp =
        state_entity::transfer::transfer_sender(
            &mut wallets[sender_index],
            shared_key_id,
            receiver_addr.clone(),
    ).unwrap();

    let (commitment, nonce) = make_commitment(state_chain_id);

    let transfer_finalized_data =
        state_entity::transfer::transfer_receiver(
            &mut wallets[receiver_index],
            &tranfer_sender_resp,
            &Some(
                BatchData {
                    id: batch_id.clone(),
                    commitment: commitment.clone()
                })
            ).unwrap();

    println!("(Transfer Took: {})", TimeFormat(start.elapsed()));

    return (transfer_finalized_data, commitment, nonce)
}

/// Run a batch transfer. Input wallets, (sender-receiver) mapping, corresponding funding_txids, shared_key_ids and state_chain_ids.
/// Return batch id, finalize datas, commitments, nonces and state chain signatures.
pub fn run_batch_transfer(
    wallets: &mut Vec<Wallet>,      // vec of all wallets
    swap_map: &Vec<(usize,usize)>,   // mapping of sender -> receiver
    funding_txids: &Vec<String>,
    shared_key_ids: &Vec<String>,
    state_chain_ids: &Vec<String>,
) -> (String, Vec<TransferFinalizeData>, Vec<String>, Vec<[u8;32]>, Vec<StateChainSig>) {
    let num_state_chains = swap_map.len();

    // Create new batch transfer ID
    let batch_id = random::<u64>().to_string();

    // Gen transfer-batch signatures for each state chain (each wallet's SCE coins)
    let mut transfer_sigs = vec!();
    for i in 0..num_state_chains {
        transfer_sigs.push(
            state_entity::transfer::transfer_batch_sign(
                &mut wallets[swap_map[i].0],
                &state_chain_ids[i], // state chain id
                &batch_id
            ).unwrap()
        );
    }

    // Initiate batch-transfer protocol on SCE
    let transfer_batch_init = state_entity::transfer::transfer_batch_init(
        &wallets[0].client_shim,
        &transfer_sigs,
        &batch_id
    );
    assert!(transfer_batch_init.is_ok());

    // Perform transfers
    let mut transfer_finalized_datas = vec!();
    let mut commitments = vec!();
    let mut nonces = vec!();
    for i in 0..num_state_chains {
        let (transfer_finalized_data, commitment, nonce) = run_transfer_with_commitment(
            wallets,
            i,
            i+1%num_state_chains-1,
            &funding_txids[i], // funding txid
            &shared_key_ids[i], // shared key id
            &state_chain_ids[i],  // state chian id
            &batch_id
        );
        transfer_finalized_datas.push(transfer_finalized_data);
        nonces.push(nonce);
        commitments.push(commitment);
    }

    // Check all marked true (= complete)
    let status_api = state_entity::api::get_transfer_batch_status(&wallets[0].client_shim, &batch_id);
    let mut state_chains_copy = status_api.unwrap().state_chains;
    state_chains_copy.retain(|_, &mut v| v == false);
    assert_eq!(state_chains_copy.len(), 0);

    (batch_id, transfer_finalized_datas, commitments, nonces, transfer_sigs)
}

/// Finalize transfers involved in a batch.
/// Input wallets, (sender-receiver) mapping and transfer finalize data.
pub fn finalize_batch_transfer(
    wallets: &mut Vec<Wallet>,
    swap_map: &Vec<(usize,usize)>,   // mapping of sender -> receiver
    transfer_finalized_datas: Vec<TransferFinalizeData>) {
    for i in 0..swap_map.len() {
        let _ = state_entity::transfer::transfer_receiver_finalize(
            &mut wallets[swap_map[i].1],
            transfer_finalized_datas[swap_map[i].0].clone()
        ).unwrap();
    }
}

/// Function verifies state chains and amounts have transferred according to swap_map after a batch transfer is finalized.
pub fn batch_transfer_verify_amounts(
    wallets: &mut Vec<Wallet>,
    amounts: &Vec<u64>,
    state_chain_ids: &Vec<String>,
    swap_map: &Vec<(usize,usize)>   // mapping of sender -> receiver
) {
    // Check amounts have correctly rotated
    for i in 0..swap_map.len() {
        let (_, wallet_sc_ids, bals) = wallets[swap_map[i].1].get_state_chains_info();
        // check state chain id is in wallets shared keys
        let index = wallet_sc_ids.iter().position(|r| r == &state_chain_ids[swap_map[i].0]);
        assert!(index.is_some());
        // check amount of state chain at index is correctß
        assert!(bals[index.unwrap()].confirmed == amounts[swap_map[i].0])
    }
}
