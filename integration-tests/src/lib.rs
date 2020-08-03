pub mod batch_transfer_test;
pub mod simulation;
pub mod test;

use client_lib::state_entity::transfer::TransferFinalizeData;
use client_lib::wallet::wallet::Wallet;
use client_lib::*;

use bitcoin::{PublicKey, Transaction};
use floating_duration::TimeFormat;
use rocket;
use rocket::error::LaunchError;
use server_lib::server;
use shared_lib::{
    commitment::make_commitment,
    mocks::mock_electrum::MockElectrum,
    state_chain::StateChainSig,
    structs::{BatchData, PrepareSignTxMsg},
    mainstay
};
use std::error;
use std::fmt;
use std::sync::mpsc;
use std::sync::mpsc::RecvTimeoutError;
use std::time::Instant;
use std::{thread, time};
use uuid::Uuid;

#[cfg(test)]
#[macro_use]
extern crate serial_test;

extern crate stoppable_thread;

#[derive(Debug)]
pub enum SpawnError {
    GetServer,
    Launch(LaunchError),
    Timeout(RecvTimeoutError),
}

impl fmt::Display for SpawnError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SpawnError::GetServer => write!(f, "failed to initialize a new server"),
            SpawnError::Launch(ref e) => e.fmt(f),
            SpawnError::Timeout(ref e) => e.fmt(f),
        }
    }
}

impl error::Error for SpawnError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            SpawnError::GetServer => None,
            SpawnError::Launch(ref e) => Some(e),
            SpawnError::Timeout(ref e) => Some(e),
        }
    }
}

impl From<LaunchError> for SpawnError {
    fn from(err: LaunchError) -> SpawnError {
        SpawnError::Launch(err)
    }
}

impl From<RecvTimeoutError> for SpawnError {
    fn from(err: RecvTimeoutError) -> SpawnError {
        SpawnError::Timeout(err)
    }
}

/// Spawn a StateChain entity server in testing mode if there isn't one running already.
/// Returns Ok(()) if a new server was spawned, otherwise returns an error.
pub fn spawn_server(mainstay_config: Option<mainstay::Config>) -> Result<(), SpawnError> {
    let (tx, rx) = mpsc::channel::<SpawnError>();

    // Rocket server is blocking, so we spawn a new thread.
    thread::spawn(move || {
        tx.send({
            match server::get_server(true, mainstay_config) {
                Ok(s) => {
                    let try_launch = s.launch();
                    let _ = try_launch.kind(); // LaunchError needs to be accessed here for this to work. Be carfeul modifying this code.
                    try_launch.into()
                }
                Err(_) => SpawnError::GetServer,
            }
        })
    });

    //If we haven't received an error within 2 secs then assume server running.
    match rx.recv_timeout(time::Duration::from_millis(2000)) {
        Ok(e) => Err(e),
        Err(e) => match e {
            RecvTimeoutError::Timeout => Ok(()),
            RecvTimeoutError::Disconnected => Err(e.into()),
        },
    }
}

/// Create a wallet and generate some addresses
pub fn gen_wallet() -> Wallet {
    let mut wallet = Wallet::new(
        &[0xcd; 32],
        &"regtest".to_string(),
        ClientShim::new("http://localhost:8000".to_string(), None),
        Box::new(MockElectrum::new()),
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
        Box::new(MockElectrum::new()),
    );

    let _ = wallet.keys.get_new_address();
    let _ = wallet.keys.get_new_address();

    run_deposit(&mut wallet, &amount);

    wallet
}

/// Run deposit on a wallet for some amount
/// Returns shared_key_id, state_chain_id, funding txid, signed backup tx, back up transacion data and proof_key
pub fn run_deposit(
    wallet: &mut Wallet,
    amount: &u64,
) -> (Uuid, Uuid, String, Transaction, PrepareSignTxMsg, PublicKey) {
    let start = Instant::now();
    let resp = state_entity::deposit::deposit(wallet, amount).unwrap();
    println!("(Deposit Took: {})", TimeFormat(start.elapsed()));

    resp
}

/// Run confirm_proofs on a wallet
/// Returns Vec<shared_key_id> of the shared keys that remain unconfirmed
pub fn run_confirm_proofs(wallet: &mut Wallet) -> Vec<Uuid> {
    let start = Instant::now();
    let resp = state_entity::confirm_proofs::confirm_proofs(wallet).unwrap();
    println!("(Confirm Proofs Took: {})", TimeFormat(start.elapsed()));

    resp
}

/// Run withdraw of shared key ID given
pub fn run_withdraw(wallet: &mut Wallet, state_chain_id: &Uuid) -> (String, Uuid, u64) {
    let start = Instant::now();
    let resp = state_entity::withdraw::withdraw(wallet, &state_chain_id).unwrap();
    println!("(Withdraw Took: {})", TimeFormat(start.elapsed()));

    resp
}

/// Run a transfer between two wallets. Input vector of wallets with sender and receiver indexes in vector.
/// Return new shared key id.
pub fn run_transfer(
    wallets: &mut Vec<Wallet>,
    sender_index: usize,
    receiver_index: usize,
    state_chain_id: &Uuid,
) -> Uuid {
    let funding_txid: String;
    {
        funding_txid = wallets[sender_index]
            .get_shared_key_by_state_chain_id(state_chain_id)
            .unwrap()
            .funding_txid
            .to_owned();
    }

    let receiver_addr = wallets[receiver_index]
        .get_new_state_entity_address(&funding_txid)
        .unwrap();

    let start = Instant::now();
    let tranfer_sender_resp = state_entity::transfer::transfer_sender(
        &mut wallets[sender_index],
        state_chain_id,
        receiver_addr.clone(),
    )
    .unwrap();

    let new_shared_key_id = state_entity::transfer::transfer_receiver(
        &mut wallets[receiver_index],
        &tranfer_sender_resp,
        &None,
    )
    .unwrap()
    .new_shared_key_id;

    println!("(Transfer Took: {})", TimeFormat(start.elapsed()));

    return new_shared_key_id;
}

/// Run a transfer with commitments between two wallets. Input vector of wallets with sender and receiver indexes in vector.
/// Return new shared key id, commitments and nonces.
pub fn run_transfer_with_commitment(
    wallets: &mut Vec<Wallet>,
    sender_index: usize,
    sender_state_chain_id: &Uuid,
    receiver_index: usize,
    receiver_state_chain_id: &Uuid,
    funding_txid: &String,
    batch_id: &Uuid,
) -> (TransferFinalizeData, String, [u8; 32]) {
    let start = Instant::now();

    let receiver_addr = wallets[receiver_index]
        .get_new_state_entity_address(&funding_txid)
        .unwrap();

    let tranfer_sender_resp = state_entity::transfer::transfer_sender(
        &mut wallets[sender_index],
        sender_state_chain_id,
        receiver_addr.clone(),
    )
    .unwrap();

    let (commitment, nonce) = make_commitment(&receiver_state_chain_id.to_string());

    let transfer_finalized_data = state_entity::transfer::transfer_receiver(
        &mut wallets[receiver_index],
        &tranfer_sender_resp,
        &Some(BatchData {
            id: batch_id.clone(),
            commitment: commitment.clone(),
        }),
    )
    .unwrap();

    println!("(Transfer Took: {})", TimeFormat(start.elapsed()));

    return (transfer_finalized_data, commitment, nonce);
}

/// Run a batch transfer. Input wallets, (sender-receiver) mapping, corresponding funding_txids, shared_key_ids and state_chain_ids.
/// Return batch id, finalize datas, commitments, nonces and state chain signatures.
pub fn run_batch_transfer(
    wallets: &mut Vec<Wallet>,      // vec of all wallets
    swap_map: &Vec<(usize, usize)>, // mapping of sender -> receiver
    funding_txids: &Vec<String>,
    state_chain_ids: &Vec<Uuid>,
) -> (
    Uuid,
    Vec<TransferFinalizeData>,
    Vec<String>,
    Vec<[u8; 32]>,
    Vec<StateChainSig>,
) {
    let num_state_chains = swap_map.len();

    // Create new batch transfer ID
    let batch_id = Uuid::new_v4();

    // Gen transfer-batch signatures for each state chain (each wallet's SCE coins)
    let mut transfer_sigs = vec![];
    for i in 0..num_state_chains {
        transfer_sigs.push(
            state_entity::transfer::transfer_batch_sign(
                &mut wallets[swap_map[i].0],
                &state_chain_ids[i], // state chain id
                &batch_id,
            )
            .unwrap(),
        );
    }

    // Initiate batch-transfer protocol on SCE
    let transfer_batch_init = state_entity::transfer::transfer_batch_init(
        &wallets[0].client_shim,
        &transfer_sigs,
        &batch_id,
    );
    assert!(transfer_batch_init.is_ok());

    // Perform transfers
    let mut transfer_finalized_datas = vec![];
    let mut commitments = vec![];
    let mut nonces = vec![];
    for i in 0..num_state_chains {
        let receiver_index = i + 1 % num_state_chains - 1;
        let (transfer_finalized_data, commitment, nonce) = run_transfer_with_commitment(
            wallets,
            i,
            &state_chain_ids[i], // state chian id
            receiver_index,
            &state_chain_ids[receiver_index], // state chian id
            &funding_txids[i],                // funding txid
            &batch_id,
        );
        transfer_finalized_datas.push(transfer_finalized_data);
        nonces.push(nonce);
        commitments.push(commitment);
    }

    // Check all marked true (= complete)
    let status_api =
        state_entity::api::get_transfer_batch_status(&wallets[0].client_shim, &batch_id);
    let mut state_chains_copy = status_api.unwrap().state_chains;
    state_chains_copy.retain(|_, &mut v| v == false);
    assert_eq!(state_chains_copy.len(), 0);

    (
        batch_id,
        transfer_finalized_datas,
        commitments,
        nonces,
        transfer_sigs,
    )
}

/// Finalize transfers involved in a batch.
/// Input wallets, (sender-receiver) mapping and transfer finalize data.
pub fn finalize_batch_transfer(
    wallets: &mut Vec<Wallet>,
    swap_map: &Vec<(usize, usize)>, // mapping of sender -> receiver
    transfer_finalized_datas: Vec<TransferFinalizeData>,
) {
    for i in 0..swap_map.len() {
        let _ = state_entity::transfer::transfer_receiver_finalize(
            &mut wallets[swap_map[i].1],
            transfer_finalized_datas[swap_map[i].0].clone(),
        )
        .unwrap();
    }
}

/// Function verifies state chains and amounts have transferred according to swap_map after a batch transfer is finalized.
pub fn batch_transfer_verify_amounts(
    wallets: &mut Vec<Wallet>,
    amounts: &Vec<u64>,
    state_chain_ids: &Vec<Uuid>,
    swap_map: &Vec<(usize, usize)>, // mapping of sender -> receiver
) {
    // Check amounts have correctly rotated
    for i in 0..swap_map.len() {
        let (_, wallet_sc_ids, bals) = wallets[swap_map[i].1].get_state_chains_info();
        // check state chain id is in wallets shared keys
        let index = wallet_sc_ids
            .iter()
            .position(|r| r == &state_chain_ids[swap_map[i].0]);
        assert!(index.is_some());
        // check amount of state chain at index is correctß
        assert!(bals[index.unwrap()].confirmed == amounts[swap_map[i].0])
    }
}
