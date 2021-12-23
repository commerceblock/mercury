pub mod batch_transfer_test;
pub mod simulation;
pub mod test;

extern crate bitcoin;
extern crate floating_duration;
extern crate rand;
extern crate rocket;
extern crate stoppable_thread;
extern crate uuid;

extern crate curv;
extern crate monotree;

extern crate client_lib;
extern crate server_lib;
extern crate shared_lib;
extern crate nix;

#[cfg(test)]
extern crate mockito;

use client_lib::state_entity::transfer::TransferFinalizeData;
use client_lib::wallet::wallet::Wallet;
use client_lib::*;

use bitcoin::{PublicKey, Transaction};
use floating_duration::TimeFormat;
use monotree::database::{Database as monotreeDatabase, MemoryDB};
use rocket::error::LaunchError;
use server_lib::{server, Database, MockDatabase, PGDatabase};
use shared_lib::{
    commitment::make_commitment,
    mainstay,
    state_chain::StateChainSig,
    structs::{BatchData, PrepareSignTxMsg, SCEAddress},
    util::FEE,
};

use std::env;
use std::error;
use std::fmt;
use std::sync::mpsc::RecvTimeoutError;
use std::thread;
use std::time::Instant;
use uuid::Uuid;
use wallet::wallet::DEFAULT_TEST_WALLET_LOC;

#[cfg(test)]
#[macro_use]
extern crate serial_test;

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

pub trait SpawnServer {
    /// Spawn a StateChain Entity server in testing mode if there isn't one running already.
    /// Returns Ok(()) if a new server was spawned, otherwise returns an error.
    fn spawn_server(
        self,
        mainstay_config: Option<mainstay::MainstayConfig>,
        port: Option<u16>,
        mode: Option<String>
    ) -> thread::JoinHandle<SpawnError>;
}

impl SpawnServer for PGDatabase {
    /// Spawn a StateChain Entity server in testing mode if there isn't one running already.
    /// Returns Ok(()) if a new server was spawned, otherwise returns an error.
    fn spawn_server(
        self,
        mainstay_config: Option<mainstay::MainstayConfig>,
        port: Option<u16>,
        mode: Option<String>
    ) -> thread::JoinHandle<SpawnError> {
        // Set enviroment variable to testing_mode=true to override Settings.toml
        env::set_var("MERC_TESTING_MODE", "true");
        match port {
            Some(p) => env::set_var("MERC_ROCKET_PORT", &p.to_string()[..]),
            None => ()
        };

        match mode {
            Some(m) => env::set_var("MERC_MODE", &m[..]),
            None => ()
        };
        
        // Rocket server is blocking, so we spawn a new thread.
        let handle = thread::spawn(|| {
            match server::get_server::<Self, PGDatabase>(
                mainstay_config,
                self,
                PGDatabase::get_new(),
            ) {
                Ok(s) => {
                    let try_launch = s.launch();
                    let _ = try_launch.kind(); // LaunchError needs to be accessed here for this to work. Be carfeul modifying this code.
                    try_launch.into()
                }
                Err(_) => SpawnError::GetServer,
            }
        });
        std::thread::sleep(std::time::Duration::from_secs(7));
        handle
    }
}

impl SpawnServer for MockDatabase {
    /// Spawn a StateChain Entity server in testing mode if there isn't one running already.
    /// Returns Ok(()) if a new server was spawned, otherwise returns an error.
    fn spawn_server(
        self,
        mainstay_config: Option<mainstay::MainstayConfig>,
        _port: Option<u16>,
        _mode: Option<String>
    ) -> thread::JoinHandle<SpawnError> {
        // Set enviroment variable to testing_mode=true to override Settings.toml
        env::set_var("MERC_TESTING_MODE", "true");

        // Rocket server is blocking, so we spawn a new thread.
        let handle = thread::spawn(|| {
            let db_smt = MemoryDB::new("");
            match server::get_server::<Self, MemoryDB>(mainstay_config, self, db_smt) {
                Ok(s) => {
                    let try_launch = s.launch();
                    let _ = try_launch.kind(); // LaunchError needs to be accessed here for this to work. Be carfeul modifying this code.
                    try_launch.into()
                }
                Err(_) => SpawnError::GetServer,
            }
        });
        std::thread::sleep(std::time::Duration::from_secs(5));
        handle
    }
}

/// Create a wallet with generic seed and generate some addresses
#[cfg(test)]
fn gen_wallet(conductor_port: Option<u16>) -> Wallet {
    gen_wallet_with_seed(&[0xcd; 32], conductor_port)
}

/// Create a wallet with a specified seed and generate some addresses
#[cfg(test)]
fn gen_wallet_with_seed(seed: &[u8], conductor_port: Option<u16>) -> Wallet {
    // let electrum = ElectrumxClient::new("dummy").unwrap();
    let conductor_endpoint = format!("http://localhost:{}",conductor_port.unwrap_or(8000));
    let mut wallet = Wallet::new(
        &seed,
        &"regtest".to_string(),
        DEFAULT_TEST_WALLET_LOC,
        ClientShim::new("http://localhost:8000".to_string(), None, None),
        ClientShim::new(conductor_endpoint, None, None),
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
        DEFAULT_TEST_WALLET_LOC,
        ClientShim::new("http://localhost:8000".to_string(), None, None),
        ClientShim::new("http://localhost:8000".to_string(), None, None),
    );

    let _ = wallet.keys.get_new_address();
    let _ = wallet.keys.get_new_address();

    run_deposit(&mut wallet, &amount);

    wallet
}

/// Run deposit on a wallet for some amount
/// Returns shared_key_id, statechain_id, funding txid, signed backup tx, back up transacion data and proof_key
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
pub fn run_withdraw(wallet: &mut Wallet, statechain_id: &Uuid) -> (String, Uuid, u64) {
    let start = Instant::now();
    let resp = state_entity::withdraw::withdraw(wallet, &statechain_id, &FEE).unwrap();
    println!("(Withdraw Took: {})", TimeFormat(start.elapsed()));
    
    resp
}

/// Run withdraw init of shared key ID and fee given
pub fn run_withdraw_init(wallet: &mut Wallet, statechain_id: &Uuid, fee: &u64) 
    -> (Uuid,bitcoin::Address, bitcoin::Transaction, u64) {
    let start = Instant::now();
    let resp = state_entity::withdraw::withdraw_init(wallet, &statechain_id, fee).unwrap();
    println!("(Withdraw Init Took: {})", TimeFormat(start.elapsed()));
    
    resp
}

/// Run withdraw confirm 
pub fn run_withdraw_confirm(wallet: &mut Wallet, shared_key_id: &Uuid, 
    address: &bitcoin::Address, tx_signed: &bitcoin::Transaction) 
    -> String {
    let start = Instant::now();
    let resp = state_entity::withdraw::withdraw_confirm(wallet, shared_key_id,
        address, tx_signed).unwrap();
    println!("(Withdraw Init Took: {})", TimeFormat(start.elapsed()));
    
    resp
}

/// Run withdraw of shared key IDs given
pub fn run_batch_withdraw(wallet: &mut Wallet, statechain_ids: &Vec::<Uuid>) -> (String, Vec::<Uuid>, u64) {
    let start = Instant::now();
    let resp = state_entity::withdraw::batch_withdraw(wallet, statechain_ids, &FEE).unwrap();
    println!("(Withdraw Took: {})", TimeFormat(start.elapsed()));
    
    resp
}

/// Run a transfer between two wallets. Input vector of wallets with sender and receiver indexes in vector.
/// Return new shared key id.
pub fn run_transfer(
    wallets: &mut Vec<Wallet>,
    sender_index: usize,
    receiver_index: usize,
    receiver_addr: &SCEAddress,
    statechain_id: &Uuid
) -> Uuid {
    run_transfer_repeat_keygen(wallets, sender_index, receiver_index,
        receiver_addr, statechain_id, 0)
}

/// Run a transfer between two wallets. Input vector of wallets with sender and receiver indexes in vector.
/// Return new shared key id.
pub fn run_transfer_repeat_keygen(
    wallets: &mut Vec<Wallet>,
    sender_index: usize,
    receiver_index: usize,
    receiver_addr: &SCEAddress,
    statechain_id: &Uuid,
    keygen_1_reps: u32
) -> Uuid {

    let start = Instant::now();
    let mut tranfer_sender_resp = state_entity::transfer::transfer_sender(
        &mut wallets[sender_index],
        statechain_id,
        receiver_addr.clone(),
    )
    .unwrap();

    let transfer_msg = state_entity::transfer::transfer_get_msg_addr(&mut wallets[receiver_index],&tranfer_sender_resp.statechain_sig.data);

    assert_eq!(tranfer_sender_resp,transfer_msg.unwrap()[0]);

    let tfd = state_entity::transfer::transfer_receiver_repeat_keygen(
        &mut wallets[receiver_index],
        &mut tranfer_sender_resp,
        &None,
        keygen_1_reps
    )
    .unwrap();
    let new_shared_key_id = tfd.new_shared_key_id;

    println!("(Transfer Took: {})", TimeFormat(start.elapsed()));

    return new_shared_key_id;
}


/// Run a transfer with commitments between two wallets. Input vector of wallets with sender and receiver indexes in vector.
/// Return new shared key id, commitments and nonces.
pub fn run_transfer_with_commitment(
    wallets: &mut Vec<Wallet>,
    participant_statechain_ids: &Vec<Uuid>,
    sender_index: usize,
    sender_statechain_id: &Uuid,
    receiver_index: usize,
    receiver_statechain_id: &Uuid,
    _funding_txid: &String,
    batch_id: &Uuid,
) -> (TransferFinalizeData, String, [u8; 32]) {
    let start = Instant::now();

    let receiver_addr = wallets[receiver_index]
        .get_new_state_entity_address()
        .unwrap();

    let mut tranfer_sender_resp = state_entity::transfer::transfer_sender(
        &mut wallets[sender_index],
        sender_statechain_id,
        receiver_addr.clone(),
    )
    .unwrap();

    let mut commitment_data = String::from(&receiver_statechain_id.to_string());
    let mut ids_sorted = participant_statechain_ids.clone();
    ids_sorted.sort();
    for id in ids_sorted{
        commitment_data.push_str(&id.to_string());
    }

    let (commitment, nonce) = make_commitment(&commitment_data);

    let transfer_finalized_data = state_entity::transfer::transfer_receiver(
        &mut wallets[receiver_index],
        &mut tranfer_sender_resp,
        &Some(BatchData {
            id: batch_id.clone(),
            commitment: commitment.clone(),
        }),
    )
    .unwrap();

    println!("(Transfer Took: {})", TimeFormat(start.elapsed()));

    return (transfer_finalized_data, commitment, nonce);
}

/// Run a batch transfer. Input wallets, (sender-receiver) mapping, corresponding funding_txids, shared_key_ids and statechain_ids.
/// Return batch id, finalize datas, commitments, nonces and state chain signatures.
pub fn run_batch_transfer(
    wallets: &mut Vec<Wallet>,      // vec of all wallets
    swap_map: &Vec<(usize, usize)>, // mapping of sender -> receiver
    funding_txids: &Vec<String>,
    statechain_ids: &Vec<Uuid>,
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
                &statechain_ids[i], // state chain id
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
            &statechain_ids,
            i,
            &statechain_ids[i], // state chian id
            receiver_index,
            &statechain_ids[receiver_index], // state chian id
            &funding_txids[i],                // funding txid
            &batch_id,
        );
        transfer_finalized_datas.push(transfer_finalized_data);
        nonces.push(nonce);
        commitments.push(commitment);
    }

    // Check complete
    let status_api =
        state_entity::api::get_transfer_batch_status(&wallets[0].client_shim, &batch_id);

    match status_api {
        Ok(v) => {
            assert_eq!(v.finalized, true, "{:?}", &v);
            assert_eq!(v.state_chains.len(), transfer_finalized_datas.len());
        },
        Err(e) => assert!(false, "Error: {}",e),
    }

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
        dbg!("transfer receiver finalize: ", i);
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
    statechain_ids: &Vec<Uuid>,
    swap_map: &Vec<(usize, usize)>, // mapping of sender -> receiver
) {
    // Check amounts have correctly rotated
    for i in 0..swap_map.len() {
        let (_, wallet_sc_ids, bals,_) = wallets[swap_map[i].1].get_state_chains_info().unwrap();
        // check state chain id is in wallets shared keys
        let index = wallet_sc_ids
            .iter()
            .position(|r| r == &statechain_ids[swap_map[i].0]);
        assert!(index.is_some());
        // check amount of state chain at index is correctß
        assert!(bals[index.unwrap()].confirmed == amounts[swap_map[i].0])
    }
}

pub fn reset_data(client: &ClientShim) -> Result<()> {
    state_entity::api::reset_data(client)?;
    Ok(())
}

pub fn reset_inram_data(client: &ClientShim) -> Result<()> {
    state_entity::api::reset_inram_data(client)?;
    Ok(())
}

pub fn start_server(port: Option<u16>, mode: Option<String>) -> thread::JoinHandle<SpawnError> {
    PGDatabase::get_new().spawn_server(None, port, mode)
}

