#![allow(unused_parens)]
#![recursion_limit = "128"]
#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;
extern crate chrono;
extern crate config as config_rs;
extern crate uuid;
#[macro_use]
extern crate failure;
extern crate error_chain;
#[macro_use]
extern crate log;
extern crate bisetmap;
extern crate bitcoin;
extern crate cfg_if;
extern crate crypto;
extern crate hex;
extern crate jsonwebtoken as jwt;
extern crate log4rs;
extern crate rusoto_dynamodb;
extern crate serde_dynamodb;

extern crate curv;
extern crate electrumx_client;
extern crate kms;
extern crate monotree;
extern crate multi_party_ecdsa;
extern crate zk_paillier;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

#[cfg(test)]
#[macro_use]
extern crate serial_test;
#[cfg(test)]
extern crate floating_duration;
extern crate mockall;
#[cfg(test)]
extern crate mockito;

extern crate shared_lib;

pub mod config;
pub mod error;
pub mod protocol;
pub mod server;
pub mod storage;
pub mod watch;

pub type Result<T> = std::result::Result<T, error::SEError>;
pub type Hash = bitcoin::hashes::sha256d::Hash;

use rocket_contrib::databases::r2d2;
use rocket_contrib::databases::r2d2_postgres::PostgresConnectionManager;

use crate::protocol::transfer::TransferFinalizeData;
use crate::storage::db::Alpha;
use bitcoin::hashes::sha256d;
use bitcoin::Transaction;
use chrono::NaiveDateTime;
use curv::{FE, GE};
use kms::ecdsa::two_party::*;
use mockall::predicate::*;
use mockall::*;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one::Party1Private;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two};
use rocket_contrib::databases::postgres;
use shared_lib::{state_chain::*, structs::TransferMsg3, Root, structs::CoinValueInfo};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

#[database("postgres_w")]
pub struct DatabaseW(postgres::Connection);
#[database("postgres_r")]
pub struct DatabaseR(postgres::Connection);
/// Sparse Merkle Tree DB items
pub struct PGDatabaseSmt {
    pub cache: monotree::database::MemCache,
    pub batch_on: bool,
    pub batch: HashMap<Vec<u8>, Vec<u8>>,
    pub table_name: String,
}
/// POstgres database struct for Mercury. Contains database connection pool and SMT DB items.
pub struct PGDatabase {
    pub pool: Option<r2d2::Pool<PostgresConnectionManager>>,
    pub smt: PGDatabaseSmt,
}

use structs::*;

#[automock]
pub trait Database {
    fn get_new() -> Self;
    fn set_connection_from_config(&mut self, config: &crate::config::Config) -> Result<()>;
    fn set_connection(&mut self, url: &String) -> Result<()>;
    fn from_pool(pool: r2d2::Pool<PostgresConnectionManager>) -> Self;
    fn get_user_auth(&self, user_id: Uuid) -> Result<Uuid>;
    fn has_withdraw_sc_sig(&self, user_id: Uuid) -> Result<()>;
    fn get_coins_histogram(&self) -> Result<CoinValueInfo>;
    fn update_withdraw_sc_sig(&self, user_id: &Uuid, sig: StateChainSig) -> Result<()>;
    fn update_withdraw_tx_sighash(
        &self,
        user_id: &Uuid,
        sig_hash: Hash,
        tx: Transaction,
    ) -> Result<()>;
    fn update_sighash(&self, user_id: &Uuid, sig_hash: Hash) -> Result<()>;
    fn update_s1_pubkey(&self, user_id: &Uuid, pubkey: &GE) -> Result<()>;
    fn get_s1_pubkey(&self, user_id: &Uuid) -> Result<GE>;
    fn update_user_backup_tx(&self, user_id: &Uuid, tx: Transaction) -> Result<()>;
    fn get_user_backup_tx(&self, user_id: Uuid) -> Result<Transaction>;
    fn update_backup_tx(&self, statechain_id: &Uuid, tx: Transaction) -> Result<()>;
    fn get_withdraw_confirm_data(&self, user_id: Uuid) -> Result<WithdrawConfirmData>;
    /// Update root value in DB. Update root with ID or insert new DB item.
    fn root_update(&self, rt: &Root) -> Result<i64>;
    /// Insert a Root into root table
    fn root_insert(&self, root: Root) -> Result<u64>;
    /// Get Id of current Root
    fn root_get_current_id(&self) -> Result<i64>;
    /// Get root with given ID
    fn get_root(&self, id: i64) -> Result<Option<Root>>;
    /// Find the latest confirmed root
    fn get_confirmed_smt_root(&self) -> Result<Option<Root>>;
    fn get_statechain_id(&self, user_id: Uuid) -> Result<Uuid>;
    fn update_statechain_id(&self, user_id: &Uuid, statechain_id: &Uuid) -> Result<()>;
    fn get_statechain_amount(&self, statechain_id: Uuid) -> Result<StateChainAmount>;
    fn update_statechain_amount(
        &self,
        statechain_id: &Uuid,
        state_chain: StateChain,
        amount: u64,
    ) -> Result<()>;
    fn create_statechain(
        &self,
        statechain_id: &Uuid,
        user_id: &Uuid,
        state_chain: &StateChain,
        amount: &i64,
    ) -> Result<()>;
    fn get_statechain(&self, statechain_id: Uuid) -> Result<StateChain>;
    fn update_statechain_owner(
        &self,
        statechain_id: &Uuid,
        state_chain: StateChain,
        new_user_id: &Uuid,
    ) -> Result<()>;
    // Remove statechain_id from user session to signal end of session
    fn remove_statechain_id(&self, user_id: &Uuid) -> Result<()>;
    fn create_backup_transaction(
        &self,
        statechain_id: &Uuid,
        tx_backup: &Transaction,
    ) -> Result<()>;
    fn get_current_backup_txs(&self, locktime: i64) -> Result<Vec<BackupTxID>>;
    fn remove_backup_tx(&self, statechain_id: &Uuid) -> Result<()>;
    fn get_backup_transaction(&self, statechain_id: Uuid) -> Result<Transaction>;
    fn get_backup_transaction_and_proof_key(&self, user_id: Uuid) -> Result<(Transaction, String)>;
    fn get_proof_key(&self, user_id: Uuid) -> Result<String>;
    fn get_sc_locked_until(&self, statechain_id: Uuid) -> Result<NaiveDateTime>;
    fn update_locked_until(&self, statechain_id: &Uuid, time: &NaiveDateTime) -> Result<()>;
    fn get_transfer_batch_data(&self, batch_id: Uuid) -> Result<TransferBatchData>;
    fn has_transfer_batch_id(&self, batch_id: Uuid) -> bool;
    fn get_transfer_batch_id(&self, batch_id: Uuid) -> Result<Uuid>;
    fn get_punished_state_chains(&self, batch_id: Uuid) -> Result<Vec<Uuid>>;
    fn create_transfer(
        &self,
        statechain_id: &Uuid,
        statechain_sig: &StateChainSig,
        x1: &FE,
    ) -> Result<()>;
    fn update_transfer_msg(&self, statechain_id: &Uuid, msg: &TransferMsg3) -> Result<()>;
    fn get_transfer_msg(&self, statechain_id: &Uuid) -> Result<TransferMsg3>;
    fn create_transfer_batch_data(
        &self,
        batch_id: &Uuid,
        state_chains: Vec<Uuid>,
    ) -> Result<()>;
    fn get_transfer_data(&self, statechain_id: Uuid) -> Result<TransferData>;
    fn remove_transfer_data(&self, statechain_id: &Uuid) -> Result<()>;
    fn transfer_is_completed(&self, statechain_id: Uuid) -> bool;
    fn get_ecdsa_master(&self, user_id: Uuid) -> Result<Option<String>>;
    fn get_ecdsa_witness_keypair(
        &self,
        user_id: Uuid,
    ) -> Result<(party_one::CommWitness, party_one::EcKeyPair)>;
    fn get_ecdsa_s2(&self, user_id: Uuid) -> Result<FE>;
    fn update_keygen_first_msg(
        &self,
        user_id: &Uuid,
        key_gen_first_msg: &party_one::KeyGenFirstMsg,
        comm_witness: party_one::CommWitness,
        ec_key_pair: party_one::EcKeyPair,
    ) -> Result<()>;
    fn update_keygen_second_msg(
        &self,
        user_id: &Uuid,
        party2_public: GE,
        paillier_key_pair: party_one::PaillierKeyPair,
        party_one_private: party_one::Party1Private,
    ) -> Result<()>;
    fn init_ecdsa(&self, user_id: &Uuid) -> Result<u64>;
    fn get_ecdsa_party_1_private(&self, user_id: Uuid) -> Result<party_one::Party1Private>;
    fn get_ecdsa_keypair(&self, user_id: Uuid) -> Result<ECDSAKeypair>;
    fn update_punished(&self, batch_id: &Uuid, punished_state_chains: Vec<Uuid>) -> Result<()>;
    fn get_transfer_batch_start_time(&self, batch_id: &Uuid) -> Result<NaiveDateTime> ;
    fn get_batch_transfer_statechain_ids(&self, batch_id: &Uuid) -> Result<HashSet<Uuid>>;
    fn get_finalize_batch_data(&self, batch_id: Uuid) -> Result<TransferFinalizeBatchData>;
    fn get_sc_finalize_batch_data(
        &self,
        statechain_id: &Uuid
    ) -> Result<TransferFinalizeData>;
    fn update_finalize_batch_data(
        &self,
        statechain_id: &Uuid,
        finalized_data: &TransferFinalizeData,
    ) -> Result<()>;
    fn update_transfer_batch_finalized(&self, batch_id: &Uuid, b_finalized: &bool) -> Result<()>;
    fn get_statechain_owner(&self, statechain_id: Uuid) -> Result<StateChainOwner>;
    // Create DB entry for newly generated ID signalling that user has passed some
    // verification. For now use ID as 'password' to interact with state entity
    fn create_user_session(&self, user_id: &Uuid, auth: &String, proof_key: &String) -> Result<()>;
    // Create new UserSession to allow new owner to generate shared wallet
    fn transfer_init_user_session(
        &self,
        new_user_id: &Uuid,
        statechain_id: &Uuid,
        finalized_data: TransferFinalizeData,
    ) -> Result<()>;
    fn update_ecdsa_sign_first(
        &self,
        user_id: Uuid,
        eph_key_gen_first_message_party_two: party_two::EphKeyGenFirstMsg,
        eph_ec_key_pair_party1: party_one::EphEcKeyPair,
    ) -> Result<()>;

    fn get_ecdsa_sign_second_input(&self, user_id: Uuid) -> Result<ECDSASignSecondInput>;

    fn get_tx_withdraw(&self, user_id: Uuid) -> Result<Transaction>;
    fn update_tx_withdraw(&self, user_id: Uuid, tx: Transaction) -> Result<()>;
    fn reset(&self) -> Result<()>;
    fn init(&self) -> Result<()>;
    fn get_ecdsa_master_key_input(&self, user_id: Uuid) -> Result<ECDSAMasterKeyInput>;
    fn update_ecdsa_master(&self, user_id: &Uuid, master_key: MasterKey1) -> Result<()>;
    fn get_sighash(&self, user_id: Uuid) -> Result<sha256d::Hash>;
}

pub mod structs {
    use super::*;

    #[derive(Clone)]
    pub struct StateChainAmount {
        pub chain: StateChain,
        pub amount: i64,
    }

    pub struct TransferBatchData {
        pub state_chains: HashSet<Uuid>,
        pub punished_state_chains: Vec<Uuid>,
        pub start_time: NaiveDateTime,
        pub finalized: bool,
    }

    pub struct TransferFinalizeBatchData {
        pub finalized_data_vec: Vec<TransferFinalizeData>,
        pub start_time: NaiveDateTime,
    }

    #[derive(Clone, Debug)]
    pub struct BackupTxID {
        pub tx: Transaction,
        pub id: Uuid,
    }

    #[derive(Debug)]
    pub struct StateChainOwner {
        pub locked_until: NaiveDateTime,
        pub owner_id: Uuid,
        pub chain: StateChain,
    }

    pub struct WithdrawConfirmData {
        pub tx_withdraw: Transaction,
        pub withdraw_sc_sig: StateChainSig,
        pub statechain_id: Uuid,
    }

    pub struct TransferData {
        pub statechain_id: Uuid,
        pub statechain_sig: StateChainSig,
        pub x1: FE,
    }

    pub struct ECDSAKeypair {
        pub party_1_private: Party1Private,
        pub party_2_public: GE,
    }

    pub struct ECDSAFourthMessageInput {
        pub party_one_private: party_one::Party1Private,
        pub party_one_pdl_decommit: party_one::PDLdecommit,
        pub party_two_pdl_first_message: party_two::PDLFirstMessage,
        pub alpha: Alpha,
    }

    pub struct ECDSASignSecondInput {
        pub shared_key: MasterKey1,
        pub eph_ec_key_pair_party1: party_one::EphEcKeyPair,
        pub eph_key_gen_first_message_party_two: party_two::EphKeyGenFirstMsg,
    }

    pub struct ECDSAMasterKeyInput {
        pub party2_public: GE,
        pub paillier_key_pair: party_one::PaillierKeyPair,
        pub party_one_private: party_one::Party1Private,
        pub comm_witness: party_one::CommWitness,
    }
}
