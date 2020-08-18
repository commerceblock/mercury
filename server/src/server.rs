use super::protocol::*;
use crate::Database;

use crate::config::SMT_DB_LOC_TESTING;
use shared_lib::mainstay;

use crate::config::Config;
use rocket;
use rocket::{Rocket, Request, config::{Config as RocketConfig, Environment}};

use log::LevelFilter;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config as LogConfig, Root as LogRoot};
use log4rs::encode::pattern::PatternEncoder;

use mockall::*;
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct StateChainEntity<T: Database + Send + Sync + 'static> {
    pub config: Config,
    pub database: T,
}

impl<T: Database + Send + Sync + 'static> StateChainEntity<T> {
    pub fn load(mut db: T) -> Result<StateChainEntity<T>> {
        // Get config as defaults, Settings.toml and env vars
        let config_rs = Config::load()?;
        db.set_connection_from_config(&config_rs)?;

        Ok(Self {
            config: config_rs,
            database: db,
        })
    }
}

#[catch(500)]
fn internal_error() -> &'static str {
    "Internal server error"
}

#[catch(400)]
fn bad_request() -> &'static str {
    "Bad request"
}

#[catch(404)]
fn not_found(req: &Request) -> String {
    format!("Unknown route '{}'.", req.uri())
}

use std::marker::{Send, Sync};

/// Start Rocket Server. mainstay_config parameter overrides Settings.toml and env var settings.
/// If no db provided then use mock
pub fn get_server<T: Database + Send + Sync + 'static>
    (mainstay_config: Option<mainstay::MainstayConfig>,
        db: T) -> Result<Rocket> {

    let mut sc_entity = StateChainEntity::<T>::load(db)?;

    match mainstay_config {
        Some(c) => sc_entity.config.mainstay = Some(c),
        None => (),
    }
    //At this point the mainstay config should be set,
    //either in testing mode or specified in the settings file
    if sc_entity.config.mainstay.is_none() {
        panic!("expected mainstay config");
    }

    set_logging_config(&sc_entity.config.log_file);

    let rocket_config = get_rocket_config(&sc_entity.config);

    if sc_entity.config.testing_mode {
        info!("Server running in testing mode.");
        // Use test SMT DB
        sc_entity.config.smt_db_loc = SMT_DB_LOC_TESTING.to_string();
        // reset dbs
        if let Err(_) = sc_entity.database.reset(&sc_entity.config.smt_db_loc) {
            sc_entity.database.init()?;
        }
    }

    let rock = rocket::custom(rocket_config)
        .register(catchers![internal_error, not_found, bad_request])
        .mount(
            "/",
            routes![
                ping::ping,
                ecdsa::first_message,
                ecdsa::second_message,
                ecdsa::third_message,
                ecdsa::fourth_message,
                ecdsa::sign_first,
                ecdsa::sign_second,
                util::get_statechain,
                util::get_smt_root,
                //util::get_confirmed_smt_root,
                util::get_smt_proof,
                util::get_fees,
                util::prepare_sign_tx,
                util::get_transfer_batch_status,
                util::reset_test_dbs, // !!
                deposit::deposit_init,
                deposit::deposit_confirm,
                transfer::transfer_sender,
                transfer::transfer_receiver,
                transfer_batch::transfer_batch_init,
                transfer_batch::transfer_reveal_nonce,
                withdraw::withdraw_init,
                withdraw::withdraw_confirm
            ],
        )
        .manage(sc_entity);

    Ok(rock)
}

fn set_logging_config(log_file: &String) {
    if log_file.len() == 0 {
        let _ = env_logger::try_init();
    } else {
        // Write log to file
        let logfile = FileAppender::builder()
            .encoder(Box::new(PatternEncoder::new("{l} - {m}\n")))
            .build(log_file)
            .unwrap();
        let log_config = LogConfig::builder()
            .appender(Appender::builder().build("logfile", Box::new(logfile)))
            .build(
                LogRoot::builder()
                    .appender("logfile")
                    .build(LevelFilter::Info),
            )
            .unwrap();
        let _ = log4rs::init_config(log_config);
    }
}

fn get_rocket_config(config: &Config) -> RocketConfig {
    RocketConfig::build(Environment::Staging)
        .keep_alive(config.rocket.keep_alive.clone())
        .address(config.rocket.address.clone())
        .port(config.rocket.port.clone())
        .finalize()
        .unwrap()
}

/// Get postgres URL from env vars. Suffix can be "TEST", "W", or "R"
pub fn get_postgres_url(
    host: String,
    port: String,
    user: String,
    pass: String,
    database: String,
) -> String {
    format!(
        "postgresql://{}:{}@{}:{}/{}",
        user, pass, host, port, database
    )
}

//Mock all the traits implemented by StateChainEntity so that they can
//be called from MockStateChainEntity
use crate::protocol::conductor::{Conductor, SwapInfo};
use crate::protocol::deposit::Deposit;
use crate::protocol::ecdsa::Ecdsa;
use crate::protocol::transfer::{Transfer, TransferFinalizeData};
use crate::protocol::transfer_batch::BatchTransfer;
use crate::protocol::util::{Proof, Utilities};
use crate::protocol::withdraw::Withdraw;
use crate::storage;
use crate::storage::Storage;
use shared_lib::structs::*;

mock! {
    StateChainEntity{}
    trait Deposit {
        fn deposit_init(&self, deposit_msg1: DepositMsg1) -> deposit::Result<Uuid>;
        fn deposit_confirm(
            &self,
            deposit_msg2: DepositMsg2,
        ) -> deposit::Result<Uuid>;
    }
    trait Ecdsa {
        fn master_key(&self, user_id: Uuid) -> ecdsa::Result<()>;

        fn first_message(
            &self,
            key_gen_msg1: KeyGenMsg1,
        ) -> ecdsa::Result<(Uuid, ecdsa::party_one::KeyGenFirstMsg)>;

        fn second_message(
            &self,
            key_gen_msg2: KeyGenMsg2,
        ) -> ecdsa::Result<ecdsa::party1::KeyGenParty1Message2>;

        fn third_message(
            &self,
            key_gen_msg3: KeyGenMsg3,
        ) -> ecdsa::Result<ecdsa::party_one::PDLFirstMessage>;

        fn fourth_message(
            &self,
            key_gen_msg4: KeyGenMsg4,
        ) -> ecdsa::Result<ecdsa::party_one::PDLSecondMessage>;

        fn sign_first(
            &self,
            sign_msg1: SignMsg1,
        ) -> ecdsa::Result<ecdsa::party_one::EphKeyGenFirstMsg>;

        fn sign_second(
            &self,
            sign_msg2: SignMsg2,
        ) -> ecdsa::Result<Vec<Vec<u8>>>;
    }
    trait Conductor {
        fn poll_utxo(&self, state_chain_id: Uuid) -> conductor::Result<Option<Uuid>>;
        fn poll_swap(&self, swap_id: Uuid) -> conductor::Result<SwapInfo>;
        fn register_utxo(&self, register_utxo_msg: RegisterUtxo) -> conductor::Result<()>;
        fn swap_first_message(&self, swap_msg1: SwapMsg1) -> conductor::Result<()>;
        fn swap_second_message(&self, swap_msg2: SwapMsg2) -> conductor::Result<SCEAddress>;
    }
    trait Transfer {
        fn transfer_sender(
            &self,
            transfer_msg1: TransferMsg1,
        ) -> transfer::Result<TransferMsg2>;
        fn transfer_receiver(
            &self,
            transfer_msg4: TransferMsg4,
        ) -> transfer::Result<TransferMsg5>;
        fn transfer_finalize(
            &self,
            finalized_data: &TransferFinalizeData,
        ) -> transfer::Result<()>;
    }
    trait BatchTransfer {
        fn transfer_batch_init(
            &self,
            transfer_batch_init_msg: TransferBatchInitMsg,
        ) -> transfer_batch::Result<()>;
        fn finalize_batch(
            &self,
            batch_id: Uuid,
        ) -> transfer_batch::Result<()>;
        fn transfer_reveal_nonce(
            &self,
            transfer_reveal_nonce: TransferRevealNonce,
        ) -> transfer_batch::Result<()>;
    }
    trait Utilities {
        fn get_fees(&self) -> util::Result<StateEntityFeeInfoAPI>;

        /// API: Generates sparse merkle tree inclusion proof for some key in a tree with some root.
        fn get_smt_proof(
            &self,
            smt_proof_msg: SmtProofMsgAPI,
        ) -> util::Result<Option<Proof>>;
        fn prepare_sign_tx(
            &self,
            prepare_sign_msg: PrepareSignTxMsg,
        ) -> util::Result<()>;
    }
    trait Withdraw{
        fn withdraw_init(
            &self,
            withdraw_msg1: WithdrawMsg1,
        ) -> withdraw::Result<()>;
        fn withdraw_confirm(
            &self,
            withdraw_msg2: WithdrawMsg2,
        ) -> withdraw::Result<Vec<Vec<u8>>>;
    }
    trait Storage{
        fn update_smt(&self, funding_txid: &String, proof_key: &String)
            -> storage::Result<(Option<storage::Root>, storage::Root)>;
        fn get_confirmed_smt_root(&self) -> storage::Result<Option<storage::Root>>;
        fn get_smt_root(&self) -> storage::Result<Option<storage::Root>>;
        fn get_root(&self, id: i64) -> storage::Result<Option<storage::Root>>;
        fn update_root(&self, root: &storage::Root) -> storage::Result<i64>;
        fn get_statechain_data_api(&self,state_chain_id: Uuid) -> storage::Result<StateChainDataAPI>;
        fn get_statechain(&self, state_chain_id: Uuid) -> storage::Result<storage::StateChain>;
    }
}
