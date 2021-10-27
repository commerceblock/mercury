use super::protocol::conductor::Scheduler;
use super::protocol::*;
use crate::config::{Config, Mode};
use crate::structs::StateChainOwner;
use crate::Database;
use shared_lib::{mainstay, state_chain::StateChainSig, swap_data::*};

use log::LevelFilter;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config as LogConfig, Root as LogRoot};
use log4rs::encode::pattern::PatternEncoder;

use std::thread;
use crate::watch::watch_node;

use mockall::*;
use monotree::database::Database as MonotreeDatabase;
use rocket;
use rocket_okapi::routes_with_openapi;
use rocket_okapi::swagger_ui::{make_swagger_ui, SwaggerUIConfig};
use rocket::{
    config::{Config as RocketConfig, Environment},
    Request, Rocket, Route
};
use rocket_prometheus::{
    prometheus::{opts, IntCounter, IntCounterVec},
    PrometheusMetrics,
};
use reqwest;
use once_cell::sync::Lazy;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use std::collections::HashMap;
use url::Url;
use std::collections::HashSet;
use std::default::Default;
use governor::{Quota, clock::DefaultClock, state::keyed::DashMapStateStore};
use std::sync::atomic::{AtomicBool, Ordering};
use signal_hook::{flag, consts::TERM_SIGNALS};

//prometheus statics
pub static DEPOSITS_COUNT: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("deposit_counter", "Total completed deposits")
        .expect("Could not create lazy IntCounter")
});
pub static WITHDRAWALS_COUNT: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("withdraw_counter", "Total completed withdrawals")
        .expect("Could not create lazy IntCounter")
});
pub static TRANSFERS_COUNT: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("transfer_counter", "Total completed transfers")
        .expect("Could not create lazy IntCounter")
});
pub static REG_SWAP_UTXOS: Lazy<IntCounterVec> = Lazy::new(|| {
    IntCounterVec::new(opts!("reg_swap_utxos", "Registered utxos by group size and amount"), &["size","amount"])
        .expect("Could not create lazy IntGaugeVec")
});

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub type UserIDs = HashSet::<Uuid>;

#[derive(Debug, Clone)]
pub struct Endpoints {
    endpoints: Vec<Url>
}

impl Endpoints {
    pub fn from(endpoints: Vec<Url>) -> Self {
        Endpoints { endpoints }
    }

    /// Select a url from the list of active urls depending on the numerical value
    /// of the statechain identifier.
    pub fn select(&self, statechain_id: &Uuid) -> Option<(&Url, usize)> {
        let len = self.endpoints.len();
        if len == 0 {return None}
        let scid_bytes = statechain_id.as_bytes();
        let index = u128::from_be_bytes(*scid_bytes) % len as u128;
        self.get(&(index as usize)).map(|x|(x, index as usize))
    }

    pub fn get(&self, index: &usize) -> Option<&Url> {
        self.endpoints.get(index.to_owned())
    }
}

#[derive(Debug, Clone)]
pub struct Lockbox {
    pub client: reqwest::blocking::Client,
    pub endpoint: Endpoints,
}

impl Lockbox {
    pub fn new(endpoints: Vec<Url>) -> Result<Lockbox> {
        let endpoint = Endpoints::from(endpoints);
        let client = reqwest::blocking::Client::new();
        Ok(Lockbox{client, endpoint})
    }
}

pub struct StateChainEntity<
    T: Database + Send + Sync + 'static,
    D: MonotreeDatabase + Send + Sync + 'static,
> {
    pub config: Config,
    pub database: T,
    pub coin_value_info: Arc<Mutex<CoinValueInfo>>,
    pub user_ids: Arc<Mutex<UserIDs>>,
    pub smt: Arc<Mutex<Monotree<D, Blake3>>>,
    pub scheduler: Option<Arc<Mutex<Scheduler>>>,
    pub lockbox: Option<Lockbox>,
    pub rate_limiter_slow: Option<Arc<governor::RateLimiter<String, DashMapStateStore<String> , DefaultClock> >>,
    pub rate_limiter_fast: Option<Arc<governor::RateLimiter<String, DashMapStateStore<String> , DefaultClock> >>,
    pub rate_limiter_id: Option<Arc<governor::RateLimiter<Uuid, DashMapStateStore<Uuid> , DefaultClock> >>
}

impl<
        T: Database + Send + Sync + 'static,
        D: Database + MonotreeDatabase + Send + Sync + 'static,
    > StateChainEntity<T, D>
{

    pub fn load(mut db: T, mut db_smt: D, config: Option<Config>) -> Result<StateChainEntity<T, D>> {
        // Get config as defaults, Settings.toml and env vars
        let config_rs = config.unwrap_or(Config::load()?);
        db.set_connection_from_config(&config_rs)?;
        db_smt.set_connection_from_config(&config_rs)?;

        let smt = Monotree {
            db: db_smt,
            hasher: Blake3::new(),
        };

        let conductor_config = config_rs.conductor.clone();

        pub fn init_lb(conf: &Config) -> Option<Lockbox>{

            let lb_config = match &conf.lockbox {
                None => return None,
                Some(l) => l
            };

            let lb_str = lb_config.replace(" ", "");
            let lb_str_list: Vec<&str> = lb_str.split(",").collect();
            let mut lb_list: Vec<Url> = vec![];
            for i in lb_str_list {
                lb_list.push(Url::parse(i).unwrap())
            }
            Some(lb_list).map(|l| Lockbox::new(l.to_vec()).unwrap())
        }
    
        let (lockbox, scheduler) = match config_rs.mode {
            Mode::Both => (init_lb(&config_rs), Some(Arc::new(Mutex::new(Scheduler::new(&conductor_config))))),
            Mode::Conductor => (None, Some(Arc::new(Mutex::new(Scheduler::new(&conductor_config))))),
            Mode::Core => (init_lb(&config_rs), None)
        };

        let rate_limiter_slow = config_rs.rate_limit_slow.map(|r| Arc::new(governor::RateLimiter::dashmap(Quota::per_second(r))));
        let rate_limiter_fast = config_rs.rate_limit_fast.map(|r| Arc::new(governor::RateLimiter::dashmap(Quota::per_second(r))));
        let rate_limiter_id = config_rs.rate_limit_id.map(|r| Arc::new(governor::RateLimiter::dashmap(Quota::per_second(r))));

        let sce = Self {
            config: config_rs,
            database: db,
            coin_value_info: Arc::new(Mutex::new(Default::default())),
            user_ids: Arc::new(Mutex::new(Default::default())),
            smt: Arc::new(Mutex::new(smt)),
            scheduler,
            lockbox,
            rate_limiter_slow,
            rate_limiter_fast,
            rate_limiter_id
        };

        match &sce.scheduler {
            Some(s) => {
                Self::start_conductor_thread(s.clone(), sce.config.mode);
            },
            None => ()
        }

        Ok(sce)
    }

    pub fn start_conductor_thread(scheduler: Arc<Mutex<Scheduler>>, mode: Mode) -> 
        std::thread::JoinHandle<()>
    {
        
        let term = Arc::new(AtomicBool::new(false));
        let shutdown_ready = Arc::new(AtomicBool::new(false));
    
        
        for sig in TERM_SIGNALS {
            flag::register(*sig, Arc::clone(&term)).unwrap();
            flag::register_conditional_shutdown(*sig, 0, Arc::clone(&shutdown_ready)).unwrap();
        }
        
        std::thread::spawn(move || loop {
            let mut guard = scheduler.lock().unwrap();
            if Arc::clone(&term).load(Ordering::Relaxed) {
                guard.request_shutdown();
            }
            if let Err(e) = guard.update_swap_info() {
                error!("{}", &e.to_string());
            }
            if guard.shutdown_ready(){
                // Swap coordination complete - allow a grace period for 
                // completion of transfers (if using mercury/conductor combined 
                // server), then execute shutdown
                match mode {
                    Mode::Both => thread::sleep(std::time::Duration::new(180, 0)),
                    _ => ()
                };
                Arc::clone(&shutdown_ready).store(true, Ordering::Relaxed);
                signal_hook::low_level::raise(signal_hook::consts::TERM_SIGNALS[0]).expect("failed to raise TERM signal");
            }
            drop(guard);
            std::thread::sleep(std::time::Duration::from_secs(10));
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

fn get_docs() -> SwaggerUIConfig {
    use rocket_okapi::swagger_ui::UrlObject;

    SwaggerUIConfig {
        url: "/openapi.json".to_string(),
        urls: vec![UrlObject::new("Mercury", "/openapi.json")],
        ..Default::default()
    }
}

fn get_routes(mode: &Mode) -> std::vec::Vec<Route>{
    match mode {
        Mode::Both => routes_with_openapi![
            util::get_statechain,
            util::get_smt_root,
            util::get_smt_proof,
            util::get_fees,
            util::prepare_sign_tx,
            util::get_recovery_data,
            util::get_transfer_batch_status,
            util::get_coin_info,
            util::reset_test_dbs,
            util::reset_inram_data,
            ecdsa::first_message,
            ecdsa::second_message,
            ecdsa::sign_first,
            ecdsa::sign_second,
            deposit::deposit_init,
            deposit::deposit_confirm,
            transfer::transfer_sender,
            transfer::transfer_receiver,
            transfer::transfer_update_msg,
            transfer::transfer_get_msg,
            transfer::transfer_get_msg_addr,
            transfer::transfer_get_pubkey,
            transfer_batch::transfer_batch_init,
            transfer_batch::transfer_reveal_nonce,
            withdraw::withdraw_init,
            withdraw::withdraw_confirm,
            conductor::poll_utxo,
            conductor::poll_swap,
            conductor::get_swap_info,
            conductor::get_blinded_spend_signature,
            conductor::register_utxo,
            conductor::deregister_utxo,
            conductor::swap_first_message,
            conductor::swap_second_message,
            conductor::get_group_info],
        Mode::Core => routes_with_openapi![
            util::get_statechain,
            util::get_smt_root,
            util::get_smt_proof,
            util::get_fees,
            util::prepare_sign_tx,
            util::get_recovery_data,
            util::get_transfer_batch_status,
            util::get_coin_info,
            util::reset_test_dbs,
            util::reset_inram_data,
            ecdsa::first_message,
            ecdsa::second_message,
            ecdsa::sign_first,
            ecdsa::sign_second,
            deposit::deposit_init,
            deposit::deposit_confirm,
            transfer::transfer_sender,
            transfer::transfer_receiver,
            transfer::transfer_update_msg,
            transfer::transfer_get_msg,
            transfer::transfer_get_msg_addr,
            transfer::transfer_get_pubkey,
            transfer_batch::transfer_batch_init,
            transfer_batch::transfer_reveal_nonce,
            withdraw::withdraw_init,
            withdraw::withdraw_confirm],
        Mode::Conductor => routes_with_openapi![
            util::reset_test_dbs,
            util::reset_inram_data,
            conductor::poll_utxo,
            conductor::poll_swap,
            conductor::get_swap_info,
            conductor::get_blinded_spend_signature,
            conductor::register_utxo,
            conductor::deregister_utxo,
            conductor::swap_first_message,
            conductor::swap_second_message,
            conductor::get_group_info],
    }
}

/// Start Rocket Server. mainstay_config parameter overrides Settings.toml and env var settings.
/// If no db provided then use mock
pub fn get_server<
    T: Database + Send + Sync + 'static,
    D: Database + MonotreeDatabase + Send + Sync + 'static,
>(
    mainstay_config: Option<mainstay::MainstayConfig>,
    db: T,
    db_smt: D,
) -> Result<Rocket> {
    let mut sc_entity = StateChainEntity::<T, D>::load(db, db_smt,None)?;

    set_logging_config(&sc_entity.config.log_file);

    // Initialise DBs
    if sc_entity.config.testing_mode {
        info!("Server running in testing mode.");
        // reset dbs
        sc_entity.database.reset()?;
    }
    let guard_coins_mutex: &Mutex::<CoinValueInfo> = sc_entity.coin_value_info.as_ref();
    //let mut guard_coins: &mut CoinValueInfo = guard_coins_mutex.lock()?.deref_mut();
    let guard_ids_mutex: &Mutex::<HashSet::<Uuid>> = sc_entity.user_ids.as_ref();
    //let mut guard_ids = guard_ids_mutex.lock()?.deref_mut();
    sc_entity.database.init(guard_coins_mutex, guard_ids_mutex)?;
    drop(guard_coins_mutex);
    drop(guard_ids_mutex);
    match mainstay_config {
        Some(c) => sc_entity.config.mainstay = Some(c),
        None => (),
    }

    //At this point the mainstay config should be set,
    //either in testing mode or specified in the settings file
    if sc_entity.config.mainstay.is_none() {
        panic!("expected mainstay config");
    }

    let prometheus = PrometheusMetrics::new();
    prometheus.registry().register(Box::new(DEPOSITS_COUNT.clone())).unwrap();
    prometheus.registry().register(Box::new(WITHDRAWALS_COUNT.clone())).unwrap();
    prometheus.registry().register(Box::new(TRANSFERS_COUNT.clone())).unwrap();
    prometheus.registry().register(Box::new(REG_SWAP_UTXOS.clone())).unwrap();

    let rocket_config = get_rocket_config(&sc_entity.config);
    let bitcoind = sc_entity.config.bitcoind.clone();

    if sc_entity.config.watch_only {
        info!("Server running in watch-only mode.");
        thread::spawn(|| watch_node(bitcoind));
        let rock = rocket::custom(rocket_config)
            .register(catchers![internal_error, not_found, bad_request])
            .mount(
                "/",
                routes![
                    ping::ping
                ],
            );
        Ok(rock)
    } else {
        // if bitcoind path supplied, run watching
        if sc_entity.config.bitcoind.is_empty() == false {
            thread::spawn(|| watch_node(bitcoind));
        }
        
        let rock = rocket::custom(rocket_config)
            .register(catchers![internal_error, not_found, bad_request])
            .attach(prometheus.clone())
            .mount(
                "/",
                routes![
                    ping::ping,
                ],
            )
            .mount(
                "/",
                get_routes(&sc_entity.config.mode),
            )
            .mount("/swagger", make_swagger_ui(&get_docs()))
            .mount("/metrics", prometheus)
            .manage(sc_entity);

        Ok(rock)
    }
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
use crate::protocol::conductor::Conductor;
use crate::protocol::deposit::Deposit;
use crate::protocol::ecdsa::Ecdsa;
use crate::protocol::transfer::{Transfer, TransferFinalizeData};
use crate::protocol::transfer_batch::BatchTransfer;
use crate::protocol::util::{Proof, Utilities, RateLimiter};
use crate::protocol::withdraw::Withdraw;
use crate::storage;
use crate::storage::Storage;
use monotree::{hasher::Blake3, Hasher, Monotree};
use shared_lib::blinded_token::{BlindedSpendSignature, BlindedSpendToken};
use shared_lib::structs::*;

mock! {
    StateChainEntity{}
    trait Deposit {
        fn deposit_init(&self, deposit_msg1: DepositMsg1) -> deposit::Result<UserID>;
        fn deposit_confirm(
            &self,
            deposit_msg2: DepositMsg2,
        ) -> deposit::Result<StatechainID>;
    }
    trait Ecdsa {
        fn master_key(&self, user_id: Uuid) -> ecdsa::Result<()>;

        fn first_message(
            &self,
            key_gen_msg1: KeyGenMsg1,
        ) -> ecdsa::Result<KeyGenReply1>;

        fn second_message(
            &self,
            key_gen_msg2: KeyGenMsg2,
        ) -> ecdsa::Result<KeyGenReply2>;

        fn sign_first(
            &self,
            sign_msg1: SignMsg1,
        ) -> ecdsa::Result<SignReply1>;

        fn sign_second(
            &self,
            sign_msg2: SignMsg2,
        ) -> ecdsa::Result<Vec<Vec<u8>>>;
    }
    trait Conductor {
        fn poll_utxo(&self, statechain_id: &Uuid) -> conductor::Result<SwapID>;
        fn poll_swap(&self, swap_id: &Uuid) -> conductor::Result<Option<SwapStatus>>;
        fn get_swap_info(&self, swap_id: &Uuid) -> conductor::Result<Option<SwapInfo>>;
        fn register_utxo(&self, register_utxo_msg: &RegisterUtxo) -> conductor::Result<()>;
        fn deregister_utxo(&self, statechain_id: &Uuid) -> conductor::Result<()>;
        fn swap_first_message(&self, swap_msg1: &SwapMsg1) -> conductor::Result<()>;
        fn swap_second_message(&self, swap_msg2: &SwapMsg2) -> conductor::Result<SCEAddress>;
        fn get_group_info(&self) -> conductor::Result<HashMap<SwapGroup,GroupStatus>>;
        fn get_blinded_spend_signature(&self, swap_id: &Uuid, statechain_id: &Uuid) -> conductor::Result<BlindedSpendSignature>;
        fn get_address_from_blinded_spend_token(&self, bst: &BlindedSpendToken) -> conductor::Result<SCEAddress>;
    }

    trait Transfer {
        fn transfer_sender(
            &self,
            transfer_msg1: TransferMsg1,
        ) -> transfer::Result<TransferMsg2>;
        fn transfer_get_pubkey(
            &self,
            user_id: Uuid,
            ) -> transfer::Result<S1PubKey>;
        fn transfer_receiver(
            &self,
            transfer_msg4: TransferMsg4,
        ) -> transfer::Result<TransferMsg5>;
        fn transfer_finalize(
            &self,
            finalized_data: &TransferFinalizeData,
        ) -> transfer::Result<()>;
        fn transfer_update_msg(&self, transfer_msg3: TransferMsg3) -> transfer::Result<()>;
        fn transfer_get_msg(&self, statechain_id: Uuid) -> transfer::Result<TransferMsg3>;
        fn transfer_get_msg_addr(&self, receive_addr: String) -> transfer::Result<Vec<TransferMsg3>>;
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
        fn get_recovery_data(
            &self,
            recovery_request: Vec<RecoveryRequest>,
        ) -> util::Result<Vec<RecoveryDataMsg>>;
        fn get_lockbox_url(&self, user_id: &Uuid
        ) -> util::Result<Option<(Url, usize)>>;
    }
    trait RateLimiter{
        fn check_rate_slow<T:'static+Into<String>>(&self, key: T) -> storage::Result<()>;
        fn check_rate_fast<T:'static+Into<String>>(&self, key: T) -> storage::Result<()>;
        fn check_rate_id(&self, key: &Uuid) -> storage::Result<()>;
    }
    trait Withdraw{
        fn verify_statechain_sig(&self,
            statechain_id: &Uuid,
            statechain_sig: &StateChainSig,
            user_id: Option<Uuid>)
                -> withdraw::Result<StateChainOwner>;
        fn withdraw_init(
            &self,
            withdraw_msg1: WithdrawMsg1,
        ) -> withdraw::Result<()>;
        fn withdraw_confirm(
            &self,
            withdraw_msg2: WithdrawMsg2,
        ) -> withdraw::Result<Vec<Vec<Vec<u8>>>>;
    }
    trait Storage{
        fn reset_data(&self) -> storage::Result<()>;
        fn update_smt(&self, funding_txid: &String, proof_key: &String)
            -> storage::Result<(Option<storage::Root>, storage::Root)>;
        fn get_confirmed_smt_root(&self) -> storage::Result<Option<storage::Root>>;
        fn get_smt_root(&self) -> storage::Result<Option<storage::Root>>;
        fn get_root(&self, id: i64) -> storage::Result<Option<storage::Root>>;
        fn update_root(&self, root: &storage::Root) -> storage::Result<i64>;
        fn get_statechain_data_api(&self,statechain_id: Uuid) -> storage::Result<StateChainDataAPI>;
        fn get_statechain(&self, statechain_id: Uuid) -> storage::Result<storage::StateChain>;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoints() {
        let urls: Vec<Url> = vec![];
        let eps = Endpoints::from(urls);
        assert_eq!(eps.endpoints.len(), 0);
        assert!(eps.select(&Uuid::default()).is_none());
        let urls = vec![Url::parse("https://url1.net/").unwrap(), 
                        Url::parse("https://url2.net/").unwrap(), 
                        Url::parse("https://url3.net/").unwrap(), 
                        Url::parse("https://url4.net/").unwrap(), 
                        Url::parse("https://url5.net/").unwrap(), 
                        Url::parse("https://url6.net/").unwrap()];
        let eps: Endpoints = Endpoints::from(urls.clone());
        for i in 0..100000 {
            let id = Uuid::from_bytes(&(i as u128).to_be_bytes()).unwrap();
            let (url_selected, index) = eps.select(&id).unwrap();
            let index_check = ( i % urls.len() as u128 ) as usize; 
            assert_eq!(index, index_check); 
            assert_eq!(url_selected, &urls[index])
        }    
    }
}
