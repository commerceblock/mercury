use super::protocol::*;
use crate::DatabaseR;
use crate::{
    //storage::{db_make_tables, db_reset_dbs, get_test_postgres_connection},
    DatabaseW,
    Database
};

use crate::PGDatabase as DB;

use config;
use rocket;
use rocket::config::{Config as RocketConfig, Environment, Value};
use rocket::{Request, Rocket};
use shared_lib::mainstay;

use log::LevelFilter;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config as LogConfig, Root};
use log4rs::encode::pattern::PatternEncoder;
use std::collections::HashMap;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct StateChainEntity {
    pub config: Config
}

impl StateChainEntity {
    pub fn load() -> Result<StateChainEntity> {
        // Get config as defaults, Settings.toml and env vars
        let config_rs = Config::load()?;

        Ok(StateChainEntity {
            config: config_rs
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

/// Start Rocket Server. mainsta_config parameter overrides Settings.toml and env var settings.
pub fn get_server(mainstay_config: Option<mainstay::MainstayConfig>) -> Result<Rocket> {
    let mut sc_entity = StateChainEntity::load()?;

    //Override the mainstay config if Some (used for testing)
    match mainstay_config {
        Some(c) => sc_entity.config.mainstay = Some(c),
        None => ()
    }
    //At this point the mainstay config should be set,
    //either in testing mode or specified in the settings file
    if sc_entity.config.mainstay.is_none() {
        panic!("expected mainstay config");
    }

    set_logging_config(&sc_entity.config.log_file);

    let rocket_config = get_rocket_config(&sc_entity.config);

    let database = DB::get_test();
    let mut smt_db_loc: String;
    if sc_entity.config.testing_mode {
        // Use test SMT DB
        smt_db_loc = SMT_DB_LOC_TESTING.to_string();
        // reset dbs
        if let Err(_) = database.reset_dbs(&smt_db_loc) {
            database.make_tables()?;
        }
    } else {
        smt_db_loc = settings
            .get("smt_db_loc")
            .unwrap_or(&SMT_DB_LOC_DEFAULT.to_string())
            .to_string();
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
                util::get_confirmed_smt_root,
                util::get_smt_proof,
                util::get_fees,
                util::prepare_sign_tx,
                util::get_transfer_batch_status,
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
        .manage(sc_entity)
        .attach(DatabaseR::fairing()) // read
        .attach(DatabaseW::fairing()); // write
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
            .build(Root::builder().appender("logfile").build(LevelFilter::Info))
            .unwrap();
        let _ = log4rs::init_config(log_config);
    }
}

fn get_rocket_config(config: &Config) -> RocketConfig {
    let mut database_config = HashMap::new();

    // Make postgres URL.
    let mut databases = HashMap::new();
    // write DB
    database_config.insert("url", Value::from(
        get_postgres_url(
            config.storage.db_host_w.clone(),
            config.storage.db_port_w.clone(),
            config.storage.db_user_w.clone(),
            config.storage.db_pass_w.clone(),
            config.storage.db_database_w.clone(),
        )
    ));
    databases.insert("postgres_w", Value::from(database_config));

    // read DB
    let mut database_config = HashMap::new();
    database_config.insert("url", Value::from(
        get_postgres_url(
            config.storage.db_host_r.clone(),
            config.storage.db_port_r.clone(),
            config.storage.db_user_r.clone(),
            config.storage.db_pass_r.clone(),
            config.storage.db_database_r.clone(),
        )
    ));
    databases.insert("postgres_r", Value::from(database_config));

    RocketConfig::build(Environment::Staging)
        .extra("databases", databases)
        .finalize()
        .unwrap()
}

/// Get postgres URL from env vars. Suffix can be "TEST", "W", or "R"
pub fn get_postgres_url(host: String, port: String, user: String, pass: String, database: String) -> String {
    format!("postgresql://{}:{}@{}:{}/{}",user, pass, host, port, database)
}
