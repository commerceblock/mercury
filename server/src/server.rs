use super::routes::*;
use super::Config;

use crate::DatabaseR;
use crate::{storage::{db_make_tables, db_reset_dbs, get_test_postgres_connection}, DatabaseW};

use config;
use rocket;
use rocket::config::{Config as RocketConfig, Environment, Value};
use rocket::{Request, Rocket};
use shared_lib::mainstay;

use log::LevelFilter;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config as LogConfig, Root};
use log4rs::encode::pattern::PatternEncoder;
use std::{collections::HashMap, str::FromStr};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

impl Config {
    pub fn load(settings: HashMap<String, String>) -> Result<Config> {
        let fee_address = settings.get("fee_address").unwrap().to_string();
        if let Err(e) = bitcoin::Address::from_str(&fee_address) {
            panic!("Invalid fee address: {}", e)
        };

        let testing_mode = bool::from_str(settings.get("testing_mode").unwrap()).unwrap();

        //mainstay_config is optional
        let mainstay_config = match testing_mode {
            true =>  None,
            false => match settings.get("mainstay_config") {
                Some(o) => Some(o.parse::<mainstay::Config>().unwrap()),
                None => None,
            },
        };

        Ok(Config {
            electrum_server: settings.get("electrum_server").unwrap().to_string(),
            network: settings.get("network").unwrap().to_string(),
            testing_mode,
            fee_address,
            fee_deposit: settings.get("fee_deposit").unwrap().parse::<u64>().unwrap(),
            fee_withdraw: settings
                .get("fee_withdraw")
                .unwrap()
                .parse::<u64>()
                .unwrap(),
            block_time: settings.get("block_time").unwrap().parse::<u64>().unwrap(),
            batch_lifetime: settings
                .get("batch_lifetime")
                .unwrap()
                .parse::<u64>()
                .unwrap(),
            punishment_duration: settings
                .get("punishment_duration")
                .unwrap()
                .parse::<u64>()
                .unwrap(),
            mainstay_config,
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

/// Start Rocket Server. testing_mode parameter overrides Settings.toml.
pub fn get_server(force_testing_mode: bool, mainstay_config: Option<mainstay::Config>) -> Result<Rocket> {
    let settings = get_settings_as_map();

    let mut config = Config::load(settings.clone())?;
    if force_testing_mode {
        config.testing_mode = true;
    }

    //Set the mainstay config if Some (used for testing)
    match mainstay_config {
        Some(c) => config.mainstay_config = Some(c),
        None => ()
    }
    //At this point the mainstay config should be set,
    //either in testing mode or specified in the settings file
    if config.mainstay_config.is_none() {
        panic!("expected mainstay config");
    }

    set_logging_config(settings.get("log_file"));

    let rocket_config = get_rocket_config(&config.testing_mode);

    if config.testing_mode {
        let conn = get_test_postgres_connection();
        if let Err(_) = db_reset_dbs(&conn) {
            db_make_tables(&conn)?;
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
                util::get_confirmed_smt_root,
                util::get_smt_proof,
                util::get_state_entity_fees,
                util::prepare_sign_tx,
                util::get_transfer_batch_status,
                deposit::deposit_init,
                deposit::deposit_confirm,
                transfer::transfer_sender,
                transfer::transfer_receiver,
                transfer::transfer_batch_init,
                transfer::transfer_reveal_nonce,
                withdraw::withdraw_init,
                withdraw::withdraw_confirm
            ],
        )
        .manage(config)
        .attach(DatabaseR::fairing()) // read
        .attach(DatabaseW::fairing()); // write

    Ok(rock)
}

/// List of available settings. Set via Settings.toml or enviroment variables MERC_[SETTING_STR.to_uppercase()].
static SETTING_STRS: [&str; 9] = ["electrum_server", "network", "block_time", "testing_mode", "fee_address",
    "fee_deposit", "fee_withdraw", "punishment_duration", "batch_lifetime"];

fn get_settings_as_map() -> HashMap<String, String> {
    let config_file = include_str!("../Settings.toml");
    let mut settings = config::Config::default();
    settings
        .merge(config::File::from_str(
            config_file,
            config::FileFormat::Toml,
        ))
        .unwrap();

    let mut settings_as_map: HashMap<String, String> = settings.try_into().unwrap();

    // Override Setting.toml parameters with any environment variable parameters that are set
    for var_name in SETTING_STRS.iter() {
        let env_name = format!("MERC_{}",var_name.to_uppercase());
        match std::env::var(env_name) {
            Ok(v) => {
                let _ = settings_as_map.insert(var_name.to_string(), v);
            },
            Err(_) => {}
        }
    }
    settings_as_map
}

fn set_logging_config(log_file: Option<&String>) {
    if log_file.is_none() {
        let _ = env_logger::try_init();
    } else {
        // Write log to file
        let logfile = FileAppender::builder()
            .encoder(Box::new(PatternEncoder::new("{l} - {m}\n")))
            .build(log_file.unwrap())
            .unwrap();
        let log_config = LogConfig::builder()
            .appender(Appender::builder().build("logfile", Box::new(logfile)))
            .build(Root::builder().appender("logfile").build(LevelFilter::Info))
            .unwrap();
        let _ = log4rs::init_config(log_config);
    }
}

fn get_rocket_config(testing_mode: &bool) -> RocketConfig {
    let mut database_config = HashMap::new();
    let mut databases = HashMap::new();

    // Make postgres URL. If testing use Test DB for reads and writes.
    match testing_mode {
        true => {
            database_config.insert("url", Value::from(get_postgres_url("TEST".to_string())));
            databases.insert("postgres_w", Value::from(database_config.clone()));
            databases.insert("postgres_r", Value::from(database_config));
        }
        false => {
            database_config.insert("url", Value::from(get_postgres_url("W".to_string())));
            databases.insert("postgres_w", Value::from(database_config));
            let mut database_config = HashMap::new();
            database_config.insert("url", Value::from(get_postgres_url("R".to_string())));
            databases.insert("postgres_r", Value::from(database_config));
        }
    };

    RocketConfig::build(Environment::Staging)
        .extra("databases", databases)
        .finalize()
        .unwrap()
}

static DB_SETTING_STRS: [&str; 5] = ["MERC_DB_USER", "MERC_DB_PASS", "MERC_DB_HOST", "MERC_DB_PORT", "MERC_DB_DATABASE"];

/// Get postgres URL from env vars. Suffix can be "TEST", "W", or "R"
pub fn get_postgres_url(var_suffix: String) -> String {
    let mut db_vars = vec![];
    for db_var_name in DB_SETTING_STRS.iter() {
        match std::env::var(format!("{}_{}", db_var_name, var_suffix)) {
            Ok(v) => db_vars.push(v),
            Err(_) => panic!(
                "Missing DB environment variable {}",
                format!("{}_{}", db_var_name, var_suffix)
            ),
        }
    }
    format!(
        "postgresql://{}:{}@{}:{}/{}",
        db_vars[0], db_vars[1], db_vars[2], db_vars[3], db_vars[4]
    )
}
