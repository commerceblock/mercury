use super::routes::*;
use super::storage::db;
use super::{Config, AuthConfig};

use config;
use rocket;
use rocket::{Request, Rocket};
use rocksdb;
use shared_lib::mainstay;

use log::LevelFilter;
use log4rs::append::file::FileAppender;
use log4rs::encode::pattern::PatternEncoder;
use log4rs::config::{Appender, Config as LogConfig, Root};

use std::{collections::HashMap, str::FromStr};
use crate::DataBase;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

impl Config {
    pub fn load(settings: HashMap<String, String>) -> Result<Config> {
        let db = get_db(settings.clone())?;
        let fee_address = settings.get("fee_address").unwrap().to_string();
        if let Err(e) = bitcoin::Address::from_str(&fee_address) {
            panic!("Invalid fee address: {}",e)
        };

        let testing_mode=bool::from_str(settings.get("testing_mode").unwrap()).unwrap();

        //mainstay_config is optional
        let mainstay_config = match testing_mode {
            true => mainstay::Config::from_test(),
            false => {
                match settings.get("mainstay_config"){
                    Some(o) => {
                        Some(o.parse::<mainstay::Config>().unwrap())
                    },
                    None => None
                }
            }
        };

        if mainstay_config.is_none()  {
            panic!("expected mainstay config");
        }

        Ok(
            Config {
                db,
                electrum_server: settings.get("electrum_server").unwrap().to_string(),
                network: settings.get("network").unwrap().to_string(),
                testing_mode,
                fee_address,
                fee_deposit: settings.get("fee_deposit").unwrap().parse::<u64>().unwrap(),
                fee_withdraw: settings.get("fee_withdraw").unwrap().parse::<u64>().unwrap(),
                block_time: settings.get("block_time").unwrap().parse::<u64>().unwrap(),
                batch_lifetime: settings.get("batch_lifetime").unwrap().parse::<u64>().unwrap(),
                punishment_duration: settings.get("punishment_duration").unwrap().parse::<u64>().unwrap(),
                mainstay_config
            }
        )
    }
}

impl AuthConfig {
    pub fn load(settings: HashMap<String, String>) -> AuthConfig {
        AuthConfig {
            issuer: settings.get("issuer").unwrap_or(&"".to_string()).to_owned(),
            audience: settings.get("audience")
                .unwrap_or(&"".to_string()).to_owned(),
            region: settings.get("region")
                .unwrap_or(&"".to_string()).to_owned(),
            pool_id: settings.get("pool_id")
                .unwrap_or(&"".to_string()).to_owned(),
        }
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

pub fn get_server() -> Result<Rocket> {
    let settings = get_settings_as_map();

    let config = Config::load(settings.clone())?;
    let auth_config = AuthConfig::load(settings.clone());

    set_logging_config(settings.get("log_file"));

    let rock = rocket::ignite()
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
        .manage(auth_config)
        .attach(DataBase::fairing());

    Ok(rock)
}

fn get_settings_as_map() -> HashMap<String, String> {
    let config_file = include_str!("../Settings.toml");
    let mut settings = config::Config::default();
    settings
        .merge(config::File::from_str(
            config_file,
            config::FileFormat::Toml,
        ))
        .unwrap()
        .merge(config::Environment::new())
        .unwrap();

    settings.try_into::<HashMap<String, String>>().unwrap()
}

fn get_db(_settings: HashMap<String, String>) -> Result<rocksdb::DB> {
    // let env = settings
    //     .get("env")
    //     .unwrap_or(&"dev".to_string())
    //     .to_string();

    Ok(rocksdb::DB::open_default(db::DB_LOC)?)
}

fn set_logging_config(log_file: Option<&String>) {
    if log_file.is_none() {
        let _ = env_logger::try_init();
    } else {
        // Write log to file
        let logfile = FileAppender::builder()
            .encoder(Box::new(PatternEncoder::new("{l} - {m}\n")))
            .build(log_file.unwrap()).unwrap();
        let log_config = LogConfig::builder()
            .appender(Appender::builder().build("logfile", Box::new(logfile)))
            .build(Root::builder()
                       .appender("logfile")
                       .build(LevelFilter::Info)).unwrap();

        let _ = log4rs::init_config(log_config);
    }
}
