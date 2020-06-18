use super::routes::*;
use super::storage::db;
use super::{Config, AuthConfig};

use config;
use rocket;
use rocket::{Request, Rocket};
use rocksdb;

use std::{collections::HashMap, str::FromStr};

impl Config {
    pub fn load(settings: HashMap<String, String>) -> Config {
        let db = get_db(settings.clone());
        let fee_address = settings.get("fee_address").unwrap().to_string();
        if let Err(e) = bitcoin::Address::from_str(&fee_address) {
            panic!("Invalid fee address: {}",e)
        };
        Config {
            db,
            electrum_server: settings.get("electrum_server").unwrap().to_string(),
            network: settings.get("network").unwrap().to_string(),
            testing_mode: bool::from_str(settings.get("testing_mode").unwrap()).unwrap(),
            fee_address,
            fee_deposit: settings.get("fee_deposit").unwrap().parse::<u64>().unwrap(),
            fee_withdraw: settings.get("fee_withdraw").unwrap().parse::<u64>().unwrap(),
            block_time: settings.get("block_time").unwrap().parse::<u64>().unwrap(),
            batch_lifetime: settings.get("batch_lifetime").unwrap().parse::<u64>().unwrap(),
        }
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

pub fn get_server() -> Rocket {
    let settings = get_settings_as_map();

    let config = Config::load(settings.clone());
    let auth_config = AuthConfig::load(settings.clone());

    rocket::ignite()
        .register(catchers![internal_error, not_found, bad_request])
        .mount(
            "/",
            routes![
                ping::ping,
                ecdsa::first_message,
                ecdsa::second_message,
                ecdsa::third_message,
                ecdsa::fourth_message,
                ecdsa::chain_code_first_message,
                ecdsa::chain_code_second_message,
                ecdsa::sign_first,
                ecdsa::sign_second,
                ecdsa::recover,
                schnorr::keygen_first,
                schnorr::keygen_second,
                schnorr::keygen_third,
                schnorr::sign,
                state_entity::get_statechain,
                state_entity::get_smt_root,
                state_entity::get_smt_proof,
                state_entity::get_state_entity_fees,
                state_entity::get_transfer_batch_status,
                state_entity::deposit_init,
                state_entity::deposit_confirm,
                state_entity::prepare_sign_tx,
                state_entity::transfer_sender,
                state_entity::transfer_receiver,
                state_entity::transfer_batch_init,
                state_entity::withdraw_init,
                state_entity::withdraw_confirm
            ],
        )
        .manage(config)
        .manage(auth_config)
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

fn get_db(_settings: HashMap<String, String>) -> rocksdb::DB {
    // let env = settings
    //     .get("env")
    //     .unwrap_or(&"dev".to_string())
    //     .to_string();

    rocksdb::DB::open_default(db::DB_LOC).unwrap()
}
