//! # Config
//!
//! Config module handling config options from file and env

use super::Result;

use config_rs::{Config as ConfigRs, Environment, File};
use serde::{Deserialize, Serialize};
use shared_lib::mainstay::MainstayConfig;
use std::env;
use std::str::FromStr;
use std::vec::Vec;
use uuid::Uuid;
use url::Url;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")] 
pub enum Mode {
    Both,
    Core,
    Conductor
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConductorConfig {
    //Time in seconds that a swap must be completed by once the group has been formed
    pub group_timeout: u32,
    //Time in seconds that a UTXO registered for a swap must be polled for 
    //in order to remain in a swap group
    pub utxo_timeout: u32, 
    /// Length of punishment for unresponsivve/misbehaving batch-transfer utxo
    pub punishment_duration: u64,
}

impl Default for ConductorConfig {
    fn default() -> Self {
        Self {
            group_timeout: 600,
            utxo_timeout: 60,
            punishment_duration: 360
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
/// Storage specific config
pub struct StorageConfig {
    /// Storage write host
    pub db_host_w: String,
    /// Storage write port
    pub db_port_w: String,
    /// Storage write user
    pub db_user_w: String,
    /// Storage write pass
    pub db_pass_w: String,
    /// Storage write database
    pub db_database_w: String,
    /// Storage read host
    pub db_host_r: String,
    /// Storage read port
    pub db_port_r: String,
    /// Storage read user
    pub db_user_r: String,
    /// Storage read pass
    pub db_pass_r: String,
    /// Storage read database
    pub db_database_r: String,
}

impl Default for StorageConfig {
    fn default() -> StorageConfig {
        StorageConfig {
            db_host_w: String::from(""),
            db_port_w: String::from(""),
            db_user_w: String::from(""),
            db_pass_w: String::from(""),
            db_database_w: String::from(""),
            db_host_r: String::from(""),
            db_port_r: String::from(""),
            db_user_r: String::from(""),
            db_pass_r: String::from(""),
            db_database_r: String::from(""),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
/// Rocket specific config
pub struct RocketConfig {
    /// Rocket keep alive parameter
    pub keep_alive: u32,
    /// Rocket address
    pub address: String,
    /// Rocket port
    pub port: u16,
}

impl Default for RocketConfig {
    fn default() -> RocketConfig {
        RocketConfig {
            keep_alive: 100,
            address: "0.0.0.0".to_string(),
            port: 8000,
        }
    }
}

/// Config struct storing all StataChain Entity config
#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// Mode: "core", "conductor" or "both"
    pub mode: Mode, 
    /// Log file location. If not present print to stdout
    pub log_file: String,
    /// Electrum Server Address
    pub electrum_server: String,
    /// Active lockbox server addresses
    pub lockbox: Option<Vec<Url>>,
    /// Bitcoin network name (testnet, regtest, mainnet)
    pub network: String,
    /// Testing mode
    pub testing_mode: bool,
    /// Initial deposit backup nlocktime
    pub lockheight_init: u32,
    /// Transfer nlocktime decrement
    pub lh_decrement: u32,
    /// Required confirmations for deposit
    pub required_confirmation: u32,
    /// Receive address for fee payments
    pub fee_address: String,
    /// Despoit fee (basis points)
    pub fee_deposit: u64,
    /// Withdraw fee (basis points)
    pub fee_withdraw: u64,
    /// Time to allow batch transfer to take
    pub batch_lifetime: u64,
    /// Watch-only
    pub watch_only: bool,
    /// bitcoind node connecton
    pub bitcoind: String,
    /// Storage config
    pub storage: StorageConfig,
    /// Mainstay config
    pub mainstay: Option<MainstayConfig>,
    /// Rocket config
    pub rocket: RocketConfig,
    /// Conductor config
    pub conductor: ConductorConfig
}

impl Default for Config {
    fn default() -> Config {
        Config {
            mode: Mode::Both,
            log_file: String::from(""),
            electrum_server: String::from("127.0.0.1:60401"),
            lockbox: None,
            network: String::from("regtest"),
            testing_mode: false,
            lockheight_init: 10000,
            lh_decrement: 100,
            required_confirmation: 3,
            fee_address: String::from("bcrt1qjjwk2rk7nuxt6c79tsxthf5rpnky0sdhjr493x"),
            fee_deposit: 40,
            fee_withdraw: 40,
            batch_lifetime: 3600,     // 1 hour
            watch_only: false,
            bitcoind: String::from(""),
            storage: StorageConfig::default(),
            mainstay: Some(MainstayConfig::default()),
            rocket: RocketConfig::default(),
            conductor: ConductorConfig::default(),
        }
    }
}

impl Config {
    /// Load Config instance reading default values, overridden with Settings.toml,
    /// overriden with environment variables in form MERC_[setting_name]
    pub fn load() -> Result<Self> {
        let mut conf_rs = ConfigRs::new();
        let _ = conf_rs
            // First merge struct default config
            .merge(ConfigRs::try_from(&Config::default())?)?;
        // Override with settings in file Settings.toml if exists
        conf_rs.merge(File::with_name("Settings").required(false))?;
        // Override with settings in file Rocket.toml if exists
        conf_rs.merge(File::with_name("Rocket").required(false))?;
        // Override any config from env using MERC prefix
        conf_rs.merge(Environment::with_prefix("MERC"))?;

        // Override storage and mainstay config from env variables.
        // Currently doesn't seem to be supported by config_rs.
        // https://github.com/mehcode/config-rs/issues/104
        // A possible alternative would be using a "__" separator
        // e.g. Environment::with_prefix("CO").separator("__")) and
        // setting envs as below but is less readable and confusing
        // CO_CLIENTCHAIN__ASSET_HASH=73be005...
        // CO_CLIENTCHAIN__ASSET=CHALLENGE
        // CO_CLIENTCHAIN__HOST=127.0.0.1:5555
        // CO_CLIENTCHAIN__GENESIS_HASH=706f6...

        if let Ok(v) = env::var("MERC_DB_HOST_W") {
            let _ = conf_rs.set("storage.db_host_w", v)?;
        }
        if let Ok(v) = env::var("MERC_DB_PORT_W") {
            let _ = conf_rs.set("storage.db_port_w", v)?;
        }
        if let Ok(v) = env::var("MERC_DB_USER_W") {
            let _ = conf_rs.set("storage.db_user_w", v)?;
        }
        if let Ok(v) = env::var("MERC_DB_PASS_W") {
            let _ = conf_rs.set("storage.db_pass_w", v)?;
        }
        if let Ok(v) = env::var("MERC_DB_DATABASE_W") {
            let _ = conf_rs.set("storage.db_database_w", v)?;
        }

        if let Ok(v) = env::var("MERC_DB_HOST_R") {
            let _ = conf_rs.set("storage.db_host_r", v)?;
        }
        if let Ok(v) = env::var("MERC_DB_PORT_R") {
            let _ = conf_rs.set("storage.db_port_r", v)?;
        }
        if let Ok(v) = env::var("MERC_DB_USER_R") {
            let _ = conf_rs.set("storage.db_user_r", v)?;
        }
        if let Ok(v) = env::var("MERC_DB_PASS_R") {
            let _ = conf_rs.set("storage.db_pass_r", v)?;
        }
        if let Ok(v) = env::var("MERC_DB_DATABASE_R") {
            let _ = conf_rs.set("storage.db_database_r", v)?;
        }

        if let Ok(v) = env::var("MERC_MS_SLOT") {
            let _ = conf_rs.set("mainstay.position", v)?;
        }

        if let Ok(v) = env::var("MERC_MS_TOKEN") {
            let _ = conf_rs.set("mainstay.token", v)?;
        }

        if let Ok(v) = env::var("MERC_ROCKET_KEEP_ALIVE") {
            let _ = conf_rs.set("rocket.keep_alive", v)?;
        }
        if let Ok(v) = env::var("MERC_ROCKET_ADDRESS") {
            let _ = conf_rs.set("rocket.address", v)?;
        }
        if let Ok(v) = env::var("MERC_ROCKET_PORT") {
            let _ = conf_rs.set("rocket.port", v)?;
        }

        if let Ok(v) = env::var("MERC_UTXO_TIMEOUT") {
            let _ = conf_rs.set("conductor.utxo_timeout", v)?;
        }

        if let Ok(v) = env::var("MERC_GROUP_TIMEOUT") {
            let _ = conf_rs.set("conductor.group_timeout", v)?;
        }

        // Type checks
        let fee_address = conf_rs.get_str("fee_address")?;
        if let Err(e) = bitcoin::Address::from_str(&fee_address) {
            panic!("Invalid fee address: {}", e)
        };
        Ok(conf_rs.try_into()?)
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_deserialize_lockbox() {
        let urls = Some(vec![Url::parse("https://url1.net/").unwrap(), 
                        Url::parse("https://url2.net/").unwrap(), 
                        Url::parse("https://url3.net/").unwrap()]);
    
        let urls_str = "[\"https://url1.net\", \"https://url2.net\", \"https://url3.net\"]";
        let urls_deser: Option<Vec<Url>> = serde_json::from_str(urls_str).unwrap();
        assert_eq!(urls, urls_deser);
    }
}

