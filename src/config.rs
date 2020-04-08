//! # Config
//!
//! Config module handling config options from file/env

use config_rs::{Config as ConfigRs, Environment, File};
use serde::{Deserialize, Serialize};

use crate::error::{CError, Error, Result, InputErrorType::MissingArgument};

#[derive(Debug, Serialize, Deserialize)]
/// Api specific config
pub struct ApiConfig {
    /// Client rpc host
    pub host: String,
    /// Client rpc user
    pub user: String,
    /// Client rpc pass
    pub pass: String,
}

impl Default for ApiConfig {
    fn default() -> ApiConfig {
        ApiConfig {
            host: String::new(),
            user: String::new(),
            pass: String::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
/// Storage specific config
pub struct StorageConfig {
    /// Storage host
    pub host: String,
    /// Storage name
    pub name: String,
    /// Storage user
    pub user: Option<String>,
    /// Storage pass
    pub pass: Option<String>,
}

impl Default for StorageConfig {
    fn default() -> StorageConfig {
        StorageConfig {
            host: String::from("localhost:27017"),
            name: String::from("mercury"),
            user: None,
            pass: None,
        }
    }
}

/// Config struct storing all config
#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// Env logger log level
    pub log_level: String,
    /// Listener host address
    pub listener_host: String,
    /// Api configuration
    pub api: ApiConfig,
    /// Storage configuration
    pub storage: StorageConfig,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            log_level: String::from("mercury"),
            listener_host: String::from("localhost:80"),
            api: ApiConfig::default(),
            storage: StorageConfig::default(),
        }
    }
}


impl Config {
    /// New Config instance reading default values from value
    /// as well as overriden values by the environment
    pub fn new() -> Result<Self> {
        let mut conf_rs = ConfigRs::new();
        let _ = conf_rs
        // First merge struct default config
            .merge(ConfigRs::try_from(&Config::default())?)?
            // Add in defaults from file config/default.toml if exists
            // This is especially useful for local testing config as
            // the default file is not actually loaded in production
            // This could be done with include_str! if ever required
            .merge(File::with_name("config/default").required(false))?
            // Override any config from env using CO prefix and a
            // "_" separator for the nested config in Config
            .merge(Environment::with_prefix("CO"))?;

        if false {
        // if conf_rs.get_str("clientchain.payment_asset")?.len() == 0 {
            return Err(Error::from(CError::InputError(
                MissingArgument,
                "clientchain.payment_asset".into(),
            )));
        }

        Ok(conf_rs.try_into()?)
    }
}
