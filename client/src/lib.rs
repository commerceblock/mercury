extern crate centipede;
extern crate config;
extern crate curv;
extern crate kms;
extern crate multi_party_ecdsa;
extern crate reqwest;
extern crate zk_paillier;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate log;

#[macro_use]
extern crate failure;

extern crate base64;
extern crate bitcoin;
extern crate electrumx_client;
extern crate hex;
extern crate itertools;
extern crate uuid;
extern crate shared_lib;
extern crate telnet;
extern crate tor_control;

pub mod ecdsa;
pub mod error;
pub mod state_entity;
pub mod wallet;

mod utilities;

extern crate url;
use url::Url;

use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, error::CError>;

type TorControl = tor_control::TorControl< Writer = BufStream<T>, Error  = tor_control::TCError>

pub mod tor {
    pub static SOCKS5URL : &str = "socks5h://127.0.0.1:9050"; 
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub endpoint: String,
    pub electrum_server: String,
    pub testing_mode: bool,
    pub tor: Tor,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            endpoint: "http://localhost:8000".to_string(),
            electrum_server: "127.0.0.1:60401".to_string(),
            testing_mode: true,
            tor: Tor::default(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Tor {
    pub enable: bool,
    pub proxy: String,
    pub control_port: u64,
    pub control_password: String,
}

impl Default for Tor {
   fn default() -> Self  {
       Self{ 
            enable: false, 
            proxy: tor::SOCKS5URL.to_string(), 
            control_port: 9051,  
            control_password: String::default()
        }
    }
}

impl Tor {
    fn get_control(&self) -> Result<dyn tor_control::TorControl> {
        if (self.enable == false){
            return Err(CError::TorError("cannot get TorControl: Tor not enabled".to_string()));
        }
        let mut url = Url::parse(&self.proxy)?;
        url.set_port(Some(self.control_port as u16))?;
        url.set_scheme(None)?;
        let url = url.into_string();
        let mut tc = tor_control::TorControl::connect(&url)?;
        tc.auth(Some(format!("\"{}\"", tor.control_password)))?;
        tc
    }
}

#[derive(Debug, Clone)]
pub struct ClientShim {
    pub client: reqwest::Client,
    pub tor_control: Option<dyn tor_control::TorControl>,
    pub auth_token: Option<String>,
    pub endpoint: String,
}

impl ClientShim {

    pub fn from_config(config: &Config) -> ClientShim {
        match config.tor.enable {
            true => Self::new(config.endpoint.to_owned(), None, Some(config.tor)),
            false => Self::new(config.endpoint.to_owned(), None, None),
        }
    }

    pub fn new(endpoint: String, auth_token: Option<String>, tor: Option<Tor>) -> ClientShim {
        let (client, tor_control) = match tor {
            None => (reqwest::Client::new(), None),
            Some(t) => match t.enable {
                true => {
                    (reqwest::Client::builder()
                        .proxy(reqwest::Proxy::all(&t.proxy).unwrap())
                        .build().unwrap(),
                        t.get_control()?)
                },
                false => (reqwest::Client::new(), None),
            }
        };

        let cs = ClientShim {
            client,
            tor_control,
            auth_token,
            endpoint,
        };
        cs
    }
}

