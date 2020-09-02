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

pub mod ecdsa;
pub mod error;
pub mod state_entity;
pub mod wallet;

mod utilities;

use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, error::CError>;

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

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Clone)]
pub struct ClientShim {
    pub client: reqwest::Client,
    pub auth_token: Option<String>,
    pub endpoint: String,
}

impl ClientShim {

    pub fn from_config(config: &Config) -> ClientShim {
        match config.tor.enable {
            true => Self::new(config.endpoint.to_owned(), None, Some(&config.tor)),
            false => Self::new(config.endpoint.to_owned(), None, None),
        }
    }

    pub fn new(endpoint: String, auth_token: Option<String>, tor: Option<&Tor>) -> ClientShim {
        println!("clinet shim...");
        let client = match tor {
            None => reqwest::Client::new(),
            Some(t) => match t.enable {
                true => {
                    println!("client using tor proxy: {}", t.proxy);
                    reqwest::Client::builder()
                        .proxy(reqwest::Proxy::all(&t.proxy).unwrap())
                        .build().unwrap()
                },
                false => reqwest::Client::new(),
            }
        };
        let cs = ClientShim {
            client,
            auth_token,
            endpoint,
        };
        println!("new clientshim: {:?}", cs);
        cs
    }
}

