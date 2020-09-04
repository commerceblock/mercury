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
extern crate pyo3;

pub mod ecdsa;
pub mod error;
pub mod state_entity;
pub mod wallet;

mod utilities;

extern crate url;
use url::Url;

use serde::{Deserialize, Serialize};

use pyo3::prelude::*;
use pyo3::types::IntoPyDict;

use error::CError;

type Result<T> = std::result::Result<T, CError>;


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
    /*
    fn get_control(&self) -> Result<TorControl> {
        if (self.enable == false){
            return Err(CError::TorError("cannot get TorControl: Tor not enabled".to_string()));
        }
        let mut url = Url::parse(&self.proxy)?;
        url.set_port(Some(self.control_port as u16))?;
        //url.set_scheme(None)?;
        let url = url.into_string();
        let mut tc = TorControl::new(&self)?;
        tc.connect(url)?;
        //tc.auth(Some(format!("\"{}\"", self.control_password)))?;
        Ok(tc)
    }
    */

    pub fn get_bytes_read(&self) -> Result<u64> {
        //let gil = Python::acquire_gil();
        //let py = gil.python();
        //let ct = PyModule::import(py,"stem.controller")?;
        //ct.call1("authenticate",(&self.control_password.to_owned(),))?;
        //let bytes_read: u64 = ct.call1("get_info", ("traffic/read",))?.extract()?;
        //Ok(bytes_read)
        Ok(0)
    }
}

#[derive(Debug, Clone)]
pub struct ClientShim {
    pub client: reqwest::Client,
    pub tor: Option<Tor>,
    pub auth_token: Option<String>,
    pub endpoint: String,
}

impl ClientShim {

    pub fn from_config(config: &Config) -> ClientShim {
        match config.tor.enable {
            true => Self::new(config.endpoint.to_owned(), None, Some(config.tor.clone())),
            false => Self::new(config.endpoint.to_owned(), None, None),
        }
    }

    pub fn new(endpoint: String, auth_token: Option<String>, tor: Option<Tor>) -> ClientShim {
        let client = match tor.as_ref() {
            None => reqwest::Client::new(),
            Some(t) => match t.enable {
                true => reqwest::Client::builder()
                        .proxy(reqwest::Proxy::all(&t.proxy).unwrap())
                        .build().unwrap(),
                false => reqwest::Client::new(),
            }
        };

        let cs = ClientShim {
            client,
            tor,
            auth_token,
            endpoint,
        };
        cs
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    
    #[test]
    fn test_tor_control(){
        //let tor = Tor::default();
        //let tor_control = TorControl::new(&tor).expect("failed to get new TorControl");
    }

}