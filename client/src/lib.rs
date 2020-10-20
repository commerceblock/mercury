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

extern crate tokio;
extern crate daemon_engine;

#[macro_use]
extern crate log;

#[macro_use]
extern crate failure;

extern crate base64;
extern crate bitcoin;
extern crate electrumx_client;
extern crate hex;
extern crate itertools;
extern crate pyo3;
extern crate shared_lib;
extern crate uuid;

pub mod ecdsa;
pub mod error;
pub mod state_entity;
pub mod wallet;
pub mod daemon;

mod utilities;

use serde::{Deserialize, Serialize};

use pyo3::prelude::*;
use pyo3::{py_run, PyCell, PyObjectProtocol};

use config::Config as ConfigRs;
use error::CError;

type Result<T> = std::result::Result<T, CError>;

pub mod tor {
    pub static SOCKS5URL: &str = "socks5h://127.0.0.1:9050";
    pub static IPIFYURL: &str = "https://api6.ipify.org?format=json";
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub endpoint: String,
    pub electrum_server: String,
    pub testing_mode: bool,
    pub tor: Tor,
}

impl Config {
    pub fn get() -> Result<Config> {
        let cfg = get_config()?;
        let tor = Tor::from_config(&cfg);
        Ok(Config {
            endpoint: cfg.get("endpoint")?,
            electrum_server: cfg.get("electrum_server")?,
            testing_mode: cfg.get("testing_mode")?,
            tor,
        })
    }
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

pub fn default_config() -> Result<ConfigRs> {
    let mut conf_rs = ConfigRs::new();
    let _ = conf_rs
        // First merge struct default config
        .merge(ConfigRs::try_from(&Config::default())?)?;
    Ok(conf_rs)
}

pub fn get_config() -> Result<ConfigRs> {
    let mut conf_rs = default_config()?;
    // Add in `./Settings.toml`
    conf_rs
        .merge(config::File::with_name("Settings").required(false))?
        // Add in settings from the environment (with prefix "APP")
        // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
        .merge(config::Environment::with_prefix("MERC"))?;
    Ok(conf_rs)
}

#[pyclass]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Tor {
    pub enable: bool,
    pub proxy: String,
    pub control_port: u64,
    pub control_password: String,
}

#[pymethods]
impl Tor {
    fn as_tuple(&self) -> (bool, String, u64, String) {
        (
            self.enable,
            self.proxy.clone(),
            self.control_port,
            self.control_password.clone(),
        )
    }
}

#[pyproto]
impl PyObjectProtocol for Tor {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("enable: {}, proxy: {})", self.enable, self.proxy))
    }
}

impl Default for Tor {
    fn default() -> Self {
        Self {
            enable: false,
            proxy: tor::SOCKS5URL.to_string(),
            control_port: 9051,
            control_password: String::default(),
        }
    }
}

impl Tor {
    pub fn from_config(conf_rs: &ConfigRs) -> Self {
        let mut tor = Self::default();
        match conf_rs.get("tor_enable").ok() {
            Some(v) => tor.enable = v,
            None => (),
        };
        match conf_rs.get("tor_proxy").ok() {
            Some(v) => tor.proxy = v,
            None => (),
        };
        match conf_rs.get("tor_control_port").ok() {
            Some(v) => tor.control_port = v,
            None => (),
        };
        match conf_rs.get("tor_control_password").ok() {
            Some(v) => tor.control_password = v,
            None => (),
        };
        tor
    }

    pub fn get_bytes_read(&self) -> Result<()> {
        let gil = Python::acquire_gil();
        let py = gil.python();
        let tordata = PyCell::new(py, self.to_owned())?;

        py_run!(
            py,
            tordata,
            r#"
            from stem.control import Controller
            with Controller.from_port(port = tordata.as_tuple()[2]) as controller:
                controller.authenticate(tordata.as_tuple()[3])  # provide the password here if you set one

                bytes_read = controller.get_info("traffic/read")
                bytes_written = controller.get_info("traffic/written")

                print("My Tor relay has read %s bytes and written %s bytes." % (bytes_read, bytes_written))
        "#
        );
        Ok(())
    }

    pub fn newnym(&self) -> Result<()> {
        let gil = Python::acquire_gil();
        let py = gil.python();
        let tordata = PyCell::new(py, self.to_owned())?;

        py_run!(
            py,
            tordata,
            r#"
            from stem import Signal
            from stem.control import Controller
            with Controller.from_port(port = tordata.as_tuple()[2]) as controller:
                controller.authenticate(tordata.as_tuple()[3])  # provide the password here if you set one
                controller.signal(Signal.NEWNYM)
        "#
        );
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ClientShim {
    pub client: reqwest::blocking::Client,
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
        let client = Self::new_client(tor.as_ref());
        let cs = ClientShim {
            client,
            tor,
            auth_token,
            endpoint,
        };
        cs
    }

    pub fn new_client(tor: Option<&Tor>) -> reqwest::blocking::Client {
        match tor {
            None => reqwest::blocking::Client::new(),
            Some(t) => match t.enable {
                true => reqwest::blocking::Client::builder()
                    .proxy(reqwest::Proxy::all(&t.proxy).unwrap())
                    .build()
                    .unwrap(),
                false => reqwest::blocking::Client::new(),
            },
        }
    }

    pub fn new_tor_id(&mut self) -> Result<()> {
        match &self.tor {
            Some(t) => {
                t.newnym()?;
                self.client = Self::new_client(self.tor.as_ref());
                Ok(())
            }
            None => Err(CError::TorError("no Tor in ClientShim".to_string())),
        }
    }

    pub fn get_public_ip_address(&self) -> Result<String> {
        let b = self.client.get(tor::IPIFYURL);
        let value = b.send()?.text()?;
        Ok(value)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    #[ignore]
    fn test_tor_control() {
        let config = get_config().expect("failed to get config");
        let tor = Tor::from_config(&config);
        let _ = tor.get_bytes_read().expect("failed to get bytes read");
        let _ = tor.newnym().expect("failed to get new tor identity");
        //let tor_control = TorControl::new(&tor).expect("failed to get new TorControl");
    }

    #[test]
    #[ignore]
    fn test_client_shim_tor_control() {
        let config = Config::get().expect("failed to get config");
        let mut cs = ClientShim::from_config(&config);
        let _ = cs.new_tor_id().expect("failed to get new tor id");
    }

    #[test]
    #[ignore]
    fn test_tor_stats() {
        let config = Config::get().expect("failed to get config");
        let mut cs = ClientShim::from_config(&config);
        let mut buffer = Vec::new();
        let mut sum: f32 = 0.0;
        let mut max: f32 = 0.0;
        let mut min = std::f32::MAX;
        let old_ip = cs
            .get_public_ip_address()
            .expect("failed get_public_ip_address");
        for _ in 0..10 {
            let timer = Instant::now();
            cs.new_tor_id().expect("failed to get new tor id");
            let elapsed = timer.elapsed().as_millis() as f32;
            let new_ip = cs
                .get_public_ip_address()
                .expect("failed get_public_ip_address");
            assert!(new_ip != old_ip, "expected new ip address");
            buffer.push(elapsed);
            println!("{} ms", elapsed);
            sum = sum + elapsed;
            max = max.max(elapsed);
            min = min.min(elapsed);
        }
        let count = buffer.len() as f32;
        let mean = sum / count;
        let variance: f32 = buffer
            .iter()
            .map(|val| {
                let diff = mean - val;
                diff * diff
            })
            .sum::<f32>()
            / count;
        let stdev = variance.sqrt();

        println!("Average time for new tor id is {} +/- {} ms", mean, stdev);
        println!("Longest time: {} ms", max);
        println!("Shortest time: {} ms", min);
    }
}
