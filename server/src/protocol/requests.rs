//! Requests
//!
//! Send requests and decode responses

use floating_duration::TimeFormat;
use serde;
use std::time::Instant;
use reqwest;

use super::super::Result;
use crate::error::SEError;
use url::Url;

pub fn post_lb<T, V>(url: &Url, path: &str, body: T) -> Result<V>
where
    T: serde::ser::Serialize,
    V: serde::de::DeserializeOwned,
{
    _post_lb(url, path, body)
}

fn _post_lb<T, V>(url: &Url, path: &str, body: T) -> Result<V>
where
    T: serde::ser::Serialize,
    V: serde::de::DeserializeOwned,
{
    std::thread::sleep(std::time::Duration::from_millis(100));
    let start = Instant::now();
    let client = reqwest::blocking::Client::new();

    // catch reqwest errors
    //let value = match client.post(&format!("{}/{}", url, path)).json(&body).send() 
    let value = match client.post(url.join(path)?.as_str()).json(&body).send() 
    {
        Ok(v) => {
            //Reject responses that are too long
            match v.content_length() {
                Some(l) => {
                    if l > 1000000 {
                        info!("Lockbox POST value ignored because of size: {}", l);
                        return Err(SEError::LockboxError(format!(
                            "POST value ignored because of size: {}",
                            l
                        )));
                    }
                }
                None => (),
            };

            let text = v.text()?;

            text
        },
        Err(e) => return Err(handle_error(e)),
    };

    info!("Lockbox request {}, took: {})", path, TimeFormat(start.elapsed()));

    serde_json::from_str(value.as_str())
        .map_err(|e| SEError::LockboxError(
            format!("failed to deserialize response \"{}\" due to {}", 
                &value.as_str(), e)
            )
        )
}

pub fn post_cln<T, V>(url: &Url, path: &str, body: T, macaroon: &str) -> Result<V>
where
    T: serde::ser::Serialize,
    V: serde::de::DeserializeOwned,
{
    _post_cln(url, path, body, macaroon)
}

fn _post_cln<T, V>(url: &Url, path: &str, body: T, macaroon: &str) -> Result<V>
where
    T: serde::ser::Serialize,
    V: serde::de::DeserializeOwned,
{
    std::thread::sleep(std::time::Duration::from_millis(100));
    let start = Instant::now();
    let client = reqwest::blocking::Client::new();

    info!("CLN path {:?}", path);

    info!("CLN macaroon {:?}", macaroon);

    let msg = client.post(url.join(path)?.as_str()).header("macaroon", macaroon).header("encodingtype","hex").json(&body);

    info!("CLN msg {:?}", msg);   

    // catch reqwest errors
    //let value = match client.post(&format!("{}/{}", url, path)).json(&body).send() 
    let value = match msg.send() 
    {
        Ok(v) => {
            //Reject responses that are too long
            match v.content_length() {
                Some(l) => {
                    if l > 1000000 {
                        info!("CLN POST value ignored because of size: {}", l);
                        return Err(SEError::LockboxError(format!(
                            "POST value ignored because of size: {}",
                            l
                        )));
                    }
                }
                None => (),
            };

            let text = v.text()?;

            text
        },
        Err(e) => return Err(handle_error(e)),
    };

    info!("CLN request {}, took: {})", path, TimeFormat(start.elapsed()));

    serde_json::from_str(value.as_str())
        .map_err(|e| SEError::LockboxError(
            format!("failed to deserialize response \"{}\" due to {}", 
                &value.as_str(), e)
            )
        )
}

pub fn get_cln<V>(url: &Url, path: &str, macaroon: &str) -> Result<V>
where
    V: serde::de::DeserializeOwned,
{
    std::thread::sleep(std::time::Duration::from_millis(100));
    let start = Instant::now();
    let client = reqwest::blocking::Client::new();

    let mut b = client
        .get(&format!("{}{}", url, path))
        .header("macaroon", macaroon)
        .header("encodingtype","hex");

    // catch reqwest errors
    let value = match b.send() {
        Ok(v) => v.text().unwrap(),
        Err(e) => return Err(SEError::Generic(e.to_string())),
    };

    info!("GET return value: {:?}", value);

    info!("(req {}, took: {})", path, TimeFormat(start.elapsed()));

    // catch State entity errors
    if value.contains(&String::from("Error: ")) {
        return Err(SEError::Generic(value));
    }

    serde_json::from_str(value.as_str())        
        .map_err(|e| SEError::Generic(
            format!("failed to deserialize response \"{}\" due to {}", 
                &value.as_str(), e)
            )
        )
}

fn handle_error(e: reqwest::Error) -> SEError {
    info!("Reqwest Error {:?}", e);
    match e.status() {
        Some(v) => SEError::LockboxError(format!("lockbox status code: {}", v)),
        None => SEError::LockboxError(String::from("no status code")),
    }
}
