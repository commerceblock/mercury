//! Requests
//!
//! Send requests and decode responses

use floating_duration::TimeFormat;
use serde;
use std::time::Duration;
use std::time::Instant;

use super::super::ClientShim;
use super::super::Result;
use crate::error::CError;

pub fn postb<T, V>(client_shim: &ClientShim, path: &str, body: T) -> Result<V>
where
    T: serde::ser::Serialize,
    V: serde::de::DeserializeOwned,
{
    _postb(client_shim, path, body)
}

fn _postb<T, V>(client_shim: &ClientShim, path: &str, body: T) -> Result<V>
where
    T: serde::ser::Serialize,
    V: serde::de::DeserializeOwned,
{
    std::thread::sleep(std::time::Duration::from_millis(100));
    let start = Instant::now();

    let mut b = client_shim
        .client
        .post(&format!("{}/{}", client_shim.endpoint, path));

    if client_shim.auth_token.is_some() {
        b = b.bearer_auth(client_shim.auth_token.clone().unwrap());
    }

    b = b.timeout(Duration::from_secs(300));

    // catch reqwest errors
    let value = match b.json(&body).send() {
        Ok(v) => {
            //Reject responses that are too long
            match v.content_length() {
                Some(l) => {
                    if l > 1000000 {
                        info!("POST value ignored because of size: {}", l);
                        return Err(CError::Generic(format!(
                            "POST value ignored because of size: {}",
                            l
                        )));
                    }
                }
                None => (),
            };

            let text = v.text()?;

            if text.contains(&String::from("Error: ")) {
                return Err(CError::StateEntityError(text));
            }

            text
        }

        Err(e) => return Err(CError::from(e)),
    };

    info!("(req {}, took: {})", path, TimeFormat(start.elapsed()));
    Ok(serde_json::from_str(value.as_str()).expect(&format!("failed to parse: {}", value.as_str())))
}

pub fn get<V>(client_shim: &ClientShim, path: &str) -> Result<V>
where
    V: serde::de::DeserializeOwned,
{
    std::thread::sleep(std::time::Duration::from_millis(100));
    let start = Instant::now();

    let mut b = client_shim
        .client
        .get(&format!("{}/{}", client_shim.endpoint, path));

    if client_shim.auth_token.is_some() {
        b = b.bearer_auth(client_shim.auth_token.clone().unwrap());
    }

    b = b.timeout(Duration::from_secs(300));

    // catch reqwest errors
    let value = match b.send() {
        Ok(v) => v.text().unwrap(),
        Err(e) => return Err(CError::from(e)),
    };

    info!("GET return value: {:?}", value);

    info!("(req {}, took: {})", path, TimeFormat(start.elapsed()));

    // catch State entity errors
    if value.contains(&String::from("Error: ")) {
        return Err(CError::StateEntityError(value));
    }

    Ok(serde_json::from_str(value.as_str())?)
}
