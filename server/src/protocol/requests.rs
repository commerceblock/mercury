//! Requests
//!
//! Send requests and decode responses

use floating_duration::TimeFormat;
use serde;
use std::time::Instant;
use reqwest;

use super::super::Result;
use crate::error::SEError;

pub fn post_lb<T, V>(url: &str, path: &str, body: T) -> Result<V>
where
    T: serde::ser::Serialize,
    V: serde::de::DeserializeOwned,
{
    _post_lb(url, path, body)
}

fn _post_lb<T, V>(url: &str, path: &str, body: T) -> Result<V>
where
    T: serde::ser::Serialize,
    V: serde::de::DeserializeOwned,
{
    std::thread::sleep(std::time::Duration::from_millis(100));
    let start = Instant::now();
    let client = reqwest::blocking::Client::new();

    // catch reqwest errors
    let value = match client.post(&format!("{}/{}", url, path)).json(&body).send() 
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
            format!("failed to deserialize response {} due to {}", 
                &value.as_str(), e)
            )
        )
}

fn handle_error(e: reqwest::Error) -> SEError {
    match e.status() {
        Some(v) => SEError::LockboxError(format!("lockbox status code: {}", v)),
        None => SEError::LockboxError(String::from("no status code")),
    }
}
