//! Requests
//!
//! Send requests and decode responses

use floating_duration::TimeFormat;
use serde;
use std::time::Instant;
use reqwest;

use crate::server::Lockbox;
use super::super::Result;
use crate::error::SEError;

pub fn post_lb<T, V>(lockbox: &Lockbox, path: &str, body: T) -> Result<V>
where
    T: serde::ser::Serialize,
    V: serde::de::DeserializeOwned,
{
    _post_lb(lockbox, path, body)
}

fn _post_lb<T, V>(lockbox: &Lockbox, path: &str, body: T) -> Result<V>
where
    T: serde::ser::Serialize,
    V: serde::de::DeserializeOwned,
{
    std::thread::sleep(std::time::Duration::from_millis(100));
    let start = Instant::now();
    let client = reqwest::blocking::Client::new();

    // catch reqwest errors
    let value = match client.post(&format!("{}/{}", lockbox.endpoint, path)).json(&body).send() 
    {
        Ok(v) => {
            //Reject responses that are too long
            match v.content_length() {
                Some(l) => {
                    if l > 1000000 {
                        info!("Lockbox POST value ignored because of size: {}", l);
                        return Err(SEError::Generic(format!(
                            "Lockbox POST value ignored because of size: {}",
                            l
                        )));
                    }
                }
                None => (),
            };

            let text = v.text()?;

            text
        }
        Err(e) => return sortError(e),
    };

    info!("Lockbox request {}, took: {})", path, TimeFormat(start.elapsed()));
    Ok(serde_json::from_str(value.as_str()).unwrap())
}


fn sortError(Err e){
    // check what e iss
    info!(e);

    // find lock_box url
    let config_rs = Config::load()?;
    let lockbox_url = config_rs.lockbox.clone();

    // change the error codes here - find oout if error has msg property
    if(e.msg === lockbox_url){
        e.msg = "";
    }

    // return e back
    return  e;
}
