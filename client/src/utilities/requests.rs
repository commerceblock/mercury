// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//
use serde;
use std::time::Instant;
use floating_duration::TimeFormat;

use crate::error::CError;
use super::super::ClientShim;
use super::super::Result;

pub fn post<V>(client_shim: &ClientShim, path: &str) -> Result<V>
    where V: serde::de::DeserializeOwned
{
    _postb(client_shim, path, "{}")
}

pub fn postb<T, V>(client_shim: &ClientShim, path: &str, body: T) -> Result<V>
where
    T: serde::ser::Serialize,
    V: serde::de::DeserializeOwned
{
    _postb(client_shim, path, body)
}

fn _postb<T, V>(client_shim: &ClientShim, path: &str, body: T) -> Result<V>
    where
        T: serde::ser::Serialize,
        V: serde::de::DeserializeOwned
{
    let start = Instant::now();

    let mut b = client_shim
        .client
        .post(&format!("{}/{}", client_shim.endpoint, path));

    if client_shim.auth_token.is_some() {
        b = b.bearer_auth(client_shim.auth_token.clone().unwrap());
    }

    // catch reqwest errors
    let value = match b.json(&body).send() {
        Ok(mut v) => v.text().unwrap(),
        Err(e) => return Err(CError::from(e))
    };

    info!("(req {}, took: {})", path, TimeFormat(start.elapsed()));

    // catch State entity errors
    if value == "User authorisation failed".to_string() {
        return Err(CError::StateEntityError(value));
    }
    if value == "Signing Error: No sig hash found for state chain session.".to_string() {
        return Err(CError::StateEntityError(value));
    }
    if value == "Signing Error: Message to be signed does not match verified sig hash.".to_string() {
        return Err(CError::StateEntityError(value));
    }
    if value == "Invalid sig hash - Odd number of characters.".to_string() {
        return Err(CError::StateEntityError(value));
    }

    Ok(serde_json::from_str(value.as_str()).unwrap())
}
