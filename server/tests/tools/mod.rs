
extern crate shared_lib;
use server_lib;

use shared_lib::mainstay;
use rocket::http::ContentType;
use rocket::local::Client;
use serde_json;
use std::env;
use std::str::FromStr;
use uuid::Uuid;

use mockito;

pub fn spawn_test_server() -> Client {
    // Set enviroment variable to testing_mode=true to override Settings.toml
    env::set_var("MERC_TESTING_MODE", "true");

    let mainstay_config = mainstay::Config::mock_from_url(&mockito::server_url());
    Client::new(server_lib::server::get_server(Some(mainstay_config)).unwrap())
        .expect("valid rocket instance")
}

#[allow(dead_code)]
pub fn test_server_post<T>(client: &Client, url: &str, body: &T) -> String
where
    T: serde::ser::Serialize,
{
    let mut response = client
        .post(url)
        .body(serde_json::to_string(body).unwrap())
        .header(ContentType::JSON)
        .dispatch();
    response.body_string().unwrap()
}

#[allow(dead_code)]
pub fn test_server_get(client: &Client, url: &str) -> String
{
    let mut response = client
        .get(url)
        .header(ContentType::JSON)
        .dispatch();
    response.body_string().unwrap()
}

#[allow(dead_code)]
// run deposit regression test
pub fn regtest_run_deposit() {
    todo!();
}
