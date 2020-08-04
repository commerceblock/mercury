
extern crate shared_lib;
use server_lib;

use shared_lib::mainstay;
use rocket::http::ContentType;
use rocket::local::Client;
use serde_json;

use mockito;

pub fn spawn_test_server() -> Client {
    let mainstay_config = mainstay::Config::mock_from_url(&mockito::server_url());
    Client::new(server_lib::server::get_server(Some(mainstay_config)).unwrap())
        .expect("valid rocket instance")
}

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
