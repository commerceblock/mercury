use std::error::Error as StdError;
use std::time::Duration;

use reqwest::Client;
use rusty_s3::actions::{CreateBucket, S3Action, ListObjectsV2, ListObjectsV2Response, ObjectIdentifier};
use rusty_s3::{Bucket, Credentials, UrlStyle};


const ONE_HOUR: Duration = Duration::from_secs(3600);

// NOTE: make sure url, key, secret match your local minio server
// TO RUN: cargo test

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError>> {
    let client = Client::new();

    // connection details to a local minio server
    let url = "".parse().unwrap();
    let key = "";
    let secret = "";
    let region = "minio";

    let mut buf = [0; 8];
    getrandom::getrandom(&mut buf).expect("getrandom");
    let hex = hex::encode(&buf);
    let name = format!("test-{}", hex);

    // create a bucket
    let bucket = Bucket::new(url, UrlStyle::Path, name, region).unwrap();

    // setup action to send to server
    let credential = Credentials::new(key, secret);
    let action = CreateBucket::new(&bucket, &credential);
    let signed_url = action.sign(ONE_HOUR);

    client.put(signed_url).send().await?.error_for_status()?;

    Ok(())
}


////////////////////////////
// TESTS ///////////////////
////////////////////////////

pub async fn bucket() -> (Bucket, Credentials, Client) {
    let mut buf = [0; 8];
    getrandom::getrandom(&mut buf).expect("getrandom");

    let hex = hex::encode(&buf);
    let name = format!("test-{}", hex);

    // connection details to a local minio server
    let url = "".parse().unwrap();
    let key = "";
    let secret = "";
    let region = "minio";

    let bucket = Bucket::new(url, UrlStyle::Path, name, region).unwrap();
    let credentials = Credentials::new(key, secret);

    let client = Client::new();
    let action = CreateBucket::new(&bucket, &credentials);
    let url = action.sign(Duration::from_secs(60));
    client
        .put(url)
        .send()
        .await
        .expect("send CreateBucket request")
        .error_for_status()
        .expect("CreateBucket request unexpected status code");

    (bucket, credentials, client)
}

struct UserSession {
    id: String,
    statechain_id: String,
    authentication: String,
    proofkey: String,
    s2: String, // EC_Scalar ?
    sig_hash: String,
    withdraw_sc_sig: String,
    tx_withdraw: String
}

#[tokio::test]
async fn test_create_bucket_user_table() {
    // Schema: statechainentity
    /*
        Table: User
        id	String (UUID)	true	Primary Key
        statechain_id	String (UUID)	false	Foreign Key for StateChain table
        authentication	undetermined	true	Can be string token for now
        proofkey	String	false	
        s2	EC Scalar	false	Required at transfer to create new User
        sig_hash	String (Hash)	false	Required for any tx signing
        withdraw_sc_sig	StateChainSig	false	Required for withdraw
        tx_withdraw	Transaction	false	Withdraw tx data
    */

    println!("Get bucket, credentials and client");
    let (bucket, credentials, client) = bucket().await;

    println!("User session table test");

    // mock data - // TODO - convert data to json string
    let usersession1 = UserSession {
        id: String::from("1"),
        statechain_id: String::from("someusername123"),
        authentication: String::from(""),
        proofkey: String::from(""),
        s2: String::from(""),
        sig_hash: String::from(""),
        withdraw_sc_sig: String::from(""),
        tx_withdraw: String::from("")
    };

    

    // put request takes a body (the data) and a filename to place the data in
    let body = "[{id: \"\", statechain_id: \"\", authentication: \"empty\", proofkey: \" empty \", s2: \" empty \", sig_hash: \" empty \", withdraw_sc_sig:\" empty \", tx_withdraw: \" empty \"}]";

    let action = bucket.put_object(Some(&credentials), "user.json");
    let url = action.sign(Duration::from_secs(60));
    client
        .put(url)
        .body(body.clone())
        .send()
        .await
        .expect("send PutObject")
        .error_for_status()
        .expect("PutObject unexpected status code");

    
    let action = bucket.get_object(Some(&credentials), "user.json");
    let url = action.sign(Duration::from_secs(60));

    let resp = client
        .get(url)
        .send()
        .await
        .expect("send GetObject")
        .error_for_status()
        .expect("GetObject unexpected status code");
    let bytes = resp.bytes().await.expect("GetObject read response body");

    // check data retreived is the same as the json string form above
    assert_eq!(body, bytes);
}

#[tokio::test]
async fn getcoins() {
    println!("Test was ran3");
}