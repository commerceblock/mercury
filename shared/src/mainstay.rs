use std::collections::HashMap;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::key::PrivateKey;
use reqwest;
use base64::encode;
use std::str::FromStr;
use std::string::ToString;
use std::convert::TryInto;
use std::fmt::Display;
use chrono::{DateTime, offset::Utc, NaiveDateTime};
use std::fmt;
use std::error;
use rocket::response::Responder;
use rocket::http::{ Status, ContentType };
use std::io::Cursor;

type Result<T> = std::result::Result<T, Box<dyn error::Error> >;

pub type Hash = monotree::Hash;

type Payload<'a> = HashMap::<&'a str,&'a str>;

#[derive(Serialize, Deserialize, PartialEq, Copy, Default, Debug)]
pub struct Commitment(Option<Hash>);

#[derive(Debug, Deserialize)]
pub enum MainstayError {
    /// Generic error from string error message
    Generic(String),
    /// Invalid argument error
    FormatError(String),
    /// Item not found error
    NotFoundError(String)
}

impl From<String> for MainstayError {
    fn from(e: String) -> Self {
        Self::Generic(e)
    }
}

impl From<&str> for MainstayError {
    fn from(e: &str) -> Self {
        Self::Generic(String::from(e))
    }
}

impl fmt::Display for MainstayError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MainstayError::Generic(ref e) => write!(f, "MainstayError: {}", e),
            MainstayError::FormatError(ref e) => write!(f,"MainstayError::FormatError: {}",e),
            MainstayError::NotFoundError(ref e) => write!(f,"MainstayError::NotFoundError: {}",e),
        }
    }
}

impl error::Error for MainstayError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            _ => None,
        }
    }
}

impl Responder<'static> for MainstayError {
    fn respond_to(self, _: &rocket::Request) -> ::std::result::Result<rocket::Response<'static>, Status> {
        rocket::Response::build()
            .header(ContentType::JSON)
            .sized_body(Cursor::new(format!("{}", self)))
            .ok()
    }
}

use MainstayError::NotFoundError;
use MainstayError::FormatError;

impl Commitment {
    pub fn get_hash(&self) -> Option<Hash> {
        self.0
    }
}

impl std::clone::Clone for Commitment {
    fn clone(&self) -> Self {
        *self
    }
}

impl Display for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            Some(v) => {
                write!(f, "{}", hex::encode(v))
            },
            None => write!(f, "")
        }
    }
}

impl FromStr for Commitment {
    type Err = Box<dyn error::Error>;
    fn from_str(s: &str) -> Result<Self> {
        match hex::decode(s).unwrap()[..].try_into()
        {
            Ok(h) => Ok(Self(Some(h))),
            Err(e) =>  Err(MainstayError::Generic(e.to_string()).into())
        }
    }
}

pub struct Request(reqwest::RequestBuilder);

impl Request {
    //Construct a request from the give payload and config
    pub fn from(payload: Option<&Payload>, command: &String, config: &Config, signature: Option<String>) -> Result<Self> {
        //Build request
        let client = reqwest::Client::new();
        let url = reqwest::Url::parse(&format!("{}/{}",config.url,command))?;
                
        //If there is a payload this is a 'POST' request, otherwise a 'GET' request
        let req = match payload{
            Some(p) => {
                let payload_str = String::from(serde_json::to_string(&p)?);
                let payload_enc = encode(payload_str);
                let mut data = HashMap::new();
                data.insert("X-MAINSTAY-PAYLOAD", &payload_enc);
                let sig_str = match signature {
                    Some(s)=>s,
                    None => String::from("")
                };
                data.insert("X-MAINSTAY-SIGNATURE", &sig_str);
                client.post(url)
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .json(&data)
            },
            None => client.get(url)
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
        };

        Ok(Self(req))
    }

    pub fn send(self) -> std::result::Result<reqwest::Response, reqwest::Error> {
        self.0.send()
    }
}

fn get(command: &str, config: &Config) -> Result<serde_json::Value> {
    let url = reqwest::Url::parse(&format!("{}/{}",config.url,command))?;
    Ok(reqwest::get(url)?.json()?)
}

pub trait Attestable:  {
    //Attest to the mainstay slot using the specified config
    fn attest(&self, config: &Config) -> Result<()>{
        let commitment: &Commitment = &self.commitment()?;
        let signature = match config.key {
            Some(k) => {
                self.sign(&k)?
            },
            None => Commitment(None)
        };

        let mut payload = Payload::new();
        let com = &commitment.to_string();
        let pos = &config.position.to_string();
        let tok = &config.token.to_string();
        payload.insert("commitment", &com);
        payload.insert("position", &pos);
        payload.insert("token", &tok); 
       
        let req = Request::from(Some(&payload), &String::from("commitment/send"), config, Some(signature.to_string()))?.0;        
        let mut res = req.send()?;
        let err_base = "commitment failed";
        
        if res.status().is_success() {    
            match res.json::<serde_json::Value>(){
                Ok(j)=>{
                    let response = Response::from_json(&j)?;
                    match response.response.as_str(){
                        Some(r)=>{
                            match r == "Commitment added" {
                                true => return Ok(()),
                                false => return Err(MainstayError::Generic(format!("{} - expected \"Commitment added\" in response: {:?}", err_base, res)).into())
                            }
                        }
                        None => {
                            return Err(MainstayError::Generic(format!("{} - response: {:?}", err_base, res)).into())
                        }
                    }
                }, 
                Err(e) => Err(e.into())
            }
        } else {
            return Err(MainstayError::Generic(format!("{}", err_base)).into())
        }
    }

    //The data to be commited
    fn commitment(&self) -> Result<Commitment>;

    fn sign(&self, priv_key: &PrivateKey) -> Result<Commitment>{
        let commitment = &self.commitment()?;
        let hash = &commitment.0.unwrap();
        let secp = Secp256k1::new();
        let message = &bitcoin::secp256k1::Message::from_slice(hash).unwrap();
        let signature = secp.sign(message, &priv_key.key).serialize_der().to_vec();
        let mut sig : Hash = Default::default();
        sig.copy_from_slice(&signature);
        Ok(Commitment(Some(sig)))
    }
}

impl Attestable for Hash {
    fn commitment(&self) -> Result<Commitment> {
        let commitment = Commitment::from_hash(&self);
        Ok(commitment)
    }
}

//The commitment of a Hash type is just the Hash itelf
impl Attestable for Commitment {
    fn commitment(&self) -> Result<Commitment>{
        Ok(*self)
    }    
}

impl Commitment {
    pub fn from_hash(hash: &Hash) -> Self {
        Commitment(Some(*hash))
    }
}

//Mainstay configuration
#[derive(Serialize, Deserialize)]
pub struct Config {
    url: String,
    position: u32,
    token: String,
    key: Option<PrivateKey>
}

impl Config {
    pub fn from_test() -> Self {
        Self { position: Self::test_slot(), token: Self::test_token(), ..Default::default() }
    }

    pub fn test_slot() -> u32 {
        match std::env::var("MERC_MS_TEST_SLOT_1="){
            Ok(s) => s.parse::<u32>().unwrap(),   
            Err(_)=> {
                assert!(false);
                Default::default()
            }
        }
    }

    pub fn test_token() -> String {
        match std::env::var("MERC_MS_TEST_TOKEN_1"){
            Ok(t) => t,   
            Err(_)=> {
                assert!(false);
                Default::default()
            }
        }
    }
}

impl FromStr for Config {
    type Err = Box<dyn error::Error>;
    fn from_str(s: &str) -> Result<Self> {
        match serde_json::from_str(s){
            Ok(p) => Ok(p),
            Err(e) =>  Err(MainstayError::Generic(e.to_string()).into())
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self { url: String::from("https://mainstay.xyz/api/v1"), key: None, position: u32::default(),  token: String::default()}
    }
}

#[derive(Serialize, Deserialize)]
struct MSJSON {
    response: Option<serde_json::Value>
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct Response {
    response: serde_json::Value
}

//An object that can be retreived from the API that is indexed with a commitment
//E.g. CommitmentInfo, merkle::Proof
pub trait CommitmentIndexed: APIObject {
    fn from_commitment(config: &Config, commitment: &Commitment) ->Result<Self> {
        let command = &format!("commitment/commitment?commitment={}",commitment);
        Self::from_command(command,config)
    }

    fn from_attestable<T: Attestable>(config: &Config, attestable: &T) ->Result<Self> {
        let commitment=&attestable.commitment()?;
        Self::from_commitment(config, commitment)
    }
}

pub trait APIObject: Sized {
    fn from_json(json_data: &serde_json::Value) -> Result<Self>;

    fn from_command(command: &str, config: &Config) -> Result<Self> {
        let response = get(command, config);
        match response {
            Ok(r) => Self::from_json(&r),
            Err(e) => Err(MainstayError::Generic(e.to_string()).into())
        }   
    }
}

impl APIObject for Response {
    fn from_json(json_data: &serde_json::Value) -> Result<Self>{       
        println!("parsing response: {:?}", json_data);
        match json_data.get("response"){
            Some(r) => {
                println!("got response object: {:?}", r);
                Ok(Self{response:r.clone()})
            },
            None => {
                match json_data.get("error") {
                    Some(e) => Err(NotFoundError(format!("{}", e)).into()),
                    None => {   
                        println!("got response object 2: {:?}", json_data);
                        Ok(Self{response:json_data.clone()})
                    }
                }
            }
        }
    }
}

 #[derive(Serialize, Deserialize, PartialEq, Debug)]
//Information about a commitment: it's attestation, if any, and its proof
pub struct CommitmentInfo {
    attestation: Option<Attestation>,
    merkleproof: merkle::Proof
}

/*
impl fmt::Debug for CommitmentInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Point")
         .field("x", &self.x)
         .field("y", &self.y)
         .finish()
    }
}
*/

impl CommitmentInfo {
    pub fn merkle_root(&self) -> &Commitment {
        &self.merkleproof.merkle_root()
    }

    //Is the commitment attested or not?
    pub fn is_confirmed(&self) -> bool {
        match &self.attestation {
            Some(a) => {
                return a.confirmed
            },
            None => false
        } 
    }
}

impl APIObject for CommitmentInfo{
    fn from_json(json_data: &serde_json::Value) -> Result<Self>{
        let resp = &Response::from_json(json_data)?;
        let mp = merkle::Proof::from_response(resp)?;
        match Attestation::from_response(resp){
            Ok(a) => Ok(Self{attestation: Some(a),merkleproof:mp}),
            Err(e) => Err(e)
        }
    }
}

impl CommitmentIndexed for CommitmentInfo {}


#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Attestation {
    merkle_root: Commitment,
    txid: Commitment,
    confirmed: bool,
    inserted_at: DateTime<Utc>
}

impl APIObject for Attestation {
    fn from_json(json_data: &serde_json::Value) -> Result<Self>{    
        let resp = Response::from_json(json_data);
        if resp.is_ok(){
            let resp = resp?;
            return Ok(Self::from_response(&resp)?);
        }
        Ok(Self::from_json_attestation(json_data.get("attestation").ok_or(NotFoundError("attestation".to_string()))?)?)
    }
}


fn get_val<'a>(val: &'a serde_json::Value, key: &str) -> Result<&'a serde_json::Value> {
    Ok(val.get(key).ok_or(NotFoundError(key.to_string()))?)
}

fn get_str<'a>(val: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    val.get(key).ok_or(NotFoundError(key.to_string()))?.as_str().ok_or(FormatError(key.to_string()).into())
}

fn get_bool(val: &serde_json::Value, key: &str) -> Result<bool> {
    val.get(key).ok_or(NotFoundError(key.to_string()))?.as_bool().ok_or(FormatError(key.to_string()).into())
}

fn get_array<'a>(val: &'a serde_json::Value, key: &str) -> Result<&'a std::vec::Vec<serde_json::Value>> {
    val.get(key).ok_or(NotFoundError(key.to_string()))?.as_array().ok_or(FormatError(key.to_string()).into())
}

fn get_commitment(val: &serde_json::Value, key: &str) -> Result<Commitment> {
    Commitment::from_str(get_str(val,key)?)
}


impl Attestation {
      pub fn from(merkle_root: Commitment, txid: Commitment, confirmed: bool, inserted_at: DateTime<Utc>) -> Self{
        Self{merkle_root:merkle_root, txid:txid, confirmed: confirmed, inserted_at: inserted_at}
    }

    pub fn merkle_root(&self) -> &Commitment {
        &self.merkle_root
    }

    fn from_response(response: &Response) -> Result<Self>{       
        let val = response.response.get("attestation").ok_or(NotFoundError("attestation object not found in Mainstay::Response".to_string()))?;
        Ok(Self::from_json_attestation(&val)?)
    }

    fn from_json_attestation(val: &serde_json::Value) -> Result<Self>{          
        println!("parsing attestation: {:?}", val);
        println!("parsing attestation: merkle_root");
        let merkle_root = get_commitment(val,"merkle_root")?; 
        println!("parsing attestation: txid");
        let txid = get_commitment(val,"txid")?;
        println!("parsing attestation: confirmed");
        let confirmed = get_bool(val,"confirmed")?;
        println!("parsing attestation: inserted_at");
        let inserted_at = String::from(get_str(val,"inserted_at")?);
        println!("inserted_at string: {}", inserted_at);
        match inserted_at.contains(" UTC"){
            true => {
                let inserted_at = inserted_at.replace(" UTC","");
                let inserted_at = DateTime::<Utc>::from_utc(NaiveDateTime::parse_from_str(&inserted_at, "%H:%M:%S %m/%d/%Y")?, Utc);
                Ok(Self::from(merkle_root, txid, confirmed, inserted_at))
            }
            false => Err(MainstayError::Generic(String::from("expected UTC in DateTime string")).into()),
        }
    }
        
}


pub mod merkle {
    use super::*;
    //Double sha256
    use bitcoin::hashes::sha256d::Hash as SHAHash;

    //use fmt;
    //use std::hash::Hasher;
    //use crypto::sha3::{Sha3, Sha3Mode};
    //use crypto::digest::Digest;
    use merkletree::hash;
    //::{Algorithm, Hashable};

/*
    pub struct HashAlgo(SHAHash);

    impl HashAlgo {
        pub fn new() -> HashAlgo {
            let shaHash = SHAHash::new();
            HashAlgo(SHAHash::new());
        }
    }

    impl Default for HashAlgo {
        fn default() -> HashAlgo {
            HashAlgo::new();
        }
    }


    //use std::str::FromStr;
*/

/*
"attestation":
{
    "merkle_root": "f46a58a0cc796fade0c7854f169eb86a06797ac493ea35f28dbe35efee62399b",
    "txid": "38fa2c6e103673925aaec50e5aadcbb6fd0bf1677c5c88e27a9e4b0229197b13",
    "confirmed": true,
    "inserted_at": "16:06:41 23/01/19"
}
*/

    #[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
    pub struct Proof {
        merkle_root: Commitment,
        commitment: Commitment,
        ops: Vec<Commitment>
    }

    impl CommitmentIndexed for Proof{}

    impl APIObject for Proof {
        fn from_json(json_data: &serde_json::Value) -> Result<Self>{
            println!("trying from response");
            let resp = Response::from_json(json_data);
            if resp.is_ok(){
                println!("response is ok, parsing");
                return Ok(Self::from_response(&resp?)?);        
            } 
                 
            println!("trying from merkleproof json");
            let json_data = match json_data.get("merkleproof"){
                Some(val) => val,
                None => json_data
            };

            Ok(Self::from_merkleproof_json(json_data)?)
        }
    }

    impl Proof {

        pub fn from(merkle_root: Commitment, commitment: Commitment, ops: Vec<Commitment>) -> Self{
            Self{merkle_root: merkle_root, commitment: commitment, ops: ops}
        }

        pub fn merkle_root(&self) -> &Commitment {
            &self.merkle_root
        }

        pub fn from_latest_proof(config: &Config) -> Result<Self> {
            let command = format!("commitment/latestproof?position={}",config.position);
            Self::from_command(&command, config)
        }

        pub fn from_response(response: &Response) -> Result<Self>{       
            match response.response.get("merkleproof"){
                Some(val) => Self::from_merkleproof_json(val),
                None => {
                    Self::from_merkleproof_json(&response.response)
                }
            }
        }

        fn from_merkleproof_json(val: &serde_json::Value) -> Result<Self>{
            println!("parsing merkleproof JSON object: {:?}", val);

            let err = MainstayError::from(format!("Mainstay merkle::Proof: error parsing merkleproof for JSON object: {:?}", val));
                        
            println!("parsing merkle_root");
            let merkle_root = get_commitment(val,"merkle_root")?; 

            println!("parsing commitment");
            let commitment = get_commitment(val, "commitment")?; 

            println!("parsing ops");
            let mut ops = Vec::<Commitment>::new();
            let ops_arr = get_array(val, "ops")?;
            for op in ops_arr {
                ops.push(get_commitment(op,"commitment")?)
            }
            println!("fiished parsing merkleproof JSON object");
            Ok(Proof::from(merkle_root, commitment, ops))
        }
    }

    impl FromStr for Proof {
        type Err = Box<dyn error::Error>;
        fn from_str(s: &str) -> Result<Self> {
            println!("parsing merkle::Proof from string: {}",s);
            let json_data : serde_json::Value = serde_json::from_str(s)?;
            println!("JSON data from string: {:?}",&json_data);
            Self::from_json(&json_data)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::keygen::generate_keypair;
        
    #[test]
    fn commit() {
                
        let random_hash = Commitment::from_hash(&monotree::utils::random_hash());

        let config = Config::from_test();

        match random_hash.attest(&config) {
            Ok(()) => assert!(true),
            Err(_) => assert!(false)
        }

        //Incorrect token should fail.
        let token = String::from("wrong_token");
        let config = Config { position: Config::test_slot(), token: token, ..Default::default() };        

        match random_hash.attest(&config) {
            Ok(()) => assert!(false, "should have failed with incorrect token"),
            Err(_) => {
                println!("Correctly failed with incorrect token");
            }
        }
    } 

    #[test]
    fn test_config() {
        let (priv_key, _pub_key) = generate_keypair();
        let privkey_str = priv_key.to_wif().to_string();

        let (priv_key_2, _pub_key_2) = generate_keypair();
        
        let str_1="{\"url\":\"https://mainstay.xyz/api/v1\", \"position\":234, \"token\":\"mytoken\"}";
        let str_2=format!("{{\"url\":\"https://mainstay.xyz/api/v1\", \"position\":234, \"token\":\"mytoken\", \"key\":\"{}\"}}", privkey_str);
        let config_1 = Config::from_str(str_1).unwrap();
        assert!(config_1.url == "https://mainstay.xyz/api/v1", "url parse fail");
        assert!(config_1.position == 234, "position parse fail");
        assert!(config_1.token == "mytoken", "token parse fail");
        assert!(config_1.key == None, "key parse fail");
        let config_2 = Config::from_str(&str_2).unwrap();
        assert!(config_2.key.unwrap().key == priv_key.key, "str_2 key parse fail");
        assert!(config_2.key.unwrap().key != priv_key_2.key, "str_2 key parse check fail");
    }

    #[test]
    fn parse_response() {

        let data_str = "{\"response\":{
                \"attestation\":{\"merkle_root\":\"47fc767ebc5095133d6de9a060c248c115b3fdf5f30921de2ee111225690de01\",
        \"txid\":\"4be7f5fbd3272cec65e520f5b04c79c2059548c4576558aac3f4f6655138d5d4\",\"confirmed\":true,
        \"inserted_at\":\"12:07:54 05/02/2020 UTC\"},
        \"merkleproof\":{\"position\":1,
        \"merkle_root\":\"47fc767ebc5095133d6de9a060c248c115b3fdf5f30921de2ee111225690de01\",
        \"commitment\":\"71c7f2f246caf3e4f0b94ea4ad54b6c506687069bf1e17024cd5961b0df78d6d\",
        \"ops\":[{\"append\":false,\"commitment\":\"31e66288b9074bcfeb3bc5734f2d0b189ad601b61f86b8241ee427648b59fdbc\"},
        {\"append\":true,\"commitment\":\"60da74551926c4283dd4b4e295d2a1eb5147b5cf6c7c2019e8b64c22a1ba5bab\"},{\"append\":true,
        \"commitment\":\"94adb04ab09036fbc6cc164ec6df4d9d8fba45bcd7901a03d2e91b123071a5ec\"}]}}
        ,\"timestamp\":1593160486862,
        \"allowance\":{\"cost\":17954530}
        }";

        let response_str = "{\"attestation\":{\"merkle_root\":\"47fc767ebc5095133d6de9a060c248c115b3fdf5f30921de2ee111225690de01\",
        \"txid\":\"4be7f5fbd3272cec65e520f5b04c79c2059548c4576558aac3f4f6655138d5d4\",\"confirmed\":true,
        \"inserted_at\":\"12:07:54 05/02/2020 UTC\"},\"merkleproof\":{\"position\":1,
        \"merkle_root\":\"47fc767ebc5095133d6de9a060c248c115b3fdf5f30921de2ee111225690de01\",
        \"commitment\":\"71c7f2f246caf3e4f0b94ea4ad54b6c506687069bf1e17024cd5961b0df78d6d\",
        \"ops\":[{\"append\":false,\"commitment\":\"31e66288b9074bcfeb3bc5734f2d0b189ad601b61f86b8241ee427648b59fdbc\"},
        {\"append\":true,\"commitment\":\"60da74551926c4283dd4b4e295d2a1eb5147b5cf6c7c2019e8b64c22a1ba5bab\"},{\"append\":true,
        \"commitment\":\"94adb04ab09036fbc6cc164ec6df4d9d8fba45bcd7901a03d2e91b123071a5ec\"}]}}";
        

        let merkleproof_str = 
                "{\"position\":1,
                \"merkle_root\":\"47fc767ebc5095133d6de9a060c248c115b3fdf5f30921de2ee111225690de01\",
                \"commitment\":\"71c7f2f246caf3e4f0b94ea4ad54b6c506687069bf1e17024cd5961b0df78d6d\",
                \"ops\":[{\"append\":false,\"commitment\":\"31e66288b9074bcfeb3bc5734f2d0b189ad601b61f86b8241ee427648b59fdbc\"},
                {\"append\":true,\"commitment\":\"60da74551926c4283dd4b4e295d2a1eb5147b5cf6c7c2019e8b64c22a1ba5bab\"},{\"append\":true,
                \"commitment\":\"94adb04ab09036fbc6cc164ec6df4d9d8fba45bcd7901a03d2e91b123071a5ec\"}]}";


        let merkleproof_1 = merkle::Proof::from_str(data_str).unwrap();
        let merkleproof_2 = merkle::Proof::from_str(response_str).unwrap();
        let merkleproof_3 = merkle::Proof::from_str(merkleproof_str).unwrap();

        let mut ops= Vec::<Commitment>::new();
        ops.push(Commitment::from_str("31e66288b9074bcfeb3bc5734f2d0b189ad601b61f86b8241ee427648b59fdbc").unwrap());
        ops.push(Commitment::from_str("60da74551926c4283dd4b4e295d2a1eb5147b5cf6c7c2019e8b64c22a1ba5bab").unwrap());
        ops.push(Commitment::from_str("94adb04ab09036fbc6cc164ec6df4d9d8fba45bcd7901a03d2e91b123071a5ec").unwrap());
        let merkle_root = Commitment::from_str("47fc767ebc5095133d6de9a060c248c115b3fdf5f30921de2ee111225690de01").unwrap();
        let commitment = Commitment::from_str("71c7f2f246caf3e4f0b94ea4ad54b6c506687069bf1e17024cd5961b0df78d6d").unwrap();

        let merkleproof_compare = merkle::Proof::from(merkle_root, commitment, ops);

        assert!(merkleproof_1 ==merkleproof_2);
        assert!(merkleproof_1 ==merkleproof_3);
        assert!(merkleproof_1 ==merkleproof_compare);
    }

    
    #[test]
    fn get_latest_proof() {
        match merkle::Proof::from_latest_proof(&Config::from_test()){
            Ok(_) => assert!(true),
            Err(_) => {
                assert!(false);
            }
        };
    }

    #[test]
    fn get_proof_from_commitment() {
        //Retrieve the proof for a commitment
        let commitment = &Commitment::from_str("31e66288b9074bcfeb3bc5734f2d0b189ad601b61f86b8241ee427648b59fdbc").unwrap();
        
        let config = Config::from_test();

        let proof1 = merkle::Proof::from_commitment(&config, commitment).unwrap();
        
        let proof2 = merkle::Proof::from_attestable::<Commitment>(&config, commitment).unwrap();

        assert!(proof1 == proof2);
    }

    #[test]
    fn get_commitment_info() {
        //Retrieve the proof for a commitment
        let commitment = &Commitment::from_str("31e66288b9074bcfeb3bc5734f2d0b189ad601b61f86b8241ee427648b59fdbc").unwrap();
        
        let config = Config::from_test();

        let proof1 = CommitmentInfo::from_commitment(&config, commitment).unwrap();
        
        let proof2 = merkle::Proof::from_attestable::<Commitment>(&config, commitment).unwrap();

        assert!(proof1.merkleproof == proof2);
    }

    #[test]
    fn test_commitment_to_from_str() {
        let com1 = Commitment::from_hash(&monotree::utils::random_hash());
        let str1 = com1.to_string();
        let com2 = Commitment::from_str(&str1).unwrap();
        assert!(com1 == com2, format!("{} does not equal {}", com1, com2));
    }
}