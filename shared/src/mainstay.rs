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
use merkletree::hash::{Algorithm};
use std::hash::Hasher;

type Result<T> = std::result::Result<T, Box<dyn error::Error> >;

pub type Hash = monotree::Hash;

type Payload<'a> = HashMap<&'a str,&'a str>;

#[derive(Serialize, Deserialize, PartialEq, Copy, Default, Debug)]
pub struct Commitment(Option<Hash>);

#[derive(Debug, Deserialize)]
pub enum MainstayError {
    /// Generic error from string error message
    Generic(String),
    /// Invalid argument error
    FormatError(String),
    /// Item not found error
    NotFoundError(String),
    /// Cryptographic proof error
    ProofError(String)
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
            MainstayError::ProofError(ref e) => write!(f,"MainstayError::ProofError: {}",e),
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
use MainstayError::ProofError;

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
        match hex::decode(s)?[..].try_into()
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
    pub fn from_test() -> Option<Self> {
        match (Self::test_slot(), Self::test_token()) {
            (Some(s), Some(t)) => Some(Self { position: s, token: t, ..Default::default() }),
            (Some(_), None) => None,
            (None, Some(_)) => None,
            (None, None) => None
        }
    }

    pub fn test_slot() -> Option<u32> {
        match std::env::var("MERC_MS_TEST_SLOT="){
            Ok(s) => s.parse::<u32>().ok(),
            Err(_)=> None
        }
    }

    pub fn test_token() -> Option<String> {
        match std::env::var("MERC_MS_TEST_TOKEN"){
            Ok(t) => t.parse::<String>().ok(),
            Err(_)=> None
        }
    }

    pub fn info() -> &'static str{
        "To configure mainstay tests set the following environment variables: MERC_MS_TEST_SLOT=<slot> MERC_MS_TEST_TOKEN=<token>"
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
        debug!("parsing response: {:?}", json_data);
        match json_data.get("response"){
            Some(r) => {
                debug!("got response object: {:?}", r);
                Ok(Self{response:r.clone()})
            },
            None => {
                match json_data.get("error") {
                    Some(e) => Err(NotFoundError(format!("{}", e)).into()),
                    None => {   
                        debug!("got response object 2: {:?}", json_data);
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

    pub fn commitment(&self) -> &Commitment {
        &self.merkleproof.commitment()
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
    get_val(val,key)?.as_str().ok_or(FormatError(key.to_string()).into())
}

fn get_bool(val: &serde_json::Value, key: &str) -> Result<bool> {
    get_val(val,key)?.as_bool().ok_or(FormatError(key.to_string()).into())
}

fn get_array<'a>(val: &'a serde_json::Value, key: &str) -> Result<&'a std::vec::Vec<serde_json::Value>> {
    get_val(val,key)?.as_array().ok_or(FormatError(key.to_string()).into())
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
        debug!("parsing attestation: {:?}", val);
        debug!("parsing attestation: merkle_root");
        let merkle_root = get_commitment(val,"merkle_root")?; 
        debug!("parsing attestation: txid");
        let txid = get_commitment(val,"txid")?;
        debug!("parsing attestation: confirmed");
        let confirmed = get_bool(val,"confirmed")?;
        debug!("parsing attestation: inserted_at");
        let inserted_at = String::from(get_str(val,"inserted_at")?);
        debug!("inserted_at string: {}", inserted_at);
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
    #[allow(unused_imports)]
    use bitcoin::hashes::sha256::HashEngine as SHAHashEngine;
    use bitcoin::hashes::sha256d::Hash as SHAHash; 
    use bitcoin_hashes::Hash as HashesHash;
    use bitcoin_hashes::HashEngine as HashesHashEngine;
    use merkletree::hash::Hashable;
    use crypto::digest::Digest;
    use bitcoin::util::hash::BitcoinHash;
 
    
    #[allow(unused_imports)]
    use merkletree::hash;
    use crypto::sha3::{Sha3, Sha3Mode};
    use crypto::sha2::{Sha256};


    use merkletree::store::VecStore;
    use merkletree::merkle::MerkleTree;

    
    //pub struct HashAlgo(Sha256);
    pub struct HashAlgo(SHAHashEngine);
    

    
    impl HashAlgo {
        pub fn new() -> HashAlgo {
            //HashAlgo(Sha3::new(Sha3Mode::Sha3_256))
            let engine = SHAHash::engine();
            HashAlgo(engine)
        }
    }

    impl Default for HashAlgo {
        fn default() -> HashAlgo {
            HashAlgo::new()
        }
    }

    impl Hasher for HashAlgo {
        #[inline]
        fn write(&mut self, msg: &[u8]) {
            self.0.input(msg);
        }

        #[inline]
        fn finish(&self) -> u64 {
            unimplemented!()
        }
    }

    impl Algorithm<[u8; 32]> for HashAlgo {
        #[inline]
        fn hash(&mut self) -> [u8; 32] {
            SHAHash::from_engine(self.0.clone()).into_inner()
        }
    
        #[inline]
        fn reset(&mut self) {
            self.0 = SHAHash::engine();
        }
    }
    

    #[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
    pub struct Proof {
        merkle_root: Commitment,
        commitment: Commitment,
        ops: Vec<Commitment>
    }

    impl CommitmentIndexed for Proof{}

    impl APIObject for Proof {
        fn from_json(json_data: &serde_json::Value) -> Result<Self>{
            debug!("trying from response");
            let resp = Response::from_json(json_data);
            if resp.is_ok(){
                debug!("response is ok, parsing");
                return Ok(Self::from_response(&resp?)?);        
            } 
                 
            debug!("trying from merkleproof json");
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

        pub fn commitment(&self) -> &Commitment {
            &self.commitment
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
            debug!("parsing merkleproof JSON object: {:?}", val);
                        
            debug!("parsing merkle_root");
            let merkle_root = get_commitment(val,"merkle_root")?; 

            debug!("parsing commitment");
            let commitment = get_commitment(val, "commitment")?; 

            debug!("parsing ops");
            let mut ops = Vec::<Commitment>::new();
            let ops_arr = get_array(val, "ops")?;
            for op in ops_arr {
                ops.push(get_commitment(op,"commitment")?)
            }
            debug!("finished parsing merkleproof JSON object");
            Ok(Proof::from(merkle_root, commitment, ops))
        }

        pub fn verify(&self) -> Result<()>{
            let mut h1 = [0u8; 32];
            let mut h2 = [0u8; 32];
            let mut h3 = [0u8; 32];
            let mut h4 = [0u8; 32];
            h1[0] = 0x11;
            h2[0] = 0x22;
            h3[0] = 0x33;
            h4[0] = 0x44;

            //let iter1 = vec![h1, h2, h3, h4].into_iter().map(Ok);
            
            //let t : MerkleTree<[u8; 32], HashAlgo, VecStore<_>> = MerkleTree::try_from_iter(vec![h1, h2, h3, h4].into_iter().map(Ok))?;

            println!("length of ops: {}", self.ops.len());

            let mut vec_ops = self.ops.clone();
            if vec_ops.len() % 2 > 0 {
                vec_ops.push(Commitment::from_hash(&[0u8; 32]))
            }

            println!("vec ops: {:?}", vec_ops);

            let t: MerkleTree<[u8; 32], HashAlgo, VecStore<_>> = MerkleTree::try_from_iter(
                vec_ops.into_iter().map(|x| x.get_hash().unwrap()).map(Ok)
            )?;

            //let iter2 = vec_ops.into_iter().map(|x| x.get_hash().unwrap()).map(Ok);

            //println!("iter1, iter2:: {:?}, {:?}", iter1, iter2);
                        
            match t.root() == self.merkle_root.get_hash().unwrap(){
                true => Ok(()),
                false => Err(MainstayError::ProofError(format!("calculated root: {:?}, expected root: {:?}", t.root(), self.merkle_root)).into()),
            }
        }
    }

    impl FromStr for Proof {
        type Err = Box<dyn error::Error>;
        fn from_str(s: &str) -> Result<Self> {
            debug!("parsing merkle::Proof from string: {}",s);
            let json_data : serde_json::Value = serde_json::from_str(s)?;
            debug!("JSON data from string: {:?}",&json_data);
            Self::from_json(&json_data)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::keygen::generate_keypair;
        
    #[test]
    fn test_hash() { 
        let commitment : Hash = Commitment::from_str("31e66288b9074bcfeb3bc5734f2d0b189ad601b61f86b8241ee427648b59fdbc").unwrap().get_hash().unwrap();
        let mut hasher = merkle::HashAlgo::new();
        hasher.write(&commitment);
        let hash = hasher.hash();
        let expected_hash  : Hash = Commitment::from_str("bd23c4720e83435818a1074b33891a05e2112c5e510bdffdc3e276ad3b7f378b").unwrap().get_hash().unwrap();
        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_commit() {
                
        let random_hash = Commitment::from_hash(&monotree::utils::random_hash());

        let config = Config::from_test().expect(Config::info());        
             
        match random_hash.attest(&config) {
            Ok(()) => assert!(true),
            Err(_) => assert!(false)
        }

        //Incorrect token should fail.
        let token = String::from("wrong_token");
        let config = Config { position: Config::test_slot().unwrap(), token: token, ..Default::default() };        

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
    fn test_proof() {

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
        
        match merkleproof_1.verify(){
            Ok(_) => (),
            Err(e) => {
                assert!(false, e.to_string());
                ()
            }
        }
    }

    
    #[test]
    fn test_get_latest_proof() {
        let config = Config::from_test().expect(Config::info());        

        match merkle::Proof::from_latest_proof(&config){
            Ok(_) => assert!(true),
            Err(e) => {
                assert!(false, e.to_string());
            }
        };
    }

    #[test]
    fn test_get_proof_from_commitment() {
        let config = Config::from_test().expect(Config::info());        
        
        //Retrieve the proof for a commitment
        let commitment = &Commitment::from_str("31e66288b9074bcfeb3bc5734f2d0b189ad601b61f86b8241ee427648b59fdbc").unwrap();

        let proof1 = merkle::Proof::from_commitment(&config, commitment).unwrap();
        
        let proof2 = merkle::Proof::from_attestable::<Commitment>(&config, commitment).unwrap();

        assert!(proof1 == proof2);

        //Don't retreive the proof for a non-existent commitment
        let commitment = &Commitment::from_hash(&monotree::utils::random_hash());

        assert!(merkle::Proof::from_commitment(&config, commitment).is_err(), "should not be able to retrieve proof for random commitment");
        assert!(merkle::Proof::from_attestable::<Commitment>(&config, commitment).is_err(), "should not be able to retrieve proof for random commitment");
    }

    #[test]
    fn test_get_commitment_info() {
        let config = Config::from_test().expect(Config::info());        
    
       //Retrieve the proof for a commitment
        let commitment = &Commitment::from_str("31e66288b9074bcfeb3bc5734f2d0b189ad601b61f86b8241ee427648b59fdbc").unwrap();

        let proof1 = CommitmentInfo::from_commitment(&config, commitment).unwrap();
        
        let proof2 = merkle::Proof::from_attestable::<Commitment>(&config, commitment).unwrap();

        assert!(proof1.merkleproof == proof2);

        //Don't retreive the proof for a non-existent commitment
        let commitment = &Commitment::from_hash(&monotree::utils::random_hash());

        assert!(CommitmentInfo::from_commitment(&config, commitment).is_err(), "should not be able to retrieve random commitment");
        assert!(merkle::Proof::from_attestable::<Commitment>(&config, commitment).is_err(), "should not be able to retrieve random commitment");

    }

    #[test]
    fn test_commitment_to_from_str() {
        let com1 = Commitment::from_hash(&monotree::utils::random_hash());
        let com2 = Commitment::from_str(&com1.to_string()).unwrap();
        assert!(com1 == com2, format!("{} does not equal {}", com1, com2));
    }
}