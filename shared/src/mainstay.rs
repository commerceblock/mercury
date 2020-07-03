use crate::error::SharedLibError;
use std::collections::HashMap;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::key::PrivateKey;
use reqwest;
use base64::encode;
use std::str::FromStr;
use std::string::ToString;
use std::convert::TryInto;
use std::fmt::Display;
use chrono::NaiveDateTime;

type SharedLibResult<T> = super::Result<T>;
type Result<T> = std::result::Result<T, Box<dyn ::std::error::Error> >;


pub type Hash = monotree::Hash;

type Payload<'a> = HashMap::<&'a str,&'a str>;

#[derive(Serialize, Deserialize, PartialEq, Copy, Default)]
pub struct Commitment(Option<Hash>);

impl std::clone::Clone for Commitment {
    fn clone(&self) -> Self {
        *self
    }
}

impl Display for Commitment {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.0 {
            Some(v) => {
                write!(f, "{}", hex::encode(v))
            },
            None => write!(f, "")
        }
    }
}

impl FromStr for Commitment {
    type Err = Box<dyn ::std::error::Error>;
    fn from_str(s: &str) -> Result<Self> {
        match hex::decode(s).unwrap()[..].try_into()
        {
            Ok(h) => Ok(Self(Some(h))),
            Err(e) =>  Err(SharedLibError::Generic(e.to_string()).into())
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
        let err_base = "Mainstay commitment failed";
        
        if res.status().is_success() {    
            match res.json::<serde_json::Value>(){
                Ok(j)=>{
                    let response = Response::from_json(&j)?;
                    match response.response.as_str(){
                        Some(r)=>{
                            match r == "Commitment added" {
                                true => return Ok(()),
                                false => return Err(SharedLibError::Generic(format!("{} - expected \"Commitment added\" in response: {:?}", err_base, res)).into())
                            }
                        }
                        None => {
                            return Err(SharedLibError::Generic(format!("{} - response: {:?}", err_base, res)).into())
                        }
                    }
                }, 
                Err(e) => Err(e.into())
            }
        } else {
            return Err(SharedLibError::Generic(format!("{}", err_base)).into())
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
    fn from_hash(hash: &Hash) -> Self {
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

impl FromStr for Config {
    type Err = Box<dyn ::std::error::Error>;
    fn from_str(s: &str) -> Result<Self> {
        match serde_json::from_str(s){
            Ok(p) => Ok(p),
            Err(e) =>  Err(SharedLibError::Generic(e.to_string()).into())
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

impl Response {
    pub fn from_json(json_data: &serde_json::Value) -> Result<Self>{       
        match json_data.get("response"){
            Some(r) => Ok(Self{response:r.clone()}),
            None => Err(SharedLibError::Generic(String::from("Error parsing response")).into())
        }
    }
}

 #[derive(Serialize, Deserialize, PartialEq)]
//Information about a commitment: it's attestation, if any, and its proof
pub struct CommitmentInfo {
    attestation: Option<Attestation>,
    merkle_proof: merkle::Proof
}



#[derive(Serialize, Deserialize, PartialEq)]
pub struct Attestation {
    merkle_root: Commitment,
    txid: Commitment,
    confirmed: bool,
    inserted_at: NaiveDateTime
}

#[derive(Debug, Clone)]
struct ParseError();

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "error parsing mainstay API")
    }
}

impl std::error::Error for ParseError {}
    

impl Attestation {
      pub fn from(merkle_root: Commitment, txid: Commitment, confirmed: bool, inserted_at: NaiveDateTime) -> Self{
        Self{merkle_root:merkle_root, txid:txid, confirmed: confirmed, inserted_at: inserted_at}
    }

    pub fn from_json(json_data: &serde_json::Value) -> Result<Self>{    
        let resp = &Response::from_json(json_data)?;
        Self::from_response(resp)
    }

    fn from_response(response: &Response) -> Result<Self>{       
        let err_str = "Mainstay Attestation: error parsing API response";

        match response.response.get("attestation"){
            Some(val) => {
                let mrs = val.get("merkle_root").ok_or(err_str)?.as_str();
                let mrs = mrs.ok_or(err_str)?;
                let merkle_root = Commitment::from_str(&mrs)?; 
                let txid = Commitment::from_str(val.get("txid").ok_or(err_str)?.as_str().ok_or(err_str)?)?;
                let confirmed = val.get("confirmed").ok_or(err_str)?.as_bool().ok_or(err_str)?;
                let inserted_at = val.get("inserted_at").ok_or(err_str)?.as_str().ok_or(err_str)?;
                let inserted_at = NaiveDateTime::parse_from_str(&inserted_at, "%H:%M:%S %d/%m/%y")?;

                Ok(Self::from(merkle_root, txid, confirmed, inserted_at))
            },
            None => Err(SharedLibError::Generic(String::from("Error parsing attestation")).into())
        }
    }
}


pub mod merkle {
    use super::*;
    //Double sha256
    use bitcoin::hashes::sha256d::Hash as SHAHash;

    //use std::fmt;
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

    #[derive(Serialize, Deserialize, PartialEq)]
    pub struct Proof {
        merkle_root: Commitment,
        commitment: Commitment,
        ops: Vec<Commitment>
    }

    impl Proof {
        pub fn from(merkle_root: Commitment, commitment: Commitment, ops: Vec<Commitment>) -> Self{
            Self{merkle_root: merkle_root, commitment: commitment, ops: ops}
        }

        fn from_command(command: &str, config: &Config) -> Result<Self> {
            let response = get(command, config);
            match response {
                Ok(r) => Self::from_json(&r),
                Err(e) => Err(SharedLibError::Generic(e.to_string()).into())
            }   
        }

        pub fn from_latest_proof(config: &Config) -> Result<Self> {
            let command = format!("commitment/latestproof?position={}",config.position);
            Self::from_command(&command, config)
        }

        pub fn from_commitment(config: &Config, commitment: &Commitment) ->Result<Self> {
            let command = &format!("commitment/commitment?commitment={}",commitment);
            Self::from_command(command,config)
        }

        pub fn from_attestable<T: Attestable>(config: &Config, attestable: &T) ->Result<Self> {
            let commitment=&attestable.commitment()?;
            Self::from_commitment(config, commitment)
        }

        pub fn from_json(json_data: &serde_json::Value) -> Result<Self>{
            //Parse Mainstay API responses and Proof object strings            
            let mut val: &serde_json::Value;

            match json_data.get("response"){
                Some(resp) => val = resp,
                None => val = &json_data
            };

            match val.get("merkleproof"){
                Some(resp) => val = resp,
                None => ()
            };
            
            let merkle_root = Commitment::from_str(val.get("merkle_root").unwrap().as_str().unwrap()).unwrap();
            let commitment = Commitment::from_str(val.get("commitment").unwrap().as_str().unwrap()).unwrap();
            let mut ops = Vec::<Commitment>::new();
            let ops_val = val.get("ops").unwrap();
            let ops_arr = ops_val.as_array().unwrap();
            for op in ops_arr {
                let commit_str = op.get("commitment").unwrap().as_str().unwrap();
                ops.push(Commitment::from_str(commit_str).unwrap())
            }
            
            Ok(Proof::from(merkle_root, commitment, ops))
        }
    }

    impl FromStr for Proof {
        type Err = Box<dyn ::std::error::Error>;
        fn from_str(s: &str) -> Result<Self> {
            let json_data : serde_json::Value = serde_json::from_str(s)?;
            Self::from_json(&json_data)
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::keygen::generate_keypair;
    
    pub fn slot() -> u32 {
        match std::env::var("MERC_MS_TEST_SLOT_1="){
            Ok(s) => s.parse::<u32>().unwrap(),   
            Err(_)=> {
                assert!(false);
                Default::default()
            }
        }
    }

    pub fn token() -> String {
        match std::env::var("MERC_MS_TEST_TOKEN_1"){
            Ok(t) => t,   
            Err(_)=> {
                assert!(false);
                Default::default()
            }
        }
    }

    pub fn config() -> Config {
        Config { position: slot(), token: token(), ..Default::default() }
    }

    
    #[test]
    fn test_commit() {
                
        let random_hash = Commitment::from_hash(&monotree::utils::random_hash());

        let config = config();

        match random_hash.attest(&config) {
            Ok(()) => assert!(true),
            Err(e) => assert!(false)
        }

        //Incorrect token should fail.
        let token = String::from("wrong_token");
        let config = Config { position: slot(), token: token, ..Default::default() };        

        match random_hash.attest(&config) {
            Ok(()) => assert!(false, "should have failed with incorrect token"),
            Err(e) => {
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
    fn test_parse_response() {

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
        assert!(merkleproof_1 ==merkleproof_2);
        assert!(merkleproof_1 ==merkleproof_compare);

    }

    
    #[test]
    fn test_get_latest_proof() {
        match merkle::Proof::from_latest_proof(&config()){
            Ok(_) => assert!(true),
            Err(e) => assert!(false)
        };
    }

    #[test]
    fn test_get_proof_from_commitment() {
        //Retrieve the proof for a commitment
        let commitment = &Commitment::from_str("31e66288b9074bcfeb3bc5734f2d0b189ad601b61f86b8241ee427648b59fdbc").unwrap();
        
        let proof1 = merkle::Proof::from_commitment(&config(), commitment).unwrap();
        
        let proof2 = merkle::Proof::from_attestable::<Commitment>(&config(), commitment).unwrap();

        assert!(proof1 == proof2);
    }
}