use crate::error::SharedLibError;
use std::collections::HashMap;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::key::PrivateKey;
use reqwest;
use itertools::Itertools;
use base64::encode;
use std::str::FromStr;
use std::string::ToString;
use arrayvec::ArrayVec;
use std::convert::TryInto;

use super::Result;

pub type Hash = monotree::Hash;

#[derive(Serialize, Deserialize, PartialEq, Copy)]
pub struct Commitment(Option<Hash>);

impl std::clone::Clone for Commitment {
    fn clone(&self) -> Self {
        *self
    }
}

impl FromStr for Commitment {
    type Err = SharedLibError;
    fn from_str(s: &str) -> Result<Self> {
        match hex::decode(s).unwrap()[..].try_into()
        {
            Ok(h) => Ok(Self(Some(h))),
            Err(e) =>  Err(SharedLibError::Generic(e.to_string()))
        }
    }
}

impl ToString for Commitment {
    fn to_string(&self) -> String {
        match self.0 {
            Some(v) => hex::encode(v),
            None => String::from("")
        }
    }
}

//Mainstay API requires empty string if no password
//fn bytes_to_hex_string(bytes: &Option<Hash>) -> String {
//    match bytes{
//        Some(b) => format!("{:02x}",b.iter().format("")),
//        None => String::from("")
//    }
//}

pub trait Attestable:  {
    //Attest to the mainstay slot using the specified config
    fn attest(&self, config: &Config) -> Result<()>{
        let commitment = &self.commitment()?;
        let signature = match config.key {
            Some(k) => {
                self.sign(&k)?
            },
            None => Commitment(None)
        };

        let mut payload = HashMap::new();
        payload.insert("commitment", commitment.to_string());
        payload.insert("position", config.position.to_string());
        payload.insert("token", config.token.clone()); 
        let payload_str = String::from(serde_json::to_string(&payload)?);
        let payload_enc = encode(payload_str);
        let mut data = HashMap::new();
        data.insert("X-MAINSTAY-PAYLOAD", &payload_enc);
        let sig_str = signature.to_string();
        data.insert("X-MAINSTAY-SIGNATURE", &sig_str);
        
        let client = reqwest::Client::new();
        let url = reqwest::Url::parse(&format!("{}/{}",config.url,"commitment/send"))?;
        let req = client.post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&data);
        
        let mut res = req.send()?;
        
        if res.status().is_success(){

            match res.text(){
                Ok(t) => {
                    if t.contains("Commitment added"){
                        return Ok(());
                    } else {
                        return Err(SharedLibError::Generic(String::from("Mainstay commitment failed")));
                    }
                }
                Err(e) => assert!(false, e)
            }
            return Ok(());
        } else if res.status().is_server_error() {
            return Err(SharedLibError::Generic(String::from("Mainstay server error")));
        } else {
            return Err(SharedLibError::Generic(String::from(format!("Mainstay status: {}", res.status())))); 
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
    type Err = SharedLibError;
    fn from_str(s: &str) -> Result<Self> {
        match serde_json::from_str(s){
            Ok(p) => Ok(p),
            Err(e) =>  Err(SharedLibError::Generic(e.to_string()))
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

//#[derive(Serialize, Deserialize)]
//struct 

//#[derive(Serialize, Deserialize)]
//struct Response {
    //merkleproof: merkle::Proof
//}

//#[derive(Serialize, Deserialize)]
//struct Merkle {
    //merkle_root: String,
    //txid: String,
//}


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

    #[derive(Serialize, Deserialize, PartialEq)]
    pub struct Proof {
        merkle_root: Commitment,
        commitment: Commitment,
        ops: Vec<Commitment>
    }

    impl Proof {
        pub fn from(merkle_root: &Commitment, commitment: &Commitment, ops: Vec<Commitment>) -> Self{
            Self{merkle_root:*merkle_root, commitment:*commitment, ops: ops}
        }
    }

    impl FromStr for Proof {
        type Err = SharedLibError;
        fn from_str(s: &str) -> Result<Self> {
            let json_data : serde_json::Value = serde_json::from_str(s).unwrap();
            let mut val: &serde_json::Value;

            //Parse Mainstay API responses and Proof object strings
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
            
            Ok(Proof::from(&merkle_root, &commitment, ops))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::keygen::generate_keypair;
    
    #[test]
    fn test_commit() {
        let slot = match std::env::var("MERC_MS_TEST_SLOT_1="){
            Ok(s) => s.parse::<u32>().unwrap(),   
            Err(_)=> {
                assert!(false);
                Default::default()
            }
        };
                
        let token = match std::env::var("MERC_MS_TEST_TOKEN_1"){
            Ok(t) => t,   
            Err(_)=> {
                assert!(false);
                Default::default()
            }
        };

        let test_config = Config { position: slot, token: token, ..Default::default() };
        let random_hash = Commitment::from_hash(&monotree::utils::random_hash());

        match random_hash.attest(&test_config) {
            Ok(()) => assert!(true),
            Err(e) => assert!(false, e)
        }

        //Incorrect token should fail.
        let token = String::from("wrong_token");
        let test_config = Config { position: slot, token: token, ..Default::default() };
        
        match random_hash.attest(&test_config) {
            Ok(()) => assert!(false, "should have failed with incorrect token"),
            Err(e) => {
                println!("{}",e);
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


        let msjson : MSJSON = serde_json::from_str(response_str).unwrap();

        println!("{}", response_str);
        //let resp = msjson.response.unwrap();
        //println!("{}", resp.to_string());
        //println!("{}", resp["merkleproof'"].to_string());

        let merkleproof_1 = merkle::Proof::from_str(data_str).unwrap();
        let merkleproof_2 = merkle::Proof::from_str(response_str).unwrap();
        let merkleproof_3 = merkle::Proof::from_str(merkleproof_str).unwrap();

        let mut ops= Vec::<Commitment>::new();
        ops.push(Commitment::from_str("31e66288b9074bcfeb3bc5734f2d0b189ad601b61f86b8241ee427648b59fdbc").unwrap());
        ops.push(Commitment::from_str("60da74551926c4283dd4b4e295d2a1eb5147b5cf6c7c2019e8b64c22a1ba5bab").unwrap());
        ops.push(Commitment::from_str("94adb04ab09036fbc6cc164ec6df4d9d8fba45bcd7901a03d2e91b123071a5ec").unwrap());
        let merkle_root = Commitment::from_str("47fc767ebc5095133d6de9a060c248c115b3fdf5f30921de2ee111225690de01").unwrap();
        let commitment = Commitment::from_str("71c7f2f246caf3e4f0b94ea4ad54b6c506687069bf1e17024cd5961b0df78d6d").unwrap();

        let merkleproof_compare = merkle::Proof::from(&merkle_root, &commitment, ops);

        assert!(merkleproof_1 ==merkleproof_2);
        assert!(merkleproof_1 ==merkleproof_3);
        assert!(merkleproof_1 ==merkleproof_2);
        assert!(merkleproof_1 ==merkleproof_compare);

    }

}