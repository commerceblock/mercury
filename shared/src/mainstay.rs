use std::collections::HashMap;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::key::PrivateKey;
use reqwest;
use itertools::Itertools;

use super::Result;

type Hash = monotree::Hash;

//Custom headers for Mainstay posts
header! { (XMainstayPayload, "X-MAINSTAY-PAYLOAD") => [String] }
header! { (XMainstaySignature, "X-MAINSTAY-PAYLOAD") => [String] }

//Mainstay API requires empty string if no password
fn bytes_to_hex_string(bytes: &Option<[u8; 32]>) -> String {
    match bytes{
        Some(b) => format!("{:02x}",b.iter().format("")),
        None => String::from("")
    }
}

trait Attestable:  {
    //Attest to the slot using the specified config
    fn attest(&self, config: &Config) -> Result<reqwest::Response>{
        let commitment = self.commitment()?;
        let signature = match config.key {
            Some(k) => {
                //format!("{:02x}",self.sign(&k)?.iter().format(""))
                Some(self.sign(&k)?)
            },
            None => None
        };

        let mut payload = HashMap::new();
        payload.insert("commmitment", bytes_to_hex_string(&Some(*commitment)));
        payload.insert("position", config.position.to_string());
        payload.insert("token", config.token.clone()); 
        let payload_ser = serde_json::to_string(&payload)?;

        let client = reqwest::Client::new();
        let url = reqwest::Url::parse(&format!("{}{}",config.url,"commitment/send"))?;
        let res = client.post(url)
        .header("XMainstayPayload",payload_ser)
        .header("XMainstaySignature",bytes_to_hex_string(&signature))
        .send()?;
        
        Ok(res)
    }

    //The data to be commited
    fn commitment(&self) -> Result<&Hash>;

    fn sign(&self, priv_key: &PrivateKey) -> Result<Hash>{
        let commitment = self.commitment()?;
        let secp = Secp256k1::new();
        let message = &bitcoin::secp256k1::Message::from_slice(commitment)?;
        let signature = secp.sign(message, &priv_key.key).serialize_der().to_vec();
        let mut sig : Hash = Default::default();
        sig.copy_from_slice(&signature);
        let sig = sig;
        Ok(sig)
    }
}

//The commitment of a Hash type is just the Hash itelf
impl Attestable for Hash {
    fn commitment(&self) -> Result<&Hash>{
        Ok(&self)
    }    
}

//Mainstay configuration
struct Config {
    url: String,
    position: u32,
    token: String,
    key: Option<PrivateKey>
}

impl Default for Config {
    fn default() -> Self {
        Self { url: String::from("https://mainstay.xyz/api/v1"), key: None, position: u32::default(),  token: String::default()}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let random_hash : Hash = monotree::utils::random_hash();

        match random_hash.attest(&test_config) {
            Ok(_) => assert!(true),
            Err(e) => assert!(false, e)
        }
    }
}