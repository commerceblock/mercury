extern crate ecies;
use bitcoin::util::key::{ PublicKey, PrivateKey };
use serde::{Serialize, Deserialize, de::DeserializeOwned};

use rocket::http::{Status, ContentType};
//use rocket::{Request, Response, Responder};
use std::{fmt, error};
use std::io::Cursor;
use rocket::{Request, response::{Responder, Response}};

pub type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

#[derive(Debug, Deserialize)]
pub enum ECIESError {
    /// Generic error from string error message
    Generic(String),
    /// Invalid argument error
    FormatError(String),
    /// Invalid argument error
    EncryptError(String),
    /// Invalid argument error
    DecryptError(String),
}

impl PartialEq for ECIESError {
    fn eq(&self, other: &Self) -> bool {
        use ECIESError::*;
        match (self, other) {
            (Generic(ref a), Generic(ref b)) => a == b,
            (FormatError(ref a), FormatError(ref b)) => a == b,
            (EncryptError(ref a), EncryptError(ref b)) => a == b,
            (DecryptError(ref a), DecryptError(ref b)) => a == b,
            _ => false,
        }
    }
}

impl From<String> for ECIESError {
    fn from(e: String) -> Self {
        Self::Generic(e)
    }
}

impl From<&str> for ECIESError {
    fn from(e: &str) -> Self {
        Self::Generic(String::from(e))
    }
}

impl fmt::Display for ECIESError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ECIESError::Generic(ref e) => write!(f, "ECIESError: {}", e),
            ECIESError::FormatError(ref e) => write!(f, "ECIESError::FormatError: {}", e),
            ECIESError::EncryptError(ref e) => write!(f, "ECIESError::EncryptError: {}", e),
            ECIESError::DecryptError(ref e) => write!(f, "ECIESError::DecryptError: {}", e),
        }
    }
}

impl error::Error for ECIESError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            _ => None,
        }
    }
}

impl Responder<'static> for ECIESError {
    fn respond_to(
        self,
        _: &rocket::Request,
    ) -> ::std::result::Result<rocket::Response<'static>, Status> {
        rocket::Response::build()
            .header(ContentType::JSON)
            .sized_body(Cursor::new(format!("{}", self)))
            .ok()
    }
}

use ECIESError::EncryptError;
use ECIESError::DecryptError;

//Encrypted serialization/deserialization
pub trait Encryptable: Serialize + Sized + DeserializeOwned{
    fn to_encrypted_bytes(&self, pubkey: &PublicKey) -> Result<Vec<u8>>{
        let str_self = serde_json::to_string(self)?;
        let serialized = str_self.as_bytes();
        let key_bytes = pubkey.to_bytes();
        match ecies::encrypt(&key_bytes, serialized){
            Ok(v) => Ok(v),
            Err(e) => Err(EncryptError(e.to_string()).into())
        }
    }

    fn from_encrypted_bytes(privkey: &PrivateKey, ec: &[u8]) ->Result<Self>{
        let key_bytes = privkey.to_bytes();
        let serialized = String::from_utf8(ecies::decrypt(&key_bytes, ec)?)?;
        match serde_json::from_str(&serialized){
            Ok(v) => Ok(v),
            Err(e) => Err(DecryptError(e.to_string()).into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::keygen::generate_keypair;

    #[derive(Deserialize, Serialize, Debug, PartialEq)]
    struct TestStruct {
        first_item: String,
        second_item: u32,
    }

    impl Encryptable for TestStruct{}

    #[test]
    fn test_encrypt_decrypt_struct() {
        let ts = TestStruct{first_item: "test message".to_string(), second_item: 42};
        let (sk, pk) = generate_keypair();
        let tse = ts.to_encrypted_bytes(&pk).unwrap();
        let tsu = TestStruct::from_encrypted_bytes(&sk, &tse).unwrap();
        
        assert_eq!(ts, tsu, "unencrypted != plain");

        let (sk2, _) = generate_keypair();
        let tse = ts.to_encrypted_bytes(&pk).unwrap();

        match TestStruct::from_encrypted_bytes(&sk2, &tse){
            Ok(_) => assert!(false, "decryption should have failed"),
            Err(e) => match e.downcast_ref::<secp256k1::Error>() {
                Some(e) => match e {
                    secp256k1::Error::InvalidMessage => assert!(true),
                    _ => assert!(false, "unexpected error enum: {}", e),
                }
                None => assert!(false, "expected secp256k1::Error"),
            }
        }
    }
}
