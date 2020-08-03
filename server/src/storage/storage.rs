use std::{fmt,error};
use rocket::response::Responder;
use rocket::http::{ContentType, Status};
use uuid::Uuid;
use shared_lib::state_chain::StateChain;
use shared_lib::Root;
use std::io::Cursor;
use bitcoin::blockdata::transaction::Transaction;
use kms::ecdsa::two_party::*;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use rocket_contrib::json::Json;

#[derive(Debug, Deserialize)]
pub enum StorageError {
    /// Generic error from string error message
    Generic(String),
    /// Invalid argument error
    FormatError(String),
    /// Item not found error
    NotFoundError(String),
    ConfigurationError(String),
}

impl PartialEq for StorageError {
    fn eq(&self, other: &Self) -> bool {
        use StorageError::*;
        match (self, other) {
            (Generic(ref a), Generic(ref b)) => a == b,
            (FormatError(ref a), FormatError(ref b)) => a == b,
            (NotFoundError(ref a), NotFoundError(ref b)) => a == b,
            (ConfigurationError(ref a), ConfigurationError(ref b)) => a == b,
            _ => false,
        }
    }
}

impl From<String> for StorageError {
    fn from(e: String) -> Self {
        Self::Generic(e)
    }
}

impl From<&str> for StorageError {
    fn from(e: &str) -> Self {
        Self::Generic(String::from(e))
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            StorageError::Generic(ref e) => write!(f, "StorageError: {}", e),
            StorageError::FormatError(ref e) => write!(f, "StorageError::FormatError: {}", e),
            StorageError::NotFoundError(ref e) => write!(f, "StorageError::NotFoundError: {}", e),
            StorageError::ConfigurationError(ref e) => {
                write!(f, "StorageError::ConfigurationError: {}", e)
            }
        }
    }
}

impl error::Error for StorageError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            _ => None,
        }
    }
}

impl Responder<'static> for StorageError {
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


type Result<T> = std::result::Result<T, StorageError>;


pub trait Storage {
   // fn insert<T,U>(&self, id: &T, data: U) -> Result<>;
   // fn remove<T,U>&self, id: &T, data: U) -> Result<()>;

   //Create a new user session or update an existing one 
   //If Uuid is not None, that session is updated. Otherwise, a new one is created.
   fn save_user_session(&self, id: &Uuid, auth: String, proof_key: String) 
        -> Result<()>;
    
   fn create_user_session(&self, auth: String, proof_key: String) 
        -> Result<()>{
     let id = Uuid::new_v4();
     self.save_user_session(&id, auth, proof_key)
   }

   fn save_statechain(&self, statechain_id: &Uuid, statechain: &StateChain, 
                            amount: i64, 
                            user_id: &Uuid) -> Result<()>;

    fn save_backup_tx(&self, statechain_id: &Uuid, backup_tx: &Transaction) 
        -> Result<()>;

    //Returns: (new_root, current_root)
    fn update_smt(&self, backup_tx: &Transaction, proof_key: &String)
        -> Result<(Option<Root>, Root)>;

    fn save_ecdsa(&self, user_id: &Uuid, 
        first_msg: party_one::KeyGenFirstMsg) -> Result<()>;


}