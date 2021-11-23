pub mod db;
pub mod monotree;
pub use super::Result;

use rocket::http::{ContentType, Status};
use rocket::response::Responder;
pub use shared_lib::state_chain::StateChain;
use shared_lib::structs::*;
pub use shared_lib::Root;
use std::io::Cursor;
use std::{error, fmt};
use uuid::Uuid;

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
        use self::StorageError::*;
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

pub trait Storage {
    // fn insert<T,U>(&self, id: &T, data: U) -> Result<>;
    // fn remove<T,U>&self, id: &T, data: U) -> Result<()>;

    //Create a new user session or update an existing one
    //If Uuid is not None, that session is updated. Otherwise, a new one is created.
    //fn save_user_session(&self, id: &Uuid, auth: String, proof_key: String)
    //     -> Result<()>;

    //fn create_user_session(&self, auth: String, proof_key: String)
    //     -> Result<()>{
    //  let id = Uuid::new_v4();
    //  self.save_user_session(&id, auth, proof_key)
    //}

    //fn save_statechain(&self, statechain_id: &Uuid, statechain: &StateChain,
    //                        amount: i64,
    //                          user_id: &Uuid) -> Result<()>;

    //    fn save_backup_tx(&self, statechain_id: &Uuid, backup_tx: &Transaction)
    //      -> Result<()>;

    //Returns: (new_root, current_root)
    fn update_smt(&self, funding_txid: &String, proof_key: &String)
        -> Result<(Option<Root>, Root)>;

    //fn save_ecdsa(&self, user_id: &Uuid,
    //    first_msg: party_one::KeyGenFirstMsg) -> Result<()>;

    fn get_confirmed_smt_root(&self) -> Result<Option<Root>>;

    fn get_smt_root(&self) -> Result<Option<Root>>;

    //fn get_confirmed_root(&self) -> Result<Option<Root>>;

    fn get_root(&self, id: i64) -> Result<Option<Root>>;

    fn update_root(&self, root: &Root) -> Result<i64>;

    //Returns locked until time, owner id, state chain
    fn get_statechain_data_api(&self, statechain_id: Uuid) -> Result<StateChainDataAPI>;

    //Returns locked until time, owner id, tip of state chain
    fn get_statecoin_data_api(&self, statechain_id: Uuid) -> Result<StateCoinDataAPI>;

    //Returns locked until time, owner id, state chain
    fn get_owner_id(&self, statechain_id: Uuid) -> Result<OwnerID>;

    //fn authorise_withdrawal(&self, user_id: &Uuid, signature: StateChainSig) -> Result<()>;

    // /withdraw/confirm
    //fn confirm_withdrawal(&self, user_id: &Uuid, address: &String)->Result<()>;

    // /transfer/sender
    //fn init_transfer(&self, user_id: &Uuid, sig: &StateChainSig)->Result<()>;

    // Returns statechain_id, sstatechain_sig_str, x1_str
    //fn get_transfer(&self, statechain_id: &Uuid) -> Result<(Uuid, StateChainSig, FE)>;

    fn get_statechain(&self, statechain_id: Uuid) -> Result<StateChain>;

    //Returns party1_private_str, party2_public_str
    //fn get_transfer_ecdsa_pair(&self, user_id: &Uuid) -> Result<(Party1Private, GE)>;

    //fn finalize_transfer(&self, batch_data: &Option<BatchData>, tf_data: &TransferFinalizeData);

    //fn batch_transfer_exists(&self, batch_id: &Uuid, sig: &StateChainSig)-> bool;

    // /transfer/batch/init
    //fn init_batch_transfer(&self, batch_id: &Uuid,
    //                    state_chains: &HashMap<Uuid, bool>) -> Result<()>;

    // Returns: finalized, start_time, state_chains, punished
    //fn get_transfer_batch_status(&self, batch_id: &Uuid)
    //    -> Result<TransferBatchDataAPI>;

    // Update the locked until time of a state chain (used for punishment)
    //fn update_locked_until(&self, statechain_id: &Uuid, time: &NaiveDateTime);

    //Update the list of punished state chains
    //fn update_punished(&self, punished: &Vec<Uuid>);

     //Reset the in-RAM data
     fn reset_data(&self) -> Result<()>;
}
