//! Structs
//!
//! Struct definitions used in State entity protocols

use curv::{FE, GE};
use bitcoin::Transaction;


/// /api/statechain return struct
#[derive(Serialize, Deserialize, Debug)]
pub struct StateChainData {
    pub funding_txid: String,
    pub chain: Vec<String>
}

/// /api/statechain post struct
#[derive(Serialize, Deserialize, Debug)]
pub struct SmtProofMsg {
    pub root: Option<[u8;32]>,
    pub funding_txid: String
}


/// Struct contains data necessary to caluculate tx input's sighash. This is required
/// whenever Client and Server co-sign a transaction.
#[derive(Serialize, Deserialize, Debug)]
pub struct PrepareSignTxMessage {
    pub spending_addr: String,
    pub input_txid: String,
    pub input_vout: u32,
    pub address: String,
    pub amount: u64,
    pub transfer: bool,
    pub proof_key: Option<String>
}

/// Client -> SE
#[derive(Serialize, Deserialize, Debug)]
pub struct DepositMsg1 {
    pub auth: String,
}

/// Sender -> SE
#[derive(Serialize, Deserialize, Debug)]
pub struct TransferMsg1 {
    pub shared_key_id: String,
    pub new_state_chain: Vec<String>,
}
/// SE -> Sender
#[derive(Serialize, Deserialize, Debug)]
pub struct TransferMsg2 {
    pub x1: FE,
}
/// Sender -> Receiver
#[derive(Serialize, Deserialize, Debug)]
pub struct TransferMsg3 {
    pub shared_key_id: String,
    pub t1: FE, // t1 = o1x1
    pub new_backup_tx: Transaction,
    pub state_chain: Vec<String>,
    pub state_chain_id: String,
}

/// Receiver -> State Entity
#[derive(Serialize, Deserialize, Debug)]
pub struct TransferMsg4 {
    pub shared_key_id: String,
    pub t2: FE, // t2 = t1*o2_inv = o1*x1*o2_inv
    pub state_chain: Vec<String>,
    pub o2_pub: GE
}
/// State Entity -> Receiver
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferMsg5 {
    pub new_shared_key_id: String,
    pub s2_pub: GE,
}

impl Default for TransferMsg5 {
    fn default() -> TransferMsg5 {
        TransferMsg5 {
            new_shared_key_id: String::from(""),
            s2_pub: GE::base_point2(),
        }
    }
}
