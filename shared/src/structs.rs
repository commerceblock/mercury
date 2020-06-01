//! Structs
//!
//! Struct definitions used in State entity protocols

use crate::Root;
use crate::state_chain::{State, StateChainSig};
use curv::{FE, GE, BigInt};
use kms::ecdsa::two_party::party2;
use bitcoin::OutPoint;



/// State Entity protocols
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Protocol {
    Deposit,
    Transfer,
    Withdraw
}


// API structs

/// /api/info return struct
#[derive(Serialize, Deserialize, Debug)]
pub struct StateEntityFeeInfoAPI {
    pub address: String,  // Receive address for fee payments
    pub deposit: u64, // satoshis
    pub withdraw: u64 // satoshis
}

/// /api/statechain return struct
#[derive(Serialize, Deserialize, Debug)]
pub struct StateChainDataAPI {
    pub utxo: OutPoint,
    pub amount: u64,
    pub chain: Vec<State>
}
/// /api/statechain post struct
#[derive(Serialize, Deserialize, Debug)]
pub struct SmtProofMsgAPI {
    pub root: Root,
    pub funding_txid: String
}


// PrepareSignTx structs

/// Used for sending tx data to State Entity for verification before signing
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PrepareSignMessage {
    BackUpTx(BackUpTxPSM),
    WithdrawTx(WithdrawTxPSM)
}

/// Struct contains data necessary to caluculate backup tx input's sighash. This is required
/// for Client and Server co-sign a backup transaction.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BackUpTxPSM {
    pub protocol: Protocol,
    pub spending_addr: String,  // address which funding tx funds are sent to
    pub input: OutPoint,
    pub address: String,
    pub amount: u64,
    pub proof_key: Option<String>
}

/// Same as above but for Withdraw transaction.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WithdrawTxPSM {
    pub spending_addr: String,  // address which funding tx funds are sent to
    pub input: OutPoint,
    pub address: String,
    pub amount: u64,
    pub se_fee: u64,
    pub se_fee_addr: String
}


// co-signing algorithm structs

#[derive(Serialize, Deserialize, Debug)]
pub struct SignSecondMsgRequest {
    pub protocol: Protocol,
    pub message: BigInt,
    pub party_two_sign_message: party2::SignMessage,
}


// deposit algorithm structs


/// Client -> SE
#[derive(Serialize, Deserialize, Debug)]
pub struct DepositMsg1 {
    pub auth: String,
    pub proof_key: String
}


// transfer algorithm structs


/// Address generated for State Entity transfer protocol
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StateEntityAddress {
    pub backup_tx_addr: String,
    pub proof_key: String,
}

/// Sender -> SE
#[derive(Serialize, Deserialize, Debug)]
pub struct TransferMsg1 {
    pub shared_key_id: String,
    pub state_chain_sig: StateChainSig,
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
    pub state_chain_sig: StateChainSig,
    pub state_chain_id: String,
    pub backup_tx_psm: PrepareSignMessage,
    pub rec_addr: StateEntityAddress     // receivers state entity address (btc address and proof key)
}


/// Receiver -> State Entity
#[derive(Serialize, Deserialize, Debug)]
pub struct TransferMsg4 {
    pub shared_key_id: String,
    pub t2: FE, // t2 = t1*o2_inv = o1*x1*o2_inv
    pub state_chain_sig: StateChainSig,
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

// withdraw algorithm structs
/// Owner -> State Entity
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WithdrawMsg1 {
    pub shared_key_id: String,
    pub state_chain_sig: StateChainSig,
    pub address: String,
}
