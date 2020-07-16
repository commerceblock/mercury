//! Structs
//!
//! Struct definitions used in State entity protocols

use crate::Root;
use crate::state_chain::{State, StateChainSig};
use curv::{FE, GE, BigInt, PK};
use kms::ecdsa::two_party::party2;
use bitcoin::{Transaction, OutPoint};

use std::{collections::HashMap, fmt};

/// State Entity protocols
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum Protocol {
    Deposit,
    Transfer,
    Withdraw
}


// API structs

/// /info/info return struct
#[derive(Serialize, Deserialize, Debug)]
pub struct StateEntityFeeInfoAPI {
    pub address: String,  // Receive address for fee payments
    pub deposit: u64, // satoshis
    pub withdraw: u64 // satoshis
}
impl fmt::Display for StateEntityFeeInfoAPI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fee address: {},\nDeposit fee: {}\nWithdrawal fee: {}",
            self.address, self.deposit, self.withdraw)
    }
}

/// /info/statechain return struct
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StateChainDataAPI {
    pub utxo: OutPoint,
    pub amount: u64,
    pub chain: Vec<State>
}

/// /info/transfer-batch return struct
#[derive(Serialize, Deserialize, Debug)]
pub struct TransferBatchDataAPI {
    pub state_chains: HashMap<String, bool>,
    pub finalized: bool
}


/// /info/statechain post struct
#[derive(Serialize, Deserialize, Debug)]
pub struct SmtProofMsgAPI {
    pub root: Root,
    pub funding_txid: String
}


// PrepareSignTx structs


/// Struct contains data necessary to caluculate backup tx's input sighash('s). This is required
/// by Server before co-signing is performed for validation of tx.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PrepareSignTxMsg {
    pub shared_key_id: String,
    pub protocol: Protocol,
    pub tx: Transaction,
    pub input_addrs: Vec<PK>,  // pub keys being spent from
    pub input_amounts: Vec<u64>,
    pub proof_key: Option<String>
}



// 2P-ECDSA Co-signing algorithm structs

#[derive(Serialize, Deserialize, Debug)]
pub struct SignSecondMsgRequest {
    pub protocol: Protocol,
    pub message: BigInt,
    pub party_two_sign_message: party2::SignMessage,
}


// Deposit algorithm structs


/// Client -> SE
#[derive(Serialize, Deserialize, Debug)]
pub struct DepositMsg1 {
    pub auth: String,
    pub proof_key: String
}

/// Client -> SE
#[derive(Serialize, Deserialize, Debug)]
pub struct DepositMsg2 {
    pub shared_key_id: String,
}

/// Client -> SE
#[derive(Serialize, Deserialize, Debug)]
pub struct ConfirmProofsMsg {
    pub shared_key_id: String,
}

// Transfer algorithm structs


/// Address generated for State Entity transfer protocol
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StateEntityAddress {
    pub tx_backup_addr: String,
    pub proof_key: String,
}


/// Sender -> SE
#[derive(Serialize, Deserialize, Debug)]
pub struct TransferMsg1 {
    pub shared_key_id: String,
    pub state_chain_sig: StateChainSig
}
/// SE -> Sender
#[derive(Serialize, Deserialize, Debug)]
pub struct TransferMsg2 {
    pub x1: FE
}
/// Sender -> Receiver
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferMsg3 {
    pub shared_key_id: String,
    pub t1: FE, // t1 = o1x1
    pub state_chain_sig: StateChainSig,
    pub state_chain_id: String,
    pub tx_backup_psm: PrepareSignTxMsg,
    pub rec_addr: StateEntityAddress     // receivers state entity address (btc address and proof key)
}


/// Receiver -> State Entity
#[derive(Serialize, Deserialize, Debug)]
pub struct TransferMsg4 {
    pub shared_key_id: String,
    pub state_chain_id: String,
    pub t2: FE, // t2 = t1*o2_inv = o1*x1*o2_inv
    pub state_chain_sig: StateChainSig,
    pub o2_pub: GE,
    pub batch_data: Option<BatchData>
}

/// State Entity -> Receiver
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferMsg5 {
    pub new_shared_key_id: String,
    pub s2_pub: GE,
}

/// Coordinator -> StateEntity
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferBatchInitMsg {
    pub id: String,
    pub signatures: Vec<StateChainSig>,
}

/// User -> State Entity
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferRevealNonce {
    pub batch_id: String,
    pub hash: String,
    pub state_chain_id: String,
    pub nonce: [u8;32],
}

/// Data present if transfer is part of an atomic batch transfer
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BatchData {
    pub id: String,
    pub commitment: String   // Commitment to transfer input UTXO in case of protocol failure
}


// Withdraw algorithm structs
/// Owner -> State Entity
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WithdrawMsg1 {
    pub shared_key_id: String,
    pub state_chain_sig: StateChainSig,
}

/// Owner -> State Entity
#[derive(Serialize, Deserialize, Debug)]
pub struct WithdrawMsg2 {
    pub shared_key_id: String,
    pub address: String,
}



impl Default for TransferMsg5 {
    fn default() -> TransferMsg5 {
        TransferMsg5 {
            new_shared_key_id: String::from(""),
            s2_pub: GE::base_point2(),
        }
    }
}
