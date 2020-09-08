//! Structs
//!
//! Struct definitions used in State entity protocols

use crate::state_chain::{State, StateChainSig};
use crate::blinded_token::BlindedSpendToken;
use crate::Root;
use crate::Signature;
use bitcoin::{OutPoint, Transaction};
use curv::{cryptographic_primitives::proofs::sigma_dlog::DLogProof, BigInt, FE, GE, PK};
use kms::ecdsa::two_party::party2;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two;

use std::{collections::HashMap, fmt};
use uuid::Uuid;
use bitcoin::{Address, secp256k1::PublicKey};

/// State Entity protocols
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum Protocol {
    Deposit,
    Transfer,
    Withdraw,
}

// API structs

/// /info/info return struct
#[derive(Serialize, Deserialize, Debug)]
pub struct StateEntityFeeInfoAPI {
    pub address: String, // Receive address for fee payments
    pub deposit: u64,    // satoshis
    pub withdraw: u64,   // satoshis
}
impl fmt::Display for StateEntityFeeInfoAPI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Fee address: {},\nDeposit fee: {}\nWithdrawal fee: {}",
            self.address, self.deposit, self.withdraw
        )
    }
}

/// /info/statechain return struct
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StateChainDataAPI {
    pub utxo: OutPoint,
    pub amount: u64,
    pub chain: Vec<State>,
}

/// /info/transfer-batch return struct
#[derive(Serialize, Deserialize, Debug)]
pub struct TransferBatchDataAPI {
    pub state_chains: HashMap<Uuid, bool>,
    pub finalized: bool,
}

/// /info/statechain post struct
#[derive(Serialize, Deserialize, Debug)]
pub struct SmtProofMsgAPI {
    pub root: Root,
    pub funding_txid: String,
}

// PrepareSignTx structs

/// Struct contains data necessary to caluculate backup tx's input sighash('s). This is required
/// by Server before co-signing is performed for validation of tx.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PrepareSignTxMsg {
    pub shared_key_id: Uuid,
    pub protocol: Protocol,
    pub tx: Transaction,
    pub input_addrs: Vec<PK>, // pub keys being spent from
    pub input_amounts: Vec<u64>,
    pub proof_key: Option<String>,
}

// 2P-ECDSA Co-signing algorithm structs

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyGenMsg1 {
    pub shared_key_id: Uuid,
    pub protocol: Protocol,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyGenMsg2 {
    pub shared_key_id: Uuid,
    pub dlog_proof: DLogProof,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyGenMsg3 {
    pub shared_key_id: Uuid,
    pub party_two_pdl_first_message: party_two::PDLFirstMessage,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyGenMsg4 {
    pub shared_key_id: Uuid,
    pub party_two_pdl_second_message: party_two::PDLSecondMessage,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignMsg1 {
    pub shared_key_id: Uuid,
    pub eph_key_gen_first_message_party_two: party_two::EphKeyGenFirstMsg,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignMsg2 {
    pub shared_key_id: Uuid,
    pub sign_second_msg_request: SignSecondMsgRequest,
}

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
    pub proof_key: String,
}

/// Client -> SE
#[derive(Serialize, Deserialize, Debug)]
pub struct DepositMsg2 {
    pub shared_key_id: Uuid,
}

// Transfer algorithm structs

/// Address generated for State Entity transfer protocol
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Hash)]
pub struct SCEAddress {
    pub tx_backup_addr: Address,
    pub proof_key: PublicKey,
}
impl Eq for SCEAddress{}

/// Sender -> SE
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferMsg1 {
    pub shared_key_id: Uuid,
    pub state_chain_sig: StateChainSig,
}
/// SE -> Sender
#[derive(Serialize, Deserialize, Debug)]
pub struct TransferMsg2 {
    pub x1: FE,
}
/// Sender -> Receiver
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferMsg3 {
    pub shared_key_id: Uuid,
    pub t1: FE, // t1 = o1x1
    pub state_chain_sig: StateChainSig,
    pub state_chain_id: Uuid,
    pub tx_backup_psm: PrepareSignTxMsg,
    pub rec_addr: SCEAddress, // receivers state entity address (btc address and proof key)
}

/// Receiver -> State Entity
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferMsg4 {
    pub shared_key_id: Uuid,
    pub state_chain_id: Uuid,
    pub t2: FE, // t2 = t1*o2_inv = o1*x1*o2_inv
    pub state_chain_sig: StateChainSig,
    pub o2_pub: GE,
    pub tx_backup: Transaction,
    pub batch_data: Option<BatchData>,
}

/// State Entity -> Receiver
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferMsg5 {
    pub new_shared_key_id: Uuid,
    pub s2_pub: GE,
}

/// Conductor -> StateEntity
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferBatchInitMsg {
    pub id: Uuid,
    pub signatures: Vec<StateChainSig>,
}

/// User -> State Entity
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferRevealNonce {
    pub batch_id: Uuid,
    pub hash: String,
    pub state_chain_id: Uuid,
    pub nonce: [u8; 32],
}

/// Data present if transfer is part of an atomic batch transfer
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BatchData {
    pub id: Uuid,
    pub commitment: String, // Commitment to transfer input UTXO in case of protocol failure
}

// Withdraw algorithm structs
/// Owner -> State Entity
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WithdrawMsg1 {
    pub shared_key_id: Uuid,
    pub state_chain_sig: StateChainSig,
}

/// Owner -> State Entity
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WithdrawMsg2 {
    pub shared_key_id: Uuid,
    pub address: String,
}

// Swaps

/// Owner -> Conductor
#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterUtxo {
    pub state_chain_id: Uuid,
    pub signature: StateChainSig,
    pub swap_size: u64,
}

/// Owner -> Conductor
#[derive(Serialize, Deserialize, Debug)]
pub struct SwapMsg1 {
    pub swap_id: Uuid,
    pub state_chain_id: Uuid,
    pub swap_token_sig: Signature,
    pub address: SCEAddress,
    pub bst_e_prime: FE
}

// Message to request a blinded spend token
#[derive(Serialize, Deserialize, Debug)]
pub struct BSTMsg {
    pub swap_id: Uuid,
    pub state_chain_id: Uuid,
}


/// Owner -> Conductor
#[derive(Serialize, Deserialize, Debug)]
pub struct SwapMsg2 {
    pub swap_id : Uuid,
    pub blinded_spend_token: BlindedSpendToken,
}

impl Default for TransferMsg5 {
    fn default() -> TransferMsg5 {
        TransferMsg5 {
            new_shared_key_id: Uuid::new_v4(),
            s2_pub: GE::base_point2(),
        }
    }
}
