//! State Chain
//!
//! State chain is the data structure used to track ownership of a UTXO co-owned by the State Entity.
//! An owner provides a key (we call proof key) which gets appended to the state chain once their
//! ownership is confirmed.
//! Then, to pass ownership over to a new proof key the current owner signs a StateChainSig struct
//! which includes the new owners proof key. This new proof key is then appended to the state chain
//! as before. Thus ownership can be verified by ensuring the newest proof key has been signed for by the
//! previous proof key.
//! To withdraw, and hence bring an end to the State Chain, the StateChainSig struct contains the
//! withdrawal address.

//! Tests for this code can be found in server/src/state_chain

use super::Result;
use crate::util::SharedLibError;
use bitcoin::secp256k1::{Signature, SecretKey, Message, Secp256k1, PublicKey};
use bitcoin::hashes::{sha256d,Hash};
use bitcoin::Transaction;
use uuid::Uuid;

use std::str::FromStr;

/// A list of States in which each State signs for the next State.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct StateChain {
    pub id: String,
    /// chain of transitory key history
    pub chain: Vec<State>,
    /// current back-up transaction
    pub backup_tx: Option<Transaction>,
    /// Amount
    pub amount: u64 // 0 means state chain is ended.
}

impl StateChain {
    pub fn new(data: String, amount: u64) -> Self {
        StateChain {
            id: Uuid::new_v4().to_string(),
            chain: vec!( State {
                data,
                next_state: None
            }),
            backup_tx: None,
            amount
        }
    }

    pub fn add(&mut self, state_chain_sig: StateChainSig) -> Result<()> {
        let mut tip = self.chain.last()
            .ok_or(SharedLibError::Generic(String::from("StateChain empty")))?.clone();

        // verify previous state has signature and signs for new proof_key
        let prev_proof_key = tip.data.clone();
        state_chain_sig.verify(&prev_proof_key)?;

        // add sig to current tip
        tip.next_state = Some(state_chain_sig.clone());
        self.chain.pop();
        self.chain.push(tip);

        // add new tip to chain
        Ok(self.chain.push(State {
            data: state_chain_sig.data,
            next_state: None
        }))
    }
}


/// each State in the Chain of States
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct State {
    pub data: String,   // proof key or address
    pub next_state: Option<StateChainSig> // signature representing passing of ownership
}
/// Data necessary to create ownership transfer signatures
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct StateChainSig {
    pub purpose: String, // "TRANSFER" or "WITHDRAW"
    pub data: String, // proof key or address
    sig: String
}
impl StateChainSig {
    /// create message to be signed
    fn to_message(purpose: &String, data: &String) -> Result<Message> {
        let mut str = purpose.clone();
        str.push_str(&data);    // append data to msg
        let hash = sha256d::Hash::hash(&str.as_bytes());
        Ok(Message::from_slice(&hash)?)
    }

    /// generate signature for change of state chain ownership
    pub fn new(proof_key_priv: &SecretKey, purpose: &String, data: &String) -> Result<Self> {
        let secp = Secp256k1::new();
        let message = StateChainSig::to_message(purpose, data)?;
        let sig = secp.sign(&message, &proof_key_priv);
        Ok(StateChainSig {
            purpose: purpose.clone(),
            data: data.clone(),
            sig: sig.to_string()
        })
    }

    /// verify self's signature for transfer or withdraw
    pub fn verify(&self, pk: &String) -> Result<()> {
        let secp = Secp256k1::new();
        let message = StateChainSig::to_message(&self.purpose, &self.data)?;
        Ok(secp.verify(
            &message,
            &Signature::from_str(&self.sig).unwrap(),
            &PublicKey::from_str(&pk).unwrap()
        )?)
    }
}
