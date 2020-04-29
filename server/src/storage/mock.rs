//! Mock Storage
//!
//! Mock Storage interface and implementation for building and testing State Entity.
//! This should be implemented in DBv when we have decided on a storage method.

use bitcoin::Transaction;
use std::fmt;

/// StateChain is an item in storage. It consists of an ID and chain of active transitory keys
#[derive(Debug)]
pub struct StateChain {
    /// ID
    pub id: u32,
    /// chain of transitory key history
    pub chain: Vec<String>, // Chain of owners. String for now as unsure on data type at the moment.
    /// backup transaction
    pub tx_b: Transaction
}
impl StateChain {
    /// create a new StateChain
    pub fn new(id: u32) -> Self {
        return StateChain {
            id: id,
            chain: Vec::new(),
            tx_b: Transaction {
                version: 2,
                lock_time: 0,
                input: vec!(),
                output: vec!(),
            }
        }
    }
}
impl fmt::Display for StateChain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Id: {} \nchain: {:?}", self.id, self.chain)
    }
}


/// Mock storage struct acts as a DB of state chains for testing
pub struct MockStorage {
    /// stateChain instances
    state_chains: Vec<StateChain>
}

impl MockStorage {
    /// Create a MockStorage with all flags turned off by default
    pub fn new() -> Self {
        MockStorage {
            state_chains: vec!()
        }
    }
}


/// state chain DB
pub trait Storage {
    /// crate new state chain
    fn new_chain(&mut self) -> u32;
    /// append new chain tip
    fn append_to_chain(&mut self, chain_id: usize, state_transition: String) -> Result<(),()>;
    /// return entire chain structure
    fn get_chain(&self, id: usize) -> Result<&StateChain,()>;
    /// attest statechain DB to mainstay
    fn attest_via_mainstay(&self) -> Result<(),()>;
}

impl Storage for MockStorage {
    fn new_chain(&mut self) -> u32 {
        self.state_chains.push(StateChain::new(self.state_chains.len() as u32));
        self.state_chains.last().unwrap().id.clone()
    }
    fn append_to_chain(&mut self, chain_id: usize, state_transition: String) -> Result<(),()> {
        self.state_chains.get_mut(chain_id).unwrap().chain.push(state_transition);
        Ok(())
    }
    fn get_chain(&self, chain_id: usize) -> Result<&StateChain, ()> {
        match self.state_chains.get(chain_id) {
            Some(state_chain) => Ok(state_chain),
            None => Err(()),
        }
    }
    fn attest_via_mainstay(&self) -> Result<(),()> { unimplemented!()}
}
