//! Storage
//!
//! Storage interface and implementation

use std::fmt;

/// StateChain is an item in storage. It consists of an ID and chain of active transitory keys
#[derive(Debug)]
pub struct StateChain {
    /// ID
    pub id: u32,
    /// chain of transitory key history
    pub chain: Vec<String> // String for now. Unsure on data type at the moment.
}
impl StateChain {
    /// create a new StateChain
    pub fn new(id: u32) -> Self {
        return StateChain{
            id: id,
            chain: Vec::new()
        }
    }
}

impl fmt::Display for StateChain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {

        write!(f, "Id: {} \nchain: {:?}", self.id, self.chain)
    }
}

/// state chain DB
pub trait Storage {
    /// append new chain tip
    fn append_to_chain(&mut self, chain_id: usize, state_transition: String) -> Result<(),()>;
    /// return entire chain structure
    fn get_chain(&self, id: usize) -> Result<&StateChain,()>;
    /// attest statechain DB to mainstay
    fn attest_via_mainstay(&self) -> Result<(),()>;
}
