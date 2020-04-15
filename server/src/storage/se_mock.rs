//! Mock Storage
//!
//! Mock Storage interface and implementation for State Entity. This should be implemented in DB
//! when we have decided on a storage method.

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




/// Mock storage struct acts as a DB of state chains for testing
pub struct MockStorage {
    /// stateChain instances
    state_chains: Vec<StateChain>
}

impl MockStorage {
    /// Create a MockStorage with all flags turned off by default
    pub fn new() -> Self {
        MockStorage {
            state_chains: vec!(StateChain::new(0),StateChain::new(1),StateChain::new(2))
        }
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

impl Storage for MockStorage {
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quick_tests() {
        // append
        let mut mock_storage = MockStorage::new();
        assert!(mock_storage.state_chains[0].chain.len() == 0);
        let _ = mock_storage.append_to_chain(0, "test".to_string());
        assert!(mock_storage.state_chains[0].chain[0] == "test");
        assert!(mock_storage.state_chains[0].chain.len() == 1);
        // get_chain_state
        assert!(mock_storage.get_chain(0).unwrap().chain == ["test"]);
    }
}
