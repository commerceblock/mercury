//! # Mock Owner
//!
//! MockOwner interface and implementations -  users of the state entity


use crate::state_entity::StateEntityInterface;

/// Rpc implementation of Owner
pub struct MockOwner {
    /// Rpc client instance
    id: u32,
}

impl MockOwner {
    /// create an RpcOwner
    pub fn new() -> Self {
        MockOwner{id: 1}
    }
}
impl StateEntityInterface for MockOwner {
    // deposit protocol
    fn deposit() -> String {
        return String::from("deposit")
    }
    // transfer protocol
    fn transfer() -> String {
        return String::from("transfer")
    }
}
