//! # Mock Owner
//!
//! MockOwner interface and implementations -  users of the state entity


use crate::interfaces::protocols::ProtocolStateChain;

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
impl ProtocolStateChain for MockOwner {
    // deposit protocol
    fn deposit() -> String {
        return String::from("deposit")
    }
    // transfer protocol
    fn transfer() -> String {
        return String::from("transfer")
    }
}
