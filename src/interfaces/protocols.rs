//! Protocol
//!
//! Protocol interfaces


/// Interface defining functions for interfacing with state entity
pub trait ProtocolStateChain {
    /// statechain despoit
    fn deposit() -> String;
    /// statchain transfer
    fn transfer() -> String;
}

/// Interface defining multi-party ECDSA protocol
pub trait ProtocolMPECDSA {
    
}
