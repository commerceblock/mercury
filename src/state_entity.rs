//! state_entity
//!
//! State Entity implementation

use crate::config::Config;

use crate::interfaces::storage::StateChain;
use crate::interfaces::mocks::storage::MockStorage;
use crate::interfaces::mocks::owner::MockOwner;


/// State struct representing an active UTXO shared by state entity and Owner
pub struct State {
    id: u32,
    utxo: String,
    key: String,
    state_chain: StateChain
    // owner_auth:
}
/// State Entity main
pub struct StateEntity {
    /// list of currently active states
    pub states: [State]
}


/// Run state entity main method
pub fn run(_config: Config) -> Result<(),()> {
    info!("Hello, world!");

    // let storage = Arc::new(MongoStorage::new(config.storage.clone())?);
    // let api_handler = ::api::run_api_server(&config.api, storage.clone());
    // let (req_send, req_recv): (Sender<sha256d::Hash>, Receiver<sha256d::Hash>) = channel();

    let storage = MockStorage::new();
    let owner = MockOwner::new();


    Ok(())
}
