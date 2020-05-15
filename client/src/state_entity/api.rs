//! API
//!
//! API calls availble for Client to State Entity

use super::super::Result;
use crate::wallet::wallet::Wallet;
use super::super::utilities::requests;
use shared_lib::structs::StateChainData;

/// Get state chain by ID
pub fn get_statechain(wallet: &mut Wallet, state_chain_id: &String) -> Result<StateChainData> {
    requests::post(&wallet.client_shim,&format!("api/statechain/{}",state_chain_id))
}
