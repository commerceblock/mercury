//! API
//!
//! API calls availble for Client to State Entity

use super::super::Result;
use shared_lib::structs::{
    SmtProofMsgAPI, StateChainDataAPI, StateEntityFeeInfoAPI, 
    TransferBatchDataAPI, RecoveryDataMsg, RecoveryRequest, 
    CoinValueInfo, StateCoinDataAPI, TransferFinalizeData, BlindedStateChainData
};
use shared_lib::Root;

use super::super::utilities::requests;
use crate::ClientShim;

use monotree::Proof;
use uuid::Uuid;
use std::collections::HashMap;

/// Get state chain fee
pub fn get_statechain_fee_info(client_shim: &ClientShim) -> Result<StateEntityFeeInfoAPI> {
    requests::get(client_shim, &format!("info/fee"))
}

/// Get state chain fee
pub fn get_swaps_group_info(client_shim: &ClientShim) -> Result<HashMap<String,u64>> {
    requests::get(client_shim, &format!("/swap/groupinfo"))
}

/// Get state chain fee
pub fn get_coins_info(client_shim: &ClientShim) -> Result<CoinValueInfo> {
    requests::get(client_shim, &format!("/info/coins"))
}

/// Get state chain by ID
pub fn get_statechain(
    client_shim: &ClientShim,
    statechain_id: &Uuid,
) -> Result<StateChainDataAPI> {
    requests::get(client_shim, &format!("info/statechain/{}", statechain_id))
}

/// Get blinded state chain by ID
pub fn get_blinded_statechain(
    client_shim: &ClientShim,
    statechain_id: &Uuid,
) -> Result<BlindedStateChainData> {
    requests::get(client_shim, &format!("info/blinded/statechain/{}", statechain_id))
}

/// Get state chain by ID to depth
pub fn get_statechain_depth(
    client_shim: &ClientShim,
    statechain_id: &Uuid,
    depth: &usize
) -> Result<StateChainDataAPI> {
    requests::get(client_shim, &format!("info/statechain/{}/{}", statechain_id, depth))
}

/// Get statecoin (statechain tip) by statechain ID
pub fn get_statecoin(
    client_shim: &ClientShim,
    statechain_id: &Uuid,
) -> Result<StateCoinDataAPI> {
    requests::get(client_shim, &format!("info/statecoin/{}", statechain_id))
}

/// Get recovery data by pubkey
pub fn get_recovery_data(
    client_shim: &ClientShim,
    pubkey_hex: &str,
) -> Result<Vec<RecoveryDataMsg>> {
    let recovery_request = vec!(RecoveryRequest {
            key: pubkey_hex.to_string(),
            sig: "".to_string(),
        });
    requests::postb(client_shim, &format!("info/recover/"), recovery_request)
}

/// Get recovery data by vec of pubkeys
pub fn get_recovery_data_vec(
    client_shim: &ClientShim,
    pubkey_hex: &Vec<String>,
) -> Result<Vec<RecoveryDataMsg>> {
    let mut recovery_request = vec![];
    
    for pk in pubkey_hex{
        recovery_request.push(RecoveryRequest {
            key: pk.to_string(),
            sig: "".to_string(),
        });
    }

    requests::postb(client_shim, &format!("info/recover/"), recovery_request)
}

pub fn get_sc_transfer_finalize_data(
    client_shim: &ClientShim,
    statechain_id: &Uuid
) -> Result<TransferFinalizeData> {
    requests::get(client_shim, &format!("info/sc-transfer-finalize-data/{}",statechain_id))
}

/// Get state entity's sparse merkle tree root
pub fn get_smt_root(client_shim: &ClientShim) -> Result<Option<Root>> {
    requests::get(&client_shim, &format!("info/root"))
}

/// Get state entity's sparse merkle tree root that has been confirmed by mainstay
pub fn get_confirmed_smt_root(client_shim: &ClientShim) -> Result<Option<Root>> {
    requests::get(&client_shim, &format!("info/confirmed_root"))
}

/// Get state chain inclusion proof
pub fn get_smt_proof(
    client_shim: &ClientShim,
    root: &Root,
    funding_txid: &String,
) -> Result<Option<Proof>> {
    let smt_proof_msg = SmtProofMsgAPI {
        root: root.clone(),
        funding_txid: funding_txid.clone(),
    };
    requests::postb(&client_shim, &format!("info/proof"), smt_proof_msg)
}

/// Get transaction batch session status
pub fn get_transfer_batch_status(
    client_shim: &ClientShim,
    batch_id: &Uuid,
) -> Result<TransferBatchDataAPI> {
    requests::get(client_shim, &format!("info/transfer-batch/{}", batch_id))
}

/// Get blinded transaction batch session status
pub fn get_blinded_transfer_batch_status(
    client_shim: &ClientShim,
    batch_id: &Uuid,
) -> Result<TransferBatchDataAPI> {
    requests::get(client_shim, &format!("/blinded/info/transfer-batch/{}", batch_id))
}

/// Reset the state entity's database and in-memory data
pub fn reset_data(client_shim: &ClientShim) -> Result<()> {
    requests::get(client_shim, "test/reset-db")
}

/// Reset the state entity's database and in-memory data
pub fn reset_inram_data(client_shim: &ClientShim) -> Result<()> {
    requests::get(client_shim, "test/reset-inram-data")
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::mock;

    fn mock_url() -> String {
        String::from(&mockito::server_url())
    }

    #[test]
    fn test_tor() {
        let url = mock_url();

        let _m = mock("get", "/")
            .with_header("Content-Type", "application/json")
            .with_body("{\"test string\"}");

        let tor = crate::Tor::default();

        let _client_shim = ClientShim::new(url, None, Some(tor));
        //let test_string: String = requests::get(&client_shim, &format!("/")).expect("failed to get test string via tor");
        //assert_eq!(test_string, "test string".to_string());
    }
}

