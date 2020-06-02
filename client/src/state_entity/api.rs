//! API
//!
//! API calls availble for Client to State Entity

use super::super::Result;
use shared_lib::structs::{StateChainDataAPI, SmtProofMsgAPI, StateEntityFeeInfoAPI};
use shared_lib::Root;

use crate::{ClientShim, wallet::wallet::Wallet};
use super::super::utilities::requests;

use monotree::Proof;

/// Get state chain fee
pub fn get_statechain_fee_info(client_shim: &ClientShim) -> Result<StateEntityFeeInfoAPI> {
    requests::post(client_shim,&format!("api/fee/"))
}

/// Get state chain by ID
pub fn get_statechain(client_shim: &ClientShim, state_chain_id: &String) -> Result<StateChainDataAPI> {
    requests::post(client_shim,&format!("api/statechain/{}",state_chain_id))
}

/// Get state entity's sparse merkle tree root
pub fn get_smt_root(wallet: &mut Wallet) -> Result<Root> {
    requests::post(&wallet.client_shim,&format!("/api/root"))
}

/// Get state chain inclusion proof
pub fn get_smt_proof(wallet: &mut Wallet, root: &Root, funding_txid: &String) -> Result<Option<Proof>> {
    let smt_proof_msg = SmtProofMsgAPI {
        root: root.clone(),
        funding_txid: funding_txid.clone()
    };
    requests::postb(&wallet.client_shim,&format!("api/proof"),smt_proof_msg)
}
