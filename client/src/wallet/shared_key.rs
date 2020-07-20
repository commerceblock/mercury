//! Shared Key
//!
//! Key shares of co-owned keys between user and server.

use shared_lib::{structs::PrepareSignTxMsg, Root};
use super::super::{ClientShim, ecdsa, Result};

use kms::ecdsa::two_party::MasterKey2;
use curv::elliptic::curves::traits::ECScalar;
use curv::FE;
use bitcoin::secp256k1::key::SecretKey;
use monotree::Proof;

#[derive(Serialize, Deserialize, Clone)]
pub struct InclusionProofSMT {
    pub root: Root,
    pub proof: Option<Proof>
}
#[derive(Serialize, Deserialize)]
pub struct SharedKey {
    pub id: String,
    pub share: MasterKey2,
    pub value: u64, //Satoshis
    pub state_chain_id: Option<String>,
    pub tx_backup_psm: Option<PrepareSignTxMsg>, // back up transaction data
    pub proof_key: Option<String>,
    pub smt_proof: Option<InclusionProofSMT>,
    pub unspent: bool,
    pub funding_txid: String
}

impl SharedKey {
    pub fn new(id: &String, client_shim: &ClientShim, secret_key: &SecretKey, value: &u64, is_transfer: bool) -> Result<SharedKey> {
        let mut key_share_priv: FE = ECScalar::zero();  // convert to curv lib
        key_share_priv.set_element(*secret_key);
        ecdsa::get_master_key(id, client_shim, &key_share_priv, value, is_transfer)
    }

    pub fn add_proof_data(&mut self, proof_key: &String, root: &Root, proof: &Option<Proof>, funding_txid: &String) {
        self.proof_key = Some(proof_key.to_owned());
        self.smt_proof = Some(InclusionProofSMT {
            root: root.clone(), proof: proof.clone()
        });
        self.funding_txid = funding_txid.clone();
    }

    pub fn update_proof(&mut self, root: &Root, proof: &Option<Proof>) {
        self.smt_proof = Some(InclusionProofSMT {
            root: root.clone(), proof: proof.clone()
        });
    }
}
