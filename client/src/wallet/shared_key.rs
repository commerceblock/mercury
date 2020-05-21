//! Shared Key
//!
//! Key shares of co-owned keys between user and server.


use super::super::ecdsa;
use super::super::ClientShim;
use super::super::Result;

use kms::ecdsa::two_party::MasterKey2;
use curv::elliptic::curves::traits::ECScalar;
use curv::FE;
use bitcoin::PublicKey;
use bitcoin::secp256k1::key::SecretKey;
use monotree::{Proof,Hash};

#[derive(Serialize, Deserialize, Clone)]
pub struct InclusionProofSMT {
    pub root: Option<Hash>,
    pub proof: Option<Proof>
}
#[derive(Serialize, Deserialize)]
pub struct SharedKey {
    pub id: String,
    pub share: MasterKey2,
    pub proof_key: Option<PublicKey>,
    pub smt_proof: Option<InclusionProofSMT>
}

impl SharedKey {
    pub fn new(id: &String, client_shim: &ClientShim, secret_key: &SecretKey, is_transfer: bool) -> Result<SharedKey> {
        let mut key_share_priv: FE = ECScalar::zero();  // convert to curv lib
        key_share_priv.set_element(*secret_key);
        ecdsa::get_master_key(id, client_shim, &key_share_priv, is_transfer)
    }

    pub fn add_proof_data(&mut self, proof_key: &PublicKey, root: &Option<Hash>, proof: &Option<Proof>) {
        self.proof_key = Some(proof_key.clone());
        self.smt_proof = Some(InclusionProofSMT {
            root: root.clone(), proof: proof.clone()
        });
    }
}
