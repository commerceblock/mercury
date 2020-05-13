//! Shared Key
//!
//! Key shares of co-owned keys between user and server.


use super::super::ecdsa;
use super::super::ClientShim;
use super::super::Result;

use kms::ecdsa::two_party::MasterKey2;
use curv::FE;

#[derive(Serialize, Deserialize)]
pub struct SharedKey {
    pub id: String,
    pub share: MasterKey2,
}

impl SharedKey {
    pub fn new(id: &String, client_shim: &ClientShim) -> Result<SharedKey> {
        ecdsa::get_master_key(id, client_shim)
    }

    pub fn new_fixed_secret_key(id: &String, client_shim: &ClientShim, secrte_key: &FE) -> Result<SharedKey> {
        ecdsa::get_master_key_with_fixed_secret(id, client_shim, secrte_key)
    }
}
