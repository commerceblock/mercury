//! Shared Key
//!
//! Key shares of co-owned keys between user and server.


use super::super::ecdsa;
use super::super::ClientShim;
use super::super::Result;

use kms::ecdsa::two_party::MasterKey2;
use curv::elliptic::curves::traits::ECScalar;
use curv::FE;
use bitcoin::secp256k1::key::SecretKey;

#[derive(Serialize, Deserialize)]
pub struct SharedKey {
    pub id: String,
    pub share: MasterKey2,
}

impl SharedKey {
    pub fn new(id: &String, client_shim: &ClientShim, secret_key: &SecretKey, is_transfer: bool) -> Result<SharedKey> {
        let mut key_share_priv: FE = ECScalar::zero();  // convert to curv lib
        key_share_priv.set_element(*secret_key);
        ecdsa::get_master_key(id, client_shim, &key_share_priv, is_transfer)
    }
}
