use super::Result;
use crate::error::SharedLibError;
use crate::{
    blinded_token::{BSTSenderData, BlindedSpendToken},
    state_chain::StateChainSig,
    structs::*,
    util::keygen::Message,
    Verifiable,
};
use bitcoin::{
    hashes::{sha256d, Hash},
    secp256k1::{PublicKey, Secp256k1, SecretKey, Signature},
};
use curv::FE;
use uuid::Uuid;
use rocket_okapi::JsonSchema;
use schemars;
use log::info;

// Swaps
#[allow(dead_code)]
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub enum SwapStatus {
    Phase1,
    Phase2,
    Phase3,
    Phase4,
    End,
}

/// Struct defines a Swap. This is signed by each participant as agreement to take part in the swap.
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct SwapToken {
    #[schemars(with = "UuidDef")]
    pub id: Uuid,
    pub amount: u64,
    pub time_out: u64,
    #[schemars(with = "UuidDef")]
    pub statechain_ids: Vec<Uuid>,
}
impl SwapToken {
    /// Create message to be signed
    pub fn to_message(&self) -> Result<Message> {
        let mut str = self.amount.to_string();
        str.push_str(&self.time_out.to_string());
        str.push_str(&format!("{:?}", self.statechain_ids));
        info!("swap token message str: {}", str);
        let hash = sha256d::Hash::hash(&str.as_bytes());
        info!("swap token message hash: {}", hash);
        Ok(Message::from_slice(&hash)?)
    }

    /// Generate Signature for change of state chain ownership
    pub fn sign(&self, proof_key_priv: &SecretKey) -> Result<Signature> {
        let secp = Secp256k1::new();

        let message = self.to_message()?;
        Ok(secp.sign(&message, &proof_key_priv))
    }

    /// Verify self's signature for transfer or withdraw
    pub fn verify_sig(&self, pk: &PublicKey, sig: Signature) -> Result<()> {
        let secp = Secp256k1::new();

        match secp.verify(&self.to_message()?, &sig, &pk) {
            Ok(_) => {
                info!("verify_sig: ok");
                Ok(())
            },
            Err(e) => {
                info!("verify_sig: not ok");
                Err(SharedLibError::SwapError(format!(
                    "swap token signature does not sign for token: {}",
                    e
                )))
            },
        }
    }
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct SwapInfo {
    pub status: SwapStatus,
    pub swap_token: SwapToken,
    pub bst_sender_data: BSTSenderData,
}

/// Owner -> Conductor
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct RegisterUtxo {
    #[schemars(with = "UuidDef")]
    pub statechain_id: Uuid,
    pub signature: StateChainSig,
    pub swap_size: u64,
}

#[derive(JsonSchema)]
#[schemars(remote = "Signature")]
pub struct SignatureDef(String);

/// Owner -> Conductor
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct SwapMsg1 {
    #[schemars(with = "UuidDef")]
    pub swap_id: Uuid,
    #[schemars(with = "UuidDef")]
    pub statechain_id: Uuid,
    #[schemars(with = "SignatureDef")]
    pub swap_token_sig: String,
    pub transfer_batch_sig: StateChainSig,
    pub address: SCEAddress,
    #[schemars(with = "FEDef")]
    pub bst_e_prime: FE,
}

// Message to request a blinded spend token
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct BSTMsg {
    #[schemars(with = "UuidDef")]
    pub swap_id: Uuid,
    #[schemars(with = "UuidDef")]
    pub statechain_id: Uuid,
}

/// Owner -> Conductor
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct SwapMsg2 {
    #[schemars(with = "UuidDef")]
    pub swap_id: Uuid,
    pub blinded_spend_token: BlindedSpendToken,
}
