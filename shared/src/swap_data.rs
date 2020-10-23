use super::Result;
use crate::{
    blinded_token::{BSTSenderData, BlindedSpendToken},
    structs::*,
    util::keygen::Message,
    Verifiable,
    state_chain::StateChainSig
};
use uuid::Uuid;
use curv::FE;
use bitcoin::{
    hashes::{sha256d, Hash},
    secp256k1::{PublicKey, Secp256k1, SecretKey, Signature}
};
use crate::error::SharedLibError;

// Swaps
#[allow(dead_code)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub enum SwapStatus {
    Phase1,
    Phase2,
    Phase3,
    Phase4,
    End,
}

/// Struct defines a Swap. This is signed by each participant as agreement to take part in the swap.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SwapToken {
    pub id: Uuid,
    pub amount: u64,
    pub time_out: u64,
    pub state_chain_ids: Vec<Uuid>,
}
impl SwapToken {
    /// Create message to be signed
   pub fn to_message(&self) -> Result<Message> {
        let mut str = self.amount.to_string();
        str.push_str(&self.time_out.to_string());
        str.push_str(&format!("{:?}", self.state_chain_ids));
        let hash = sha256d::Hash::hash(&str.as_bytes());
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
        match sig.verify(pk, &self.to_message()?) {
            Ok(_) => Ok(()),
            Err(e) => Err(SharedLibError::SwapError(format!(
                "signature does not sign for token: {}",
                e
            ))),
        }
    }
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SwapInfo {
    pub status: SwapStatus,
    pub swap_token: SwapToken,
    pub bst_sender_data: BSTSenderData,
}


/// Owner -> Conductor
#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterUtxo {
    pub state_chain_id: Uuid,
    pub signature: StateChainSig,
    pub swap_size: u64,
}

/// Owner -> Conductor
#[derive(Serialize, Deserialize, Debug)]
pub struct SwapMsg1 {
    pub swap_id: Uuid,
    pub state_chain_id: Uuid,
    pub swap_token_sig: Signature,
    pub transfer_batch_sig: StateChainSig,
    pub address: SCEAddress,
    pub bst_e_prime: FE,
}

// Message to request a blinded spend token
#[derive(Serialize, Deserialize, Debug)]
pub struct BSTMsg {
    pub swap_id: Uuid,
    pub state_chain_id: Uuid,
}

/// Owner -> Conductor
#[derive(Serialize, Deserialize, Debug)]
pub struct SwapMsg2 {
    pub swap_id: Uuid,
    pub blinded_spend_token: BlindedSpendToken,
}