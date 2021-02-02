//! Structs
//!
//! Struct definitions used in State entity protocols

use crate::state_chain::{State, StateChainSig};
use crate::Root;
use bitcoin::{OutPoint, Transaction, TxIn, TxOut};
use curv::{cryptographic_primitives::proofs::sigma_dlog::DLogProof, BigInt, FE, GE, PK};
use kms::ecdsa::two_party::party2;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two;

use bitcoin::{secp256k1::PublicKey, Address};
use std::{collections::HashSet, fmt};
use uuid::Uuid;
use rocket_okapi::JsonSchema;
use schemars;

use crate::ecies;
use crate::{util::transaction_serialise, ecies::{Encryptable, SelfEncryptable, WalletDecryptable}};

/// State Entity protocols
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Copy, PartialEq)]
pub enum Protocol {
    Deposit,
    Transfer,
    Withdraw,
}

// API structs

// schema struct for Uuid
#[derive(JsonSchema)]
#[schemars(remote = "Uuid")]
pub struct UuidDef(String);

//Encryptable version of FE
//Secret key is stored as raw bytes
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Default)]
pub struct FESer {
    secret_bytes: Vec<u8>,
}

impl FESer {
    pub fn get_fe(&self) -> ecies::Result<FE> {
        let secret = SK::from_slice(&self.secret_bytes)?;
        let mut fe = FE::zero();
        fe.set_element(secret);
        let fe = fe;
        Ok(fe)
    }

    pub fn from_fe(fe_in: &FE) -> Self {
        let sbs = fe_in.get_element().to_string();
        let secret_bytes = hex::decode(&sbs).expect("hex decode error");
        FESer { secret_bytes }
    }

    pub fn new_random() -> Self {
        let fe = FE::new_random();
        Self::from_fe(&fe)
    }
}

/// /info/info return struct
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct StateEntityFeeInfoAPI {
    pub address: String, // Receive address for fee payments
    pub deposit: u64,    // basis points
    pub withdraw: u64,   // basis points
    pub interval: u32,   // locktime decrement interval in blocks
    pub initlock: u32,   // inital backup locktime
}

impl fmt::Display for StateEntityFeeInfoAPI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Fee address: {},\nDeposit fee rate: {}\nWithdrawal fee rate: {}\nLock interval: {}\nInitial lock: {}",
            self.address, self.deposit, self.withdraw, self.interval, self.initlock
        )
    }
}

// schema dummy struct for outpoint
#[derive(JsonSchema)]
#[schemars(remote = "OutPoint")]
pub struct OutPointDef {
    pub txid: String,
    pub vout: u32,
}

/// /info/statechain return struct
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct StateChainDataAPI {
    #[schemars(with = "OutPointDef")]
    pub utxo: OutPoint,
    pub amount: u64,
    pub chain: Vec<State>,
    pub locktime: u32,  // the curent owner nlocktime
}

/// /info/transfer-batch return struct
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct TransferBatchDataAPI {
    #[schemars(with = "UuidDef")]
    pub state_chains: HashSet<Uuid>,
    pub finalized: bool,
}

/// /info/statechain post struct
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct SmtProofMsgAPI {
    pub root: Root,
    pub funding_txid: String,
}

#[derive(JsonSchema)]
#[schemars(remote = "PK")]
pub struct PKDef(Vec<u8>);

// PrepareSignTx structs

/// Struct contains data necessary to caluculate backup tx's input sighash('s). This is required
/// by Server before co-signing is performed for validation of tx.
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq)]
pub struct PrepareSignTxMsg {
    #[schemars(with = "UuidDef")]
    pub shared_key_id: Uuid,
    pub protocol: Protocol,
    pub tx_hex: String,
    #[schemars(with = "PKDef")]
    pub input_addrs: Vec<PK>, // pub keys being spent from
    pub input_amounts: Vec<u64>,
    pub proof_key: Option<String>,
}

impl Default for PrepareSignTxMsg {
    fn default() -> Self {
        let default_tx = Transaction {
            version: i32::default(),
            lock_time: u32::default(),
            input: Vec::<TxIn>::default(),
            output: Vec::<TxOut>::default(),
        };

        Self {
            shared_key_id: Uuid::default(),
            protocol: Protocol::Transfer,
            tx_hex: transaction_serialise(&default_tx),
            input_addrs: Vec::<PK>::default(),
            input_amounts: Vec::<u64>::default(),
            proof_key: None,
        }
    }
}

// schema information structs for openAPI/swagger
#[derive(JsonSchema)]
#[schemars(remote = "DLogProof")]
pub struct DLogProofDef(String);

#[derive(JsonSchema)]
#[schemars(remote = "party_two::EphKeyGenFirstMsg")]
pub struct EphKeyGenFirstMsgDef {
    pub pk_commitment: String,
    pub zk_pok_commitment: String,
}

#[derive(JsonSchema)]
#[schemars(remote = "BigInt")]
pub struct BigIntDef(String);

#[derive(JsonSchema)]
#[schemars(remote = "party2::SignMessage")]
pub struct SignMessageDef(String);

// 2P-ECDSA Co-signing algorithm structs

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct KeyGenMsg1 {
    #[schemars(with = "UuidDef")]
    pub shared_key_id: Uuid,
    pub protocol: Protocol,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct KeyGenMsg2 {
    #[schemars(with = "UuidDef")]
    pub shared_key_id: Uuid,
    #[schemars(with = "DLogProofDef")]
    pub dlog_proof: DLogProof,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct SignMsg1 {
    #[schemars(with = "UuidDef")]
    pub shared_key_id: Uuid,
    #[schemars(with = "EphKeyGenFirstMsgDef")]
    pub eph_key_gen_first_message_party_two: party_two::EphKeyGenFirstMsg,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct SignMsg2 {
    #[schemars(with = "UuidDef")]
    pub shared_key_id: Uuid,
    pub sign_second_msg_request: SignSecondMsgRequest,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct SignSecondMsgRequest {
    pub protocol: Protocol,
    #[schemars(with = "BigIntDef")]
    pub message: BigInt,
    #[schemars(with = "SignMessageDef")]
    pub party_two_sign_message: party2::SignMessage,
}

// Deposit algorithm structs

/// Client -> SE
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct DepositMsg1 {
    pub auth: String,
    pub proof_key: String,
}

/// Client -> SE
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct DepositMsg2 {
    #[schemars(with = "UuidDef")]
    pub shared_key_id: Uuid,
}

#[derive(JsonSchema)]
#[schemars(remote = "Address")]
pub struct AddressDef(String);
#[derive(JsonSchema)]
#[schemars(remote = "PublicKey")]
pub struct PubKeyDef(Vec<u8>);

// Transfer algorithm structs

/// Address generated for State Entity transfer protocol
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Hash)]
pub struct SCEAddress {
    #[schemars(with = "AddressDef")]
    pub tx_backup_addr: Option<Address>,
    #[schemars(with = "PubKeyDef")]
    pub proof_key: PublicKey,
}
impl Eq for SCEAddress {}

/// Sender -> SE
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct TransferMsg1 {
    #[schemars(with = "UuidDef")]
    pub shared_key_id: Uuid,
    pub statechain_sig: StateChainSig,
}

#[derive(JsonSchema)]
#[schemars(remote = "ecies::PublicKey")]
pub struct PublicKeyDef(Vec<u8>);

/// SE -> Sender
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq)]
pub struct TransferMsg2 {
    pub x1: FESer,
    #[schemars(with = "PublicKeyDef")]
    pub proof_key: ecies::PublicKey,
}
/// Sender -> Receiver
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq)]
pub struct TransferMsg3 {
    #[schemars(with = "UuidDef")]
    pub shared_key_id: Uuid,
    pub t1: FESer, // t1 = o1x1
    pub statechain_sig: StateChainSig,
    #[schemars(with = "UuidDef")]
    pub statechain_id: Uuid,
    pub tx_backup_psm: PrepareSignTxMsg,
    pub rec_se_addr: SCEAddress, // receivers state entity address (btc address and proof key)
}

#[derive(JsonSchema)]
#[schemars(remote = "FE")]
pub struct FEDef(Vec<u8>);

#[derive(JsonSchema)]
#[schemars(remote = "GE")]
pub struct GEDef(Vec<u8>);

/// Receiver -> State Entity
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct TransferMsg4 {
    #[schemars(with = "UuidDef")]
    pub shared_key_id: Uuid,
    #[schemars(with = "UuidDef")]
    pub statechain_id: Uuid,
    #[schemars(with = "FEDef")]
    pub t2: FE, // t2 = t1*o2_inv = o1*x1*o2_inv
    pub statechain_sig: StateChainSig,
    #[schemars(with = "GEDef")]
    pub o2_pub: GE,
    pub tx_backup_hex: String,
    pub batch_data: Option<BatchData>,
}

/// State Entity -> Lockbox
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KUSendMsg {
    pub user_id: Uuid,
    pub statechain_id: Uuid,
    pub x1: FE,
    pub t1: FE,
    pub o2_pub: GE,
}

/// Lockbox -> State Entity
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KUReceiveMsg {
    pub theta: FE,
    pub s2_pub: GE,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KUFinalize {
    pub statechain_id: Uuid,
    pub shared_key_id: Uuid,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KUAttest {
    pub statechain_id: Uuid,
    pub attestation: String,
}

/// State Entity -> Receiver
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct TransferMsg5 {
    #[schemars(with = "UuidDef")]
    pub new_shared_key_id: Uuid,
    #[schemars(with = "GEDef")]
    pub s2_pub: GE,
    #[schemars(with = "FEDef")]
    pub theta: FE,
}

/// Conductor -> StateEntity
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct TransferBatchInitMsg {
    #[schemars(with = "UuidDef")]
    pub id: Uuid,
    pub signatures: Vec<StateChainSig>,
}

/// User -> State Entity
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct TransferRevealNonce {
    #[schemars(with = "UuidDef")]
    pub batch_id: Uuid,
    pub hash: String,
    #[schemars(with = "UuidDef")]
    pub statechain_id: Uuid,
    pub nonce: [u8; 32],
}

/// Data present if transfer is part of an atomic batch transfer
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct BatchData {
    #[schemars(with = "UuidDef")]
    pub id: Uuid,
    pub commitment: String, // Commitment to transfer input UTXO in case of protocol failure
}

// Withdraw algorithm structs
/// Owner -> State Entity
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct WithdrawMsg1 {
    #[schemars(with = "UuidDef")]
    pub shared_key_id: Uuid,
    pub statechain_sig: StateChainSig,
}

/// Owner -> State Entity
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct WithdrawMsg2 {
    #[schemars(with = "UuidDef")]
    pub shared_key_id: Uuid,
    pub address: String,
}

impl Default for TransferMsg5 {
    fn default() -> TransferMsg5 {
        TransferMsg5 {
            new_shared_key_id: Uuid::new_v4(),
            s2_pub: GE::base_point2(),
            theta: ECScalar::zero(),
        }
    }
}

use curv::elliptic::curves::secp256_k1::SK;
impl SelfEncryptable for SK {
    fn encrypt_with_pubkey(&mut self, pubkey: &ecies::PublicKey) -> ecies::Result<()> {
        let ss = self.to_string();
        let esb = ecies::ecies::encrypt(&pubkey.to_bytes(), ss.as_bytes())?;
        let esk = SK::from_slice(&esb[..])?;
        *self = esk;
        Ok(())
    }

    fn decrypt(&mut self, privkey: &ecies::PrivateKey) -> ecies::Result<()> {
        let ess = self.to_string();
        let sb = ecies::ecies::decrypt(&privkey.to_bytes(), ess.as_bytes())?;
        let sk = SK::from_slice(&sb[..])?;
        *self = sk;
        Ok(())
    }
}

use curv::elliptic::curves::traits::ECScalar;
impl Encryptable for FESer {}
impl SelfEncryptable for FESer {
    fn decrypt(&mut self, privkey: &crate::ecies::PrivateKey) -> ecies::Result<()> {
        let sb_plain = ecies::ecies::decrypt(&privkey.to_bytes(), &self.secret_bytes[..])?;
        self.secret_bytes = sb_plain;
        Ok(())
    }

    fn encrypt_with_pubkey(&mut self, pubkey: &crate::ecies::PublicKey) -> ecies::Result<()> {
        let sb_enc = ecies::ecies::encrypt(&pubkey.to_bytes(), &self.secret_bytes[..])?;
        self.secret_bytes = sb_enc;
        Ok(())
    }
}

impl Encryptable for TransferMsg2 {}
impl SelfEncryptable for TransferMsg2 {
    fn decrypt(&mut self, privkey: &crate::ecies::PrivateKey) -> crate::ecies::Result<()> {
        self.x1.decrypt(privkey)
    }

    fn encrypt_with_pubkey(
        &mut self,
        pubkey: &crate::ecies::PublicKey,
    ) -> crate::ecies::Result<()> {
        self.x1.encrypt_with_pubkey(pubkey)
    }
}
use std::str::FromStr;
impl WalletDecryptable for TransferMsg2 {
    fn get_public_key(&self) -> crate::ecies::Result<Option<crate::ecies::PublicKey>> {
        Ok(Some(self.proof_key))
    }
}

impl SelfEncryptable for &mut TransferMsg2 {
    fn decrypt(&mut self, privkey: &crate::ecies::PrivateKey) -> crate::ecies::Result<()> {
        (**self).decrypt(privkey)
    }
    fn encrypt_with_pubkey(
        &mut self,
        pubkey: &crate::ecies::PublicKey,
    ) -> crate::ecies::Result<()> {
        (**self).encrypt_with_pubkey(pubkey)
    }
}
impl WalletDecryptable for &mut TransferMsg2 {
    fn get_public_key(&self) -> crate::ecies::Result<Option<crate::ecies::PublicKey>> {
        (**self).get_public_key()
    }
}

impl Encryptable for TransferMsg3 {}
impl SelfEncryptable for TransferMsg3 {
    fn decrypt(&mut self, privkey: &crate::ecies::PrivateKey) -> crate::ecies::Result<()> {
        self.t1.decrypt(privkey)
    }

    fn encrypt_with_pubkey(
        &mut self,
        pubkey: &crate::ecies::PublicKey,
    ) -> crate::ecies::Result<()> {
        self.t1.encrypt_with_pubkey(pubkey)
    }
}

impl WalletDecryptable for TransferMsg3 {
    fn get_public_key(&self) -> crate::ecies::Result<Option<crate::ecies::PublicKey>> {
        Ok(Some(crate::ecies::PublicKey::from_str(
            &self.statechain_sig.data,
        )?))
    }
}

impl SelfEncryptable for &mut TransferMsg3 {
    fn decrypt(&mut self, privkey: &crate::ecies::PrivateKey) -> crate::ecies::Result<()> {
        (**self).decrypt(privkey)
    }
    fn encrypt_with_pubkey(
        &mut self,
        pubkey: &crate::ecies::PublicKey,
    ) -> crate::ecies::Result<()> {
        (**self).encrypt_with_pubkey(pubkey)
    }
}
impl WalletDecryptable for &mut TransferMsg3 {
    fn get_public_key(&self) -> crate::ecies::Result<Option<crate::ecies::PublicKey>> {
        (**self).get_public_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::keygen::generate_keypair;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use rand::rngs::OsRng;

    #[test]
    fn test_encrypt_fe_ser() {
        let mut fe_ser = FESer::new_random();
        let fe_ser_clone = fe_ser.clone();
        assert_eq!(fe_ser, fe_ser_clone);
        let (priv_k, pub_k) = generate_keypair();
        fe_ser.encrypt_with_pubkey(&pub_k).unwrap();
        assert_ne!(fe_ser, fe_ser_clone);
        fe_ser.decrypt(&priv_k).unwrap();
        assert_eq!(fe_ser, fe_ser_clone);
    }

    #[test]
    fn test_to_from_fe_ser() {
        let fe_ser = FESer::new_random();
        let _ = fe_ser.get_fe().expect("failed to get fe");
        let fe = FE::new_random();
        let fe_ser = FESer::from_fe(&fe);
        let _ = fe_ser.get_fe().expect("failed to get fe");
    }

    #[test]
    fn test_encrypt_transfer_msg3() {
        let mut rng = OsRng::new().expect("OsRng");
        let secp = Secp256k1::new();
        let mut msg = TransferMsg3 {
            shared_key_id: Uuid::new_v4(),
            t1: FESer::new_random(),
            statechain_sig: StateChainSig::default(),
            statechain_id: Uuid::new_v4(),
            tx_backup_psm: PrepareSignTxMsg::default(),
            rec_se_addr: SCEAddress {
                tx_backup_addr: Some(
                    Address::from_str("1DTFRJ2XFb4AGP1Tfk54iZK1q2pPfK4n3h").unwrap(),
                ),
                proof_key: PublicKey::from_secret_key(&secp, &SecretKey::new(&mut rng)),
            },
        };

        let msg_clone = msg.clone();
        assert_eq!(msg, msg_clone);
        let (priv_k, pub_k) = generate_keypair();
        msg.encrypt_with_pubkey(&pub_k).unwrap();
        assert_ne!(msg, msg_clone);
        msg.decrypt(&priv_k).unwrap();
        assert_eq!(msg, msg_clone);

        let msg_ref = &mut msg;
        assert_eq!(msg_ref, &msg_clone);
        msg_ref.encrypt_with_pubkey(&pub_k).unwrap();
        assert_ne!(msg_ref, &msg_clone);
        msg_ref.decrypt(&priv_k).unwrap();
        assert_eq!(msg_ref, &msg_clone);
    }

    #[test]
    fn test_encrypt_transfer_msg2() {
        let x1 = FESer::new_random();
        let (priv_k, proof_key) = generate_keypair();

        let mut msg = TransferMsg2 { x1, proof_key };

        let msg_clone = msg.clone();

        assert_eq!(msg, msg_clone);
        msg.encrypt().unwrap();

        assert_ne!(msg, msg_clone);
        msg.decrypt(&priv_k).unwrap();
        assert_eq!(msg, msg_clone);

        let msg_ref = &mut msg;
        assert_eq!(msg_ref, &msg_clone);
        msg_ref.encrypt_with_pubkey(&proof_key).unwrap();
        assert_ne!(msg_ref, &msg_clone);
        msg_ref.decrypt(&priv_k).unwrap();
        assert_eq!(msg_ref, &msg_clone);
    }
}
