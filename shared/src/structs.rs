//! Structs
//!
//! Struct definitions used in State entity protocols

use crate::state_chain::{State, StateChainSig};
use crate::Root;
use bitcoin::{OutPoint, Transaction, TxIn, TxOut};
use curv::{cryptographic_primitives::proofs::sigma_dlog::DLogProof, BigInt, FE, GE, PK};
use kms::ecdsa::two_party::{party1,party2};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_one,party_two};

use bitcoin::{secp256k1::PublicKey, Address};
use std::{collections::{HashSet,HashMap}, fmt};
use uuid::Uuid;
use rocket_okapi::JsonSchema;
use schemars;
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use serde::de::{self, Visitor, Unexpected};
use regex::Regex;

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

pub trait SchemaExample{
    fn example() -> Self;
}

// schema struct for Uuid
#[derive(JsonSchema)]
#[schemars(remote = "Uuid")]
pub struct UuidDef(String);

// structs for ids
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Default)]
pub struct UserID {
    #[schemars(with = "UuidDef")]
    pub id: Uuid,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Default)]
pub struct StatechainID {
    #[schemars(with = "UuidDef")]
    pub id: Uuid,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Default)]
pub struct SwapID {
    #[schemars(with = "UuidDef")]
    pub id: Option<Uuid>,
}

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

/// Statechain entity operating information
/// This struct is returned containing information on operating requirements 
/// of the statechain entity which must be conformed with in the protocol. 
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[schemars(example = "Self::example")]
pub struct StateEntityFeeInfoAPI {
    /// The Bitcoin address that the SE fee must be paid to
    pub address: String, // Receive address for fee payments
    /// The deposit fee, which is specified as a proportion of the deposit amount in basis points
    pub deposit: u64,    // basis points
    /// The withdrawal fee, which is specified as a proportion of the deposit amount in basis points
    pub withdraw: u64,   // basis points
    /// The decementing nLocktime (block height) interval enforced for backup transactions
    pub interval: u32,   // locktime decrement interval in blocks
    /// The initial nLocktime from the current blockheight for the first backup
    pub initlock: u32,   // inital backup locktime
}

impl StateEntityFeeInfoAPI{
    pub fn example() -> Self{
        Self{
            address: "bc1qzvv6yfeg0navfkrxpqc0fjdsu9ey4qgqqsarq4".to_string(),
            deposit: 0,
            withdraw: 300,
            interval: 144,
            initlock: 14400,
        }
    }
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

/// Swap group status data
#[derive(JsonSchema, Debug, Hash, Eq, PartialEq, Clone)]
#[schemars(example = "Self::example")]
pub struct SwapGroup {
    pub amount: u64,
    pub size: u64,
}

impl SwapGroup {
    pub fn new(amount: u64, size: u64) -> SwapGroup {
        SwapGroup {amount, size}
    }
    
    pub fn example() -> Self{
        Self{
            amount: 1000000,
            size: 5,
        }
    }
}

impl Serialize for SwapGroup {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}:{}", self.amount, self.size))
    }
}

struct SwapGroupVisitor;

impl<'de> Visitor<'de> for SwapGroupVisitor {
    type Value = SwapGroup;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a colon-separated pair of u64 integers")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let re = Regex::new(r"(\d+):(\d+)").unwrap(); 
        if let Some(nums) = re.captures_iter(s).next() {
            if let Ok(amount) = u64::from_str(&nums[1]) { 
                if let Ok(size) = u64::from_str(&nums[2]) {
                    Ok(SwapGroup::new(amount, size))
                } else {
                    Err(de::Error::invalid_value(Unexpected::Str(s), &self))
                }
            } else {
                Err(de::Error::invalid_value(Unexpected::Str(s), &self))
            }
        } else {
            Err(de::Error::invalid_value(Unexpected::Str(s), &self))
        }
    }
}

impl<'de> Deserialize<'de> for SwapGroup {
    fn deserialize<D>(deserializer: D) -> Result<SwapGroup, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(SwapGroupVisitor)
    }
}

/// List of current statecoin amounts and the number of each 
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct CoinValueInfo {
    pub values: HashMap<u64,u64>,
}

impl CoinValueInfo {
    pub fn new() -> Self {
        Self { values: HashMap::<u64,u64>::new() }
    }
}

// schema dummy struct for outpoint
/// Bitcoin UTXO Outpoint
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[schemars(remote = "OutPoint")]
#[schemars(example = "Self::example")]
pub struct OutPointDef {
    /// Transaction ID
    pub txid: String,
    /// Vout Index
    pub vout: u32,
}

impl OutPointDef{
    pub fn example() -> Self{
        Self{
            txid: "320b2abfbfda6b722c0e6c712efedd1341296a387d4e63d44507179b183283a0".to_string(),
            vout: 0,
        }
    }
}

// /info/statechain return struct
/// Statechain data
/// This struct is returned containing the statechain of the specified statechain ID 
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[schemars(example = "Self::example")]
pub struct StateChainDataAPI {
    /// The statecoin UTXO OutPoint
    #[schemars(with = "OutPointDef")]
    pub utxo: OutPoint,
    /// The value of the statecoin (in satoshis)
    pub amount: u64,
    /// The statechain of owner proof keys and signatures
    pub chain: Vec<State>,
    /// The current owner nLocktime
    pub locktime: u32,  // the curent owner nlocktime
}

impl StateChainDataAPI {
    pub fn example() -> Self{
        Self{
            utxo: OutPoint::null(),
            amount: 1000000,
            chain: vec![State::example()],
            locktime: 712903,
        }
    }
}

/// /info/transfer-batch return struct
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct TransferBatchDataAPI {
    #[schemars(with = "UuidDef")]
    pub state_chains: HashSet<Uuid>,
    pub finalized: bool,
}

// /info/statechain post struct
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
    /// The shared key ID
    #[schemars(with = "UuidDef")]
    pub shared_key_id: Uuid,
    /// Purpose: "TRANSFER", "TRANSFER-BATCH" or "WITHDRAW"
    pub protocol: Protocol,
    /// Hex encoding of the unsigned transaction
    pub tx_hex: String,
    /// Vector of the transaction input public keys
    #[schemars(with = "PKDef")]
    pub input_addrs: Vec<PK>, // pub keys being spent from
    /// Vector of input amounts
    pub input_amounts: Vec<u64>,
    /// Proof public key
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

//impl PrepareSignTxMsg {
//    pub fn example() -> Self{
//        Self{
//            shared_key_id: Uuid::new_v4(),
//            protocol: Protocol::Deposit,
//            tx_hex: "02000000011333183ddf384da83ed49296136c70d206ad2b19331bf25d390e69b222165e370000000000feffffff0200e1f5050000000017a914a860f76561c85551594c18eecceffaee8c4822d787F0C1A4350000000017a914d8b6fcc85a383261df05423ddf068a8987bf0287878c000000".to_string(),
//            input_addrs: vec![PK::from_slice(&[3, 203, 250, 103, 44, 175, 45, 118, 114, 227, 88, 79, 151, 147, 57, 93, 64, 179, 159, 123, 212, 118, 151, 210, 3, 231, 97, 50, 111, 56, 152, 9, 218]).unwrap()], // pub keys being spent from
//            input_amounts: vec![100000],
//            proof_key: Some("02a95498bdde2c8c4078f01840b3bc8f4ae5bb1a90b880a621f50ce221bce3ddbe".to_string()),
//        }
//    }
//}

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

#[derive(JsonSchema)]
#[schemars(remote = "party_one::KeyGenFirstMsg")]
pub struct KeyGenFirstMsgDef(String);

#[derive(JsonSchema)]
#[schemars(remote = "party1::KeyGenParty1Message2")]
pub struct KeyGenParty1Message2Def(String);

#[derive(JsonSchema)]
#[schemars(remote = "party_one::EphKeyGenFirstMsg")]
pub struct EphKeyGenFirstMsg2Def(String);

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
pub struct KeyGenReply2 {
    #[schemars(with = "KeyGenParty1Message2Def")]
    pub msg: party1::KeyGenParty1Message2,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct KeyGenReply1 {
    #[schemars(with = "UuidDef")]
    pub user_id: Uuid,
    #[schemars(with = "KeyGenFirstMsgDef")]
    pub msg: party_one::KeyGenFirstMsg,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct SignReply1 {
    #[schemars(with = "EphKeyGenFirstMsg2Def")]
    pub msg: party_one::EphKeyGenFirstMsg,
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

/// SE public key share for encryption
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq)]
pub struct S1PubKey {
    pub key: String,
}

/// Receiver -> State Entity
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct TransferMsg4 {
    #[schemars(with = "UuidDef")]
    pub shared_key_id: Uuid,
    #[schemars(with = "UuidDef")]
    pub statechain_id: Uuid,
    #[schemars(with = "FEDef")]
    pub t2: FESer, // t2 = t1*o2_inv = o1*x1*o2_inv
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
    pub t2: FESer,
    pub o2_pub: GE,
}

/// Lockbox -> State Entity
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KUReceiveMsg {
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

impl Encryptable for TransferMsg4 {}
impl SelfEncryptable for TransferMsg4 {
    fn decrypt(&mut self, privkey: &crate::ecies::PrivateKey) -> crate::ecies::Result<()> {
        self.t2.decrypt(privkey)
    }

    fn encrypt_with_pubkey(
        &mut self,
        pubkey: &crate::ecies::PublicKey,
    ) -> crate::ecies::Result<()> {
        self.t2.encrypt_with_pubkey(pubkey)
    }
}

impl SelfEncryptable for &mut TransferMsg4 {
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
