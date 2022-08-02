//! Structs
//!
//! Struct definitions used in State entity protocols

use crate::error::SharedLibError;
use crate::state_chain::{State, StateChainSig};
use crate::Root;
use bitcoin::{OutPoint, Transaction, TxIn, TxOut};
use curv::{cryptographic_primitives::proofs::sigma_dlog::DLogProof, BigInt, FE, GE, PK};
use kms::ecdsa::two_party::{party1,party2};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_one,party_two};

use bitcoin::{secp256k1::PublicKey, Address};
use std::{collections::{HashSet, HashMap}, fmt};
use uuid::Uuid;
use rocket_okapi::JsonSchema;
use schemars;
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use serde::de::{self, Visitor, Unexpected};
use regex::Regex;
use chrono::{NaiveDateTime, Utc};
use std::default::Default;
use std::num::NonZeroU64;

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


#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq)]
pub struct Invoice{
    pub payment_hash: String,
    pub expires_at: u64,
    pub bolt11: String
}

impl From<clightningrpc::responses::Invoice> for Invoice {
    fn from(item: clightningrpc::responses::Invoice) -> Self {
        Self {
            payment_hash: item.payment_hash,
            expires_at: item.expires_at,
            bolt11: item.bolt11
        }
    }
}


#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq)]
pub struct PODInfo {
    #[schemars(with = "UuidDef")]
    pub token_id: Uuid,
    pub lightning_invoice: Invoice,
    #[schemars(with = "AddressDef")]
    pub btc_payment_address: Address,
    pub value: u64
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct PODStatus {
    pub confirmed: bool,
    pub amount: u64,
}

impl PartialEq<bool> for PODStatus {
    fn eq(&self, other: &bool) -> bool {
        (self.confirmed && self.amount > 0) == *other
    }
}

impl PartialEq<Self> for PODStatus {
    fn eq(&self, other: &Self) -> bool {
        (self.confirmed == other.confirmed) && (self.amount == other.amount)
    }
}

impl PODStatus {
    pub fn empty(&self) -> bool {
        self.amount == 0
    }
}

// structs for ids
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq, Default)]
pub struct UserID {
    #[schemars(with = "UuidDef")]
    pub id: Uuid,
    pub challenge: Option<String>,
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
    pub secret_bytes: Vec<u8>,
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
    pub deposit: i64,    // basis points
    /// The withdrawal fee, which is specified as a proportion of the deposit amount in basis points
    pub withdraw: u64,   // basis points
    /// The decementing nLocktime (block height) interval enforced for backup transactions
    pub interval: u32,   // locktime decrement interval in blocks
    /// The initial nLocktime from the current blockheight for the first backup
    pub initlock: u32,   // inital backup locktime
    /// The minumum wallet version required
    pub wallet_version: String,
    /// Message to display to all wallet users on startup
    pub wallet_message: String,
}

impl StateEntityFeeInfoAPI{
    pub fn example() -> Self{
        Self{
            address: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
            deposit: 0,
            withdraw: 300,
            interval: 144,
            initlock: 14400,
            wallet_version: "0.4.65".to_string(),
            wallet_message: "Warning".to_string(),
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

/// Swap group data
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
        if let Some(nums) = Regex::new(r"(\d+):(\d+)").unwrap().captures_iter(s).next() {
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

/// Swap group status data
#[derive(JsonSchema, Debug, Hash, Eq, PartialEq, Clone)]
#[schemars(example = "Self::example")]
pub struct GroupStatus {
    pub number: u64,
    pub time: NaiveDateTime,
}

impl GroupStatus {
    pub fn new(number: u64, time: NaiveDateTime) -> GroupStatus {
        GroupStatus {number, time}
    }

    pub fn example() -> Self{
        Self{
            number: 2,
            time: Utc::now().naive_utc(),
        }
    }
}

impl Serialize for GroupStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
   {
        serializer.serialize_str(&format!("{}:{}", self.number, self.time.timestamp()))
    }
}

struct GroupStatusVisitor;

impl<'de> Visitor<'de> for GroupStatusVisitor {
    type Value = GroupStatus;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a colon-separated pair of u64 integers")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if let Some(nums) = Regex::new(r"(\d+):(\d+)").unwrap().captures_iter(s).next() {
            if let Ok(number) = u64::from_str(&nums[1]) {
                if let Ok(time) = i64::from_str(&nums[2]) {
                    Ok(GroupStatus::new(number, NaiveDateTime::from_timestamp(time,0)))
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

impl<'de> Deserialize<'de> for GroupStatus {
    fn deserialize<D>(deserializer: D) -> Result<GroupStatus, D::Error>
    where
        D: Deserializer<'de>,
    {
    deserializer.deserialize_string(GroupStatusVisitor)
    }
}

/// List of current statecoin amounts and the number of each
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct CoinValueInfo {
    pub values: HashMap<i64,NonZeroU64>,
}


impl Default for CoinValueInfo {
    fn default() -> Self {
        Self::new()
    }
}


impl CoinValueInfo {
    pub fn new() -> Self {
        Self { values: HashMap::<i64,NonZeroU64>::new() }
    }

    pub fn update(
        &mut self,
        amount: &i64,
        prev_amount: &i64,
    ) -> crate::Result<()> {
        self.decrement(prev_amount)?;
        self.increment(amount);
        Ok(())
    }

    pub fn increment(
        &mut self,
        amount: &i64,
    ) {
        let new_count = match self.values.get(amount){
            Some(c) => {
                let c_new = c.get()+1;
                c_new
            },
            None => {
                1
            }
        };
        //.map_or(1, |c| c+1);
        self.values.insert(*amount, unsafe {NonZeroU64::new_unchecked(new_count)}); 
    
    }

    pub fn decrement(
        &mut self,
        amount: &i64,
    ) -> crate::Result<()> {
        match self.values.get(amount){
            Some(c) => {
                match NonZeroU64::new(c.get()-1){
                    Some(c) => self.values.insert(*amount, c),
                    None => self.values.remove(amount)
                };
                Ok(())
            },
            None => {
                return Err(SharedLibError::Generic(format!("amount not found: {}", amount)));
            }
        }
    }

    pub fn clear(&mut self){
        *self = Self::new();
    }
}

// schema dummy struct for outpoint
/// Bitcoin UTXO Outpoint
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
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
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq)]
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
    /// The coin confirmation status
    pub confirmed: bool,
}

impl StateChainDataAPI {
    pub fn example() -> Self{
        Self{
            utxo: OutPoint::null(),
            amount: 1000000,
            chain: vec![State::example()],
            locktime: 712903,
            confirmed: true
        }
    }

    pub fn get_tip(&self) -> super::Result<State> {
        Ok(self
            .chain
            .last()
            .ok_or(SharedLibError::Generic(String::from("StateChain empty")))?
            .clone())
    }
}

// /info/statecoin return struct
/// Statechain tip data
/// This struct is returned containing the statecoin (statechain tip) of the specified statechain ID
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[schemars(example = "Self::example")]
pub struct StateCoinDataAPI {
    /// The statecoin UTXO OutPoint
    #[schemars(with = "OutPointDef")]
    pub utxo: OutPoint,
    /// The value of the statecoin (in satoshis)
    pub amount: u64,
    /// The tip of the statechain of owner proof keys and signatures
    pub statecoin: State,
    /// The current owner nLocktime
    pub locktime: u32,  // the curent owner nlocktime
    /// The coin confirmation status
    pub confirmed: bool,
}

impl StateCoinDataAPI {
    pub fn example() -> Self{
        Self{
            utxo: OutPoint::null(),
            amount: 1000000,
            statecoin: State::example(),
            locktime: 712903,
            confirmed: true
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

/// Struct containing proof key and authentication signature
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[schemars(example = "Self::example")]
pub struct RecoveryRequest {
    pub key: String,
    pub sig: String,
}

impl RecoveryRequest {
    pub fn example() -> Self{
        Self{
            key: "02a95498bdde2c8c4078f01840b3bc8f4ae5bb1a90b880a621f50ce221bce3ddbe".to_string(),
            sig: "30440220457cf52873ae5854859a7d48b39cb57eba880ea4011806e5058da7619f4c0fab02206303326f06bbebf7170b679ba787c856dec4b6462109bf66e1cb8dc087be7ebf01".to_string(),
        }
    }
}

/// Struct with recovery information for specified proof key
#[derive(Serialize, Deserialize, JsonSchema, Debug, PartialEq)]
#[schemars(example = "Self::example")]
pub struct WithdrawingData {
    //Withdrawal transaction
    pub tx_hex: String,
    //Receiving address
    #[schemars(with = "AddressDef")]
    pub rec_addr: Address
}

impl WithdrawingData {
    pub fn example() -> Self{
        Self{
            tx_hex: "02000000000101ca878085da49c33eb9816c10e4056424e5e062689ea547ea91bb3aa840a3c5fb0000000000ffffffff02307500000000000016001412cc36c9533290c02f0c78f992df6e6ddfe50c8c0064f50500000000160014658fd2dc72e58168f3656fb632d63be54f80fbe4024730440220457cf52873ae5854859a7d48b39cb57eba880ea4011806e5058da7619f4c0fab02206303326f06bbebf7170b679ba787c856dec4b6462109bf66e1cb8dc087be7ebf012102a95498bdde2c8c4078f01840b3bc8f4ae5bb1a90b880a621f50ce221bce3ddbe00000000".to_string(),
            rec_addr: Address::from_str("1DTFRJ2XFb4AGP1Tfk54iZK1q2pPfK4n3h").unwrap(),
        }
    }
}

/// Struct with recovery information for specified proof key
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[schemars(example = "Self::example")]
pub struct RecoveryDataMsg {
    #[schemars(with = "UuidDef")]
    pub shared_key_id: Uuid,
    #[schemars(with = "UuidDef")]
    pub statechain_id: Option<Uuid>,
    pub amount: Option<u64>,
    pub tx_hex: Option<String>,
    pub proof_key: String,
    pub shared_key_data: String,
    pub withdrawing: Option<WithdrawingData>
}

impl RecoveryDataMsg {
    pub fn example() -> Self{
        Self{
            shared_key_id: Uuid::new_v4(),
            statechain_id: Some(Uuid::new_v4()),
            amount: Some(0),
            tx_hex: Some("02000000000101ca878085da49c33eb9816c10e4056424e5e062689ea547ea91bb3aa840a3c5fb0000000000ffffffff02307500000000000016001412cc36c9533290c02f0c78f992df6e6ddfe50c8c0064f50500000000160014658fd2dc72e58168f3656fb632d63be54f80fbe4024730440220457cf52873ae5854859a7d48b39cb57eba880ea4011806e5058da7619f4c0fab02206303326f06bbebf7170b679ba787c856dec4b6462109bf66e1cb8dc087be7ebf012102a95498bdde2c8c4078f01840b3bc8f4ae5bb1a90b880a621f50ce221bce3ddbe00000000".to_string()),
            proof_key: "03b2483ab9bea9843bd9bfb941e8c86c1308e77aa95fccd0e63c2874c0e3ead3f5".to_string(),
            shared_key_data: "".to_string(),
            withdrawing: None
        }
    }
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
    pub shared_key_ids: Vec<Uuid>,
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
            shared_key_ids: Vec::<Uuid>::default(),
            protocol: Protocol::Transfer,

        tx_hex: transaction_serialise(&default_tx),
            input_addrs: Vec::<PK>::default(),
            input_amounts: Vec::<u64>::default(),
            proof_key: None,
        }
    }
}

impl PrepareSignTxMsg {
    pub fn example() -> Self{
        Self{
            shared_key_ids: vec![Uuid::new_v4()],
            protocol: Protocol::Deposit,
            tx_hex: "02000000011333183ddf384da83ed49296136c70d206ad2b19331bf25d390e69b222165e370000000000feffffff0200e1f5050000000017a914a860f76561c85551594c18eecceffaee8c4822d787F0C1A4350000000017a914d8b6fcc85a383261df05423ddf068a8987bf0287878c000000".to_string(),
            input_addrs: Vec::<PK>::default(),
            input_amounts: vec![100000],
            proof_key: Some("02a95498bdde2c8c4078f01840b3bc8f4ae5bb1a90b880a621f50ce221bce3ddbe".to_string()),
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

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct KeyGenMsg1 {
    #[schemars(with = "UuidDef")]
    pub shared_key_id: Uuid,
    pub protocol: Protocol,
    pub solution: Option<String>,
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

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[schemars(example = "Self::example")]
pub struct KeyGenReply1 {
    #[schemars(with = "UuidDef")]
    pub user_id: Uuid,
    #[schemars(with = "KeyGenFirstMsgDef")]
    pub msg: party_one::KeyGenFirstMsg,
}

impl KeyGenReply1 {
    pub fn example() -> Self {
        Self{
            user_id: Uuid::default(),
            msg: party_one::KeyGenFirstMsg{
                    pk_commitment: BigInt::one(),
                    zk_pok_commitment: BigInt::one(),
                }
        }
    }
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
    pub proof_key: String
}

/// Client -> SE
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct DepositMsg1POD {
    pub auth: String,
    pub proof_key: String,
    pub amount: u64
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
    #[schemars(with = "UuidDef")]
    pub batch_id: Option<Uuid>,
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
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq)]
pub struct TransferMsg5 {
    #[schemars(with = "UuidDef")]
    pub new_shared_key_id: Uuid,
    #[schemars(with = "GEDef")]
    pub s2_pub: GE,
}

/// State Entity -> Receiver
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct OwnerID {
    #[schemars(with = "UuidDef")]
    pub shared_key_id: Uuid,
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

/// Struct holds data when transfer is complete but not yet finalized
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema, PartialEq)]
#[schemars(example = "Self::example")]
pub struct TransferFinalizeData {
    #[schemars(with = "UuidDef")]
    pub new_shared_key_id: Uuid,
    #[schemars(with = "UuidDef")]
    pub statechain_id: Uuid,
    pub statechain_sig: StateChainSig,
    #[schemars(with = "FEDef")]
    pub s2: FE,
    pub new_tx_backup_hex: String,
    pub batch_data: Option<BatchData>,
}

impl TransferFinalizeData{
    pub fn example() -> Self{
        Self{
            new_shared_key_id: Uuid::new_v4(), 
            statechain_id: Uuid::new_v4(),
            statechain_sig: StateChainSig::example(),
            s2: FE::new_random(),
            new_tx_backup_hex: "02000000000101ca878085da49c33eb9816c10e4056424e5e062689ea547ea91bb3aa840a3c5fb0000000000ffffffff02307500000000000016001412cc36c9533290c02f0c78f992df6e6ddfe50c8c0064f50500000000160014658fd2dc72e58168f3656fb632d63be54f80fbe4024730440220457cf52873ae5854859a7d48b39cb57eba880ea4011806e5058da7619f4c0fab02206303326f06bbebf7170b679ba787c856dec4b6462109bf66e1cb8dc087be7ebf012102a95498bdde2c8c4078f01840b3bc8f4ae5bb1a90b880a621f50ce221bce3ddbe00000000".to_string(),
            batch_data: None
        }
    }
}


/// Data present if transfer is part of an atomic batch transfer
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq)]
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
    pub shared_key_ids: Vec::<Uuid>,
    pub statechain_sigs: Vec::<StateChainSig>,
}

/// Owner -> State Entity
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct WithdrawMsg2 {
    #[schemars(with = "UuidDef")]
    pub shared_key_ids: Vec::<Uuid>,
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

#[derive(Clone, Copy)]
pub enum LightningInvoiceStatus {
    Waiting,
    Expired,
    Paid
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

    #[test]
    fn test_coinvalueinfo() {
        let mut cvi = CoinValueInfo::new();
        assert!(cvi.update(&(1 as i64), &(1 as i64)).is_err());
        cvi.increment(&(1 as i64));
        cvi.increment(&(1 as i64));
        cvi.increment(&(1 as i64));
        cvi.increment(&(1 as i64));
        cvi.update(&(10 as i64), &(1 as i64)).unwrap();
        cvi.update(&(20 as i64), &(10 as i64)).unwrap();
        assert!(cvi.update(&(20 as i64), &(10 as i64)).is_err());
        cvi.update(&(3 as i64), &(1 as i64)).unwrap();
        cvi.increment(&(2 as i64));
        let mut test_map = HashMap::<i64, NonZeroU64>::new();
        test_map.insert(3 as i64, NonZeroU64::new(1).unwrap());
        test_map.insert(20 as i64, NonZeroU64::new(1).unwrap());
        test_map.insert(1 as i64, NonZeroU64::new(2).unwrap());
        test_map.insert(2 as i64, NonZeroU64::new(1).unwrap());
        assert_eq!(cvi.values, test_map); 
    }
}
