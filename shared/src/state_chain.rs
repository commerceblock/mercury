//! State Chain
//!
//! State chain is the data structure used to track ownership of a UTXO co-owned by the State Entity.
//! An owner provides a key (called proof key) which gets appended to the state chain once their
//! ownership is confirmed.
//! Then, to pass ownership over to a new proof key the current owner signs a StateChainSig struct
//! which includes the new owners proof key. This new proof key is then appended to the state chain
//! as before. Thus ownership can be verified by ensuring the newest proof key has been signed for by the
//! previous proof key.
//! To withdraw, and hence bring an end to the State Chain, the StateChainSig struct contains the
//! withdrawal address.

use super::Result;
use crate::error::SharedLibError;
use crate::Verifiable;

use bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::{Message, PublicKey, Secp256k1, SecretKey, Signature},
};
use monotree::{
    hasher::{Blake3, Hasher},
    tree::verify_proof,
    {Monotree, Proof},
};

use chrono::{Duration, NaiveDateTime, Utc};
use std::panic;
use std::sync::{Arc, Mutex};
use std::{convert::TryInto, panic::AssertUnwindSafe, str::FromStr};
use uuid::Uuid;
use rocket_okapi::JsonSchema;
use std::convert::TryFrom;

/// A list of States in which each State signs for the next State.
/// On initialization the struct is always checked to have
/// non-zero chain length. The struct cannot be deserialized
/// but can be converted from a StateChainUnchecked which 
/// can be. The length check is enforced on conversion.
#[derive(Serialize, JsonSchema, Debug, PartialEq, Clone)]
#[schemars(example = "Self::example")]
pub struct StateChain {
    /// chain of transitory key history
    chain: Vec<State>,
}

/// A struct with the same struct as StateChain that can be
/// deserialized and has public member variables
#[derive(Deserialize, Debug, PartialEq, Clone)]
pub struct StateChainUnchecked {
    /// chain of transitory key history
    chain: Vec<State>,
}

impl StateChainUnchecked {
    pub fn get_chain(self) -> Vec<State> {
        self.chain
    }
}

impl TryFrom<StateChainUnchecked> for StateChain {
    type Error = SharedLibError;
    fn try_from(chain: StateChainUnchecked) -> Result<Self> {
        let result = Self{ chain: chain.get_chain() };
        StateChain::check_length(&result)?;
        Ok(result)
    }
}

impl TryFrom<&Vec<State>> for StateChain {
    type Error = SharedLibError;
    fn try_from(chain: &Vec<State>) -> Result<Self> {
        let result = Self{ chain: chain.to_owned() };
        StateChain::check_length(&result)?;
        Ok(result)
    }
}

impl TryFrom<Vec<State>> for StateChain {
    type Error = SharedLibError;
    fn try_from(chain: Vec<State>) -> Result<Self> {
        let result = Self{ chain: chain.to_owned() };
        StateChain::check_length(&result)?;
        Ok(result)
    }
}

impl StateChain {
    pub fn new(data: String) -> Self {
        StateChain {
            chain: vec![State {
                data,
                next_state: None,
            }],
        }
    }

    pub fn get_chain(&self) -> &Vec<State> {
        &self.chain
    }

    pub fn get_tip(&self) -> &State {
        self.chain.last().expect("expect StateChain to not be empty")
    }

    pub fn get_mut_tip(&mut self) -> &mut State {
        self.chain.last_mut().expect("expect StateChain to not be empty")
    }

    pub fn get_first(&self) -> &State {
        self.chain.first().expect("expect StateChain to not be empty")
    }

    pub fn add(&mut self, statechain_sig: &StateChainSig) -> Result<()> {
        // verify previous state has signature and signs for new proof_key
        let prev_proof_key: &String = &self.get_tip().data;

        // println!("---");
        // for c in &self.chain {
        //     println!("--- [state_chain] statechain vector: {:?}", c);
        // }
        // println!("---");      

        // println!("--- [state_chain] statechain tip: {:?}", &self.get_tip()); 

        // println!("--- [state_chain] prev_proof_key used to verify statechain_sig: {}", prev_proof_key);
        // println!("--- [state_chain] statechain_sig.sig: {:?}", statechain_sig.sig);
        let y = statechain_sig.verify(prev_proof_key);

        match y {
            Ok(_) => { println!("statechain_sig.verify OK"); },
            Err(e) => { println!("ERROR statechain_sig.verify: {:?}", e); return Err(e); },
        }

        // add sig to current tip
        self.get_mut_tip().next_state = Some(statechain_sig.clone());

        // add new tip to chain
        Ok(self.chain.push(State {
            data: statechain_sig.data.clone(),
            next_state: None,
        }))
    }

    pub fn example() -> Self{
        Self{
            chain: vec![State::example()],
        }
    }

    fn check_length(chain: &Self) -> Result<()> {
        match chain.get_chain().is_empty(){
            true => Err(SharedLibError::FormatError(
                "StateChain cannot be of zero length".to_string())),
            false => Ok(())
        }
    }

}

pub fn get_time_now() -> NaiveDateTime {
    Utc::now().naive_utc()
}

// Get NaiveDateTime for punishment set from now
pub fn get_locked_until(punishment_duration: i64) -> Result<NaiveDateTime> {
    let current_time = get_time_now();
    match current_time.checked_add_signed(Duration::seconds(punishment_duration)) {
        None => {
            return Err(SharedLibError::Generic(format!(
                "State Chain locked duration overflow."
            )))
        }
        Some(v) => return Ok(v),
    }
}

/// Check if state chain is available for transfer/withdrawal
pub fn is_locked(locked_until: NaiveDateTime) -> Result<()> {
    let current_time = Utc::now().naive_utc().timestamp();
    let time_left = locked_until.timestamp() - current_time;

    match time_left > 0 {
        true => {
            return Err(SharedLibError::Generic(format!(
                "State Chain locked for {} minutes.",
                (time_left / 60) + 1
            )))
        }
        false => return Ok(()),
    }
}

/// State update object
/// State to change statecoin ownership to new owner
#[derive(Serialize, Deserialize, JsonSchema, Debug, PartialEq, Clone)]
#[schemars(example = "Self::example")]
pub struct State {
    /// The new owner proof public key (if transfer) or address (if withdrawal)
    pub data: String,                      // proof key or address
    /// Current owner signature representing passing of ownership
    pub next_state: Option<StateChainSig>, // signature representing passing of ownership
}

impl State {
    pub fn example() -> Self{
        Self{
            data: "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd".to_string(),
            next_state: Some(StateChainSig::example()),
        }
    }
}

/// State change signature object
/// Data necessary to create ownership transfer signatures
#[derive(Serialize, Deserialize, JsonSchema, Debug, PartialEq, Clone, Default, Hash, Eq)]
#[schemars(example = "Self::example")]
pub struct StateChainSig {
    /// Purpose: "TRANSFER", "TRANSFER-BATCH" or "WITHDRAW"
    pub purpose: String, // "TRANSFER", "TRANSFER-BATCH" or "WITHDRAW"
    /// The new owner proof public key (if transfer) or address (if withdrawal)
    pub data: String,    // proof key, state chain id or address
    /// Current owner signature (DER encoded).
    pub sig: String,
}

impl StateChainSig {
    pub fn example() -> Self{
        Self{
            purpose: "TRANSFER".to_string(),
            data: "037f8d5dfb3c8f99b1641d200e808dd0b6c52f53b04e972c2e61ab901133902ebd".to_string(),
            sig: "3045022100abe02f0d1918aca36b634eb1af8a4e0714f3f699fb425de65cc661e538da3f2002200a538a22df665a95adb739ff6bb592b152dba5613602c453c58adf70858f05f6".to_string(),
        }
    }
    // add code here
}

impl StateChainSig {
    /// Create message to be signed
    fn to_message(purpose: &String, data: &String) -> Result<Message> {
        let mut str = purpose.clone();
        str.push_str(&data);
        let hash = sha256::Hash::hash(&str.as_bytes());
        Ok(Message::from_slice(&hash)?)
    }

    /// Generate signature for change of state chain ownership
    pub fn new(proof_key_priv: &SecretKey, purpose: &String, data: &String) -> Result<Self> {
        let secp = Secp256k1::new();
        let message = StateChainSig::to_message(purpose, data)?;
        let sig = secp.sign(&message, &proof_key_priv);
        Ok(StateChainSig {
            purpose: purpose.clone(),
            data: data.clone(),
            sig: sig.to_string(),
        })
    }

    fn purpose_transfer_batch(batch_id: &Uuid) -> String {
        format!("TRANSFER_BATCH:{}", batch_id)
    }

    /// Generate signature to request participation in a batch transfer
    pub fn new_transfer_batch_sig(
        proof_key_priv: &SecretKey,
        batch_id: &Uuid,
        statechain_id: &Uuid,
    ) -> Result<Self> {
        let purpose = &Self::purpose_transfer_batch(batch_id);
        let data = &statechain_id.to_string();
        Self::new(proof_key_priv, purpose, data)
    }

    /// Verify self's signature for transfer or withdraw
    pub fn verify(&self, pk: &String) -> Result<()> {
        let message = StateChainSig::to_message(&self.purpose, &self.data)?;
        Signature::from_str(&self.sig)?
            .verify(&PublicKey::from_str(&pk)?, &message)
    }

    pub fn is_transfer_batch(&self, batch_id: Option<&Uuid>) -> bool {
        match batch_id {
            None => self.purpose.starts_with("TRANSFER_BATCH"),
            Some(id) => self.purpose == Self::purpose_transfer_batch(id),
        }
    }
}

/// Insert new statechain entry into Sparse Merkle Tree and return proof
pub fn update_statechain_smt<D: monotree::database::Database>(
    tree: Arc<Mutex<Monotree<D, Blake3>>>,
    root: &Option<monotree::Hash>,
    funding_txid: &String,
    entry: &String,
) -> Result<Option<monotree::Hash>> {
    let key: &monotree::Hash = match funding_txid[..32].as_bytes().try_into() {
        Ok(k) => k,
        Err(e) => return Err(SharedLibError::FormatError(e.to_string())),
    };
    let entry: &monotree::Hash = match entry[..32].as_bytes().try_into() {
        Ok(entry) => entry,
        Err(e) => return Err(SharedLibError::FormatError(e.to_string())),
    };

    // update smt
    let mut new_root: Option<[u8; 32]> = None;
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let mut tree = tree.lock().unwrap();
        new_root = tree.insert(root.as_ref(), key, entry).unwrap();
    }));

    if let Err(_) = result {
        return Err(SharedLibError::Generic(String::from(
            "SMT insert failure. Probably caused by Root provided not being correct.",
        )));
    }

    Ok(new_root)
}

// Method can run as a seperate proof generation daemon. Must check root exists before calling.
pub fn gen_proof_smt<D: monotree::database::Database>(
    tree: Arc<Mutex<Monotree<D, Blake3>>>,
    root: &Option<monotree::Hash>,
    funding_txid: &String,
) -> Result<Option<Proof>> {
    let key: &monotree::Hash = funding_txid[..32].as_bytes().try_into().unwrap();

    // generate inclusion proof
    let mut proof: Option<Vec<(bool, Vec<u8>)>> = None;
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let mut tree = tree.lock().unwrap();
        proof = tree.get_merkle_proof(root.as_ref(), key).unwrap();
    }));

    if let Err(_) = result {
        return Err(SharedLibError::Generic(String::from(
            "Get merkle proof failure. Probably caused by Root provided not being correct.",
        )));
    }

    Ok(proof)
}

pub fn verify_statechain_smt(
    root: &Option<monotree::Hash>,
    proof_key: &String,
    proof: &Option<Proof>,
) -> bool {
    let entry: &monotree::Hash = proof_key[..32].as_bytes().try_into().unwrap();
    let hasher = Blake3::new();
    verify_proof(&hasher, root.as_ref(), &entry, proof.as_ref())
}

#[cfg(test)]
mod tests {

    use super::*;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use monotree::database::MemoryDB;
    static STATE_1: &str = "{\"data\":\"026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e\",\"next_state\":null}";
    static STATE_2: &str = "{\"data\":\"126ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e\",\"next_state\":null}";
    static STATE_CHAIN_1: &str = "{\"chain\":[{\"data\":\"026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e\",\"next_state\":null}]}";
    static STATE_CHAIN_2: &str = "{\"chain\":[{\"data\":\"026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e\",\"next_state\":null},{\"data\":\"126ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e\",\"next_state\":null}]}";
    static EMPTY_STATE_CHAIN_UNCHECKED: &str = "{\"chain\":[]}";

    #[test]
    fn test_add_to_state_chain() {
        let secp = Secp256k1::new();
        let proof_key1_priv = SecretKey::from_slice(&[1; 32]).unwrap();
        let proof_key1_pub = PublicKey::from_secret_key(&secp, &proof_key1_priv);

        let mut state_chain = StateChain::new(proof_key1_pub.to_string());

        assert_eq!(state_chain.chain.len(), 1);

        // StateChainSig.verify called in function below
        let new_state_sig = StateChainSig::new(
            &proof_key1_priv,
            &String::from("TRANSFER"),
            &String::from("03b971d624567214a2e9a53995ee7d4858d6355eb4e3863d9ac540085c8b2d12b3"),
        )
        .unwrap();

        // add to state chain
        let _ = state_chain.add(&new_state_sig);
        assert_eq!(state_chain.chain.len(), 2);

        // try add again (signature no longer valid for proof key "03b971d624567214a2e9a53995ee7d4858d6355eb4e3863d9ac540085c8b2d12b3")
        let fail = state_chain.add(&new_state_sig);
        assert!(fail.is_err());
    }

    #[test]
    fn test_convert_to_state_chain() {
        let sc1 = StateChain::example();
        let sc2 = sc1.get_chain().try_into().unwrap();
        assert!(&sc1 == &sc2, "expect converted from reference and original StateChain to be equal");

        let sc3 = sc1.get_chain().to_owned().try_into().unwrap();
        assert!(&sc1 == &sc3, "expect converted and original StateChain to be equal");

        let empty_vec: Vec<State> = vec![];
        assert!(empty_vec.is_empty());
        let sc_fail: Result<StateChain> = empty_vec.try_into();
        assert!(sc_fail.is_err());
    }

    #[test]
    fn test_state_chain_unchecked() {
        let s1: State = serde_json::from_str(STATE_1).expect("failed to deserialise State");
        let s2: State = serde_json::from_str(STATE_2).expect("failed to deserialise State");

        let sc_empty: Result<StateChain> = serde_json::from_str::<StateChainUnchecked>(EMPTY_STATE_CHAIN_UNCHECKED).
            expect("failed to deserialise StateChainUnchecked").try_into();
        assert!(sc_empty.is_err());

        let sc1: StateChain = serde_json::from_str::<StateChainUnchecked>(STATE_CHAIN_1)
            .expect("failed to deserialise StateChainUnchecked")
            .try_into()
            .expect("failed to convert");

        let sc2: StateChain = serde_json::from_str::<StateChainUnchecked>(STATE_CHAIN_2)
            .expect("failed to deserialise StateChainUnchecked")
            .try_into()
            .expect("failed to convert");

        assert_eq!(&s1, sc2.get_first(), "StateChain get_first incorrect");
        assert_eq!(&s2, sc2.get_tip(), "StateChain get_tip incorrect");

        assert!(serde_json::to_string(&sc1).expect("failed to serialize") == STATE_CHAIN_1.to_string());
        assert!(serde_json::to_string(&sc2).expect("failed to serialize") == STATE_CHAIN_2.to_string());
    }

    #[test]
    fn test_state_chain_locked() {
        let locked_until = Utc::now().naive_utc() - Duration::seconds(5);
        assert!(is_locked(locked_until).is_ok());
        let locked_until = Utc::now().naive_utc() + Duration::seconds(5);
        assert!(is_locked(locked_until).is_err());
    }

    #[test]
    fn test_update_and_prove_sc_smt() {
        let funding_txid =
            String::from("c1562f7f15d6b8a51ea2e7035b9cdb8c6c0c41fecb62d459a3a6bf738ff0db0e");
        let proof_key =
            String::from("03b971d624567214a2e9a53995ee7d4858d6355eb4e3863d9ac540085c8b2d12b3");

        let tree = Arc::new(Mutex::new(Monotree::<MemoryDB, Blake3>::new("")));
        let root: Option<monotree::Hash> = None;

        let root = update_statechain_smt::<monotree::database::MemoryDB>(
            tree.clone(),
            &root,
            &funding_txid,
            &proof_key,
        )
        .unwrap();

        let sc_smt_proof1 =
            gen_proof_smt::<monotree::database::MemoryDB>(tree.clone(), &root, &funding_txid)
                .unwrap();

        assert!(verify_statechain_smt(&root, &proof_key, &sc_smt_proof1));

        // update with new proof key and try again
        let proof_key =
            String::from("13b971d624567214a2e9a53995ee7d4858d6355eb4e3863d9ac540085c8b2d12b3");
        let root = update_statechain_smt::<monotree::database::MemoryDB>(
            tree.clone(),
            &root,
            &funding_txid,
            &proof_key,
        )
        .unwrap();

        let sc_smt_proof2 =
            gen_proof_smt::<monotree::database::MemoryDB>(tree.clone(), &root, &funding_txid)
                .unwrap();
        assert!(verify_statechain_smt(&root, &proof_key, &sc_smt_proof2));
    }
}
