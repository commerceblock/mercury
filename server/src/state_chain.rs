//! State Chain
//!
//! State chain is the data structure used to track ownership of a UTXO co-owned by the State Entity.
//! An owner provides a key (we call proof key) which gets appended to the state chain once their
//! ownership is confirmed.
//! Then, to pass ownership over to a new proof key the current owner signs a StateChainSig struct
//! which includes the new owners proof key. This new proof key is then appended to the state chain
//! as before. Thus ownership can be verified by ensuring the newest proof key has been signed for by the
//! previous proof key.
//! To withdraw, and hence bring an end to the State Chain, the StateChainSig struct contains the
//! withdrawal address.


use super::Result;
use crate::{error::SEError, storage::db::{get_current_root,update_root, DB_SC_LOC}};
use shared_lib::Root;
use shared_lib::state_chain::{State, StateChainSig};

use bitcoin::Transaction;
use monotree::tree::verify_proof;
use monotree::{Hash, Monotree, Proof};
use monotree::database::RocksDB;
use monotree::hasher::{Hasher,Blake2b};

use rocksdb::DB;
use uuid::Uuid;
use std::convert::TryInto;

/// A list of States in which each State signs for the next State.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct StateChain {
    pub id: String,
    /// chain of transitory key history (owners  Proof keys)
    pub chain: Vec<State>,
    /// current back-up transaction
    pub backup_tx: Option<Transaction>
}

impl StateChain {
    pub fn new(proof_key: &String) -> Self {
        StateChain {
            id: Uuid::new_v4().to_string(),
            chain: vec!( State {
                proof_key: proof_key.clone(),
                next_state: None
            }),
            backup_tx: None
        }
    }

    pub fn add(&mut self, state_chain_sig: StateChainSig) -> Result<()> {
        let prev_proof_key = self.chain.last()
            .ok_or(SEError::Generic(String::from("StateChain empty")))?
            .proof_key.clone();
        // verify previous state has signature and signs for new proof_key
        state_chain_sig.verify(&prev_proof_key)?;

        // add to chain
        Ok(self.chain.push(State {
            proof_key: state_chain_sig.data.clone(),
            next_state: None
        }))
    }
}




/// insert new statechain entry into Sparse Merkle Tree and return proof
pub fn update_statechain_smt(db: &DB, funding_txid: &String, proof_key: &String) -> Result<()> {
    let key: &Hash = funding_txid[..32].as_bytes().try_into().unwrap();
    let entry: &Hash = proof_key[..32].as_bytes().try_into().unwrap();

    // get current root
    let root = get_current_root::<Root>(&db)?;

    // update smt
    let mut tree = Monotree::<RocksDB, Blake2b>::new(DB_SC_LOC);
    let new_root = tree.insert(root.value.as_ref(), key, entry)?;

    // update root in DB
    update_root(db, new_root.unwrap())?;

    Ok(())
}

// Method can run as a seperate proof generation daemon. Must check root exists before calling.
pub fn gen_proof_smt(root: &Option<Hash>, funding_txid: &String) -> Result<Option<Proof>> {
    let key: &Hash = funding_txid[..32].as_bytes().try_into().unwrap();
    let mut tree = Monotree::<RocksDB, Blake2b>::new(DB_SC_LOC);

    // generate inclusion proof
    let proof = tree.get_merkle_proof(root.as_ref(), key)?;
    Ok(proof)
}

pub fn verify_statechain_smt(root: &Option<Hash>, proof_key: &String, proof: &Option<Proof>) -> bool {
    let entry: &Hash = proof_key[..32].as_bytes().try_into().unwrap();
    let hasher = Blake2b::new();
    verify_proof(&hasher, root.as_ref(), &entry, proof.as_ref())
}


#[cfg(test)]
mod tests {

    use super::*;
    use crate::storage::db::DB_LOC;
    use shared_lib::state_chain::StateChainSig;

    use bitcoin::secp256k1::{SecretKey, Secp256k1, PublicKey};


    #[test]
    fn test_add_to_state_chain() {
        let secp = Secp256k1::new();
        let proof_key1_priv = SecretKey::from_slice(&[1;32]).unwrap();
        let proof_key1_pub = PublicKey::from_secret_key(&secp, &proof_key1_priv);

        let mut state_chain = StateChain::new(&proof_key1_pub.to_string());
        assert_eq!(state_chain.chain.len(),1);
        // StateChainSig.verify called in function below
        let new_state_sig = StateChainSig::new(
            &proof_key1_priv,
            &String::from("TRANSFER"),
            &String::from("03b971d624567214a2e9a53995ee7d4858d6355eb4e3863d9ac540085c8b2d12b3"),
        ).unwrap();

        //add to state chain
        let _ = state_chain.add(new_state_sig.clone());
        assert_eq!(state_chain.chain.len(),2);

        // try add again (signature no longer valid for proof key "03b971d624567214a2e9a53995ee7d4858d6355eb4e3863d9ac540085c8b2d12b3")
        let fail = state_chain.add(new_state_sig);
        assert!(fail.is_err());
    }

    #[test]
    fn test_update_and_prove_sc_smt() {
        let db = rocksdb::DB::open_default(DB_LOC).unwrap();
        let funding_txid = String::from("c1562f7f15d6b8a51ea2e7035b9cdb8c6c0c41fecb62d459a3a6bf738ff0db0e");
        let proof_key = String::from("03b971d624567214a2e9a53995ee7d4858d6355eb4e3863d9ac540085c8b2d12b3");

        update_statechain_smt(&db, &funding_txid, &proof_key).unwrap();
        let root = get_current_root::<Root>(&db).unwrap();

        let sc_smt_proof1 = gen_proof_smt(&root.value, &funding_txid).unwrap();

        assert!(verify_statechain_smt(&root.value, &proof_key, &sc_smt_proof1));

        // update with new proof key and try again
        let proof_key = String::from("13b971d624567214a2e9a53995ee7d4858d6355eb4e3863d9ac540085c8b2d12b3");
        update_statechain_smt(&db, &funding_txid, &proof_key).unwrap();
        let root = get_current_root::<Root>(&db).unwrap();

        let sc_smt_proof2 = gen_proof_smt(&root.value, &funding_txid).unwrap();
        assert!(verify_statechain_smt(&root.value, &proof_key, &sc_smt_proof2));
    }
}
