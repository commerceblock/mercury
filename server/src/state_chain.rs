use super::Result;
use crate::storage::db::{get_root,update_root, DB_SC_LOC};

use monotree::tree::verify_proof;
use monotree::{Monotree, Proof, Hash};
use monotree::database::RocksDB;
use monotree::hasher::{Hasher,Blake2b};

use rocksdb::DB;
use std::convert::TryInto;


/// insert new statechain entry into Sparse Merkle Tree and return proof
pub fn update_statechain_smt(db: &DB, funding_txid: &String, proof_key: &String) -> Result<()> {
    let key: &Hash = funding_txid[..32].as_bytes().try_into().unwrap();
    let entry: &Hash = proof_key[..32].as_bytes().try_into().unwrap();

    // get current root
    let root = get_root(db)?;

    // update smt
    let mut tree = Monotree::<RocksDB, Blake2b>::new(DB_SC_LOC);
    let new_root = tree.insert(root.as_ref(), key, entry)?;

    // update root in DB
    update_root(db, new_root.unwrap())?;

    Ok(())
}

// Method can run as a seperate proof generation daemon
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

    #[test]
    fn test_update_and_prove_sc_smt() {
        let db = rocksdb::DB::open_default(DB_LOC).unwrap();
        let funding_txid = String::from("c1562f7f15d6b8a51ea2e7035b9cdb8c6c0c41fecb62d459a3a6bf738ff0db0e");
        let proof_key = String::from("03b971d624567214a2e9a53995ee7d4858d6355eb4e3863d9ac540085c8b2d12b3");

        update_statechain_smt(&db, &funding_txid, &proof_key).unwrap();
        let root = get_root(&db).unwrap();

        let sc_smt_proof1 = gen_proof_smt(&root, &funding_txid).unwrap();
        assert!(verify_statechain_smt(&root, &proof_key, &sc_smt_proof1));

        // update with new proof key and try again
        let proof_key = String::from("13b971d624567214a2e9a53995ee7d4858d6355eb4e3863d9ac540085c8b2d12b3");
        update_statechain_smt(&db, &funding_txid, &proof_key).unwrap();
        let root = get_root(&db).unwrap();

        let sc_smt_proof2 = gen_proof_smt(&root, &funding_txid).unwrap();
        assert!(verify_statechain_smt(&root, &proof_key, &sc_smt_proof2));
    }
}
