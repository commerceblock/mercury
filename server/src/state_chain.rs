use super::Result;
use crate::storage::db::{DB,get_root,update_root};

use monotree::tree::verify_proof;
use monotree::{Monotree, Proof};
use monotree::database::RocksDB;
use monotree::hasher::{Hasher,Blake2b};

use std::convert::TryInto;


/// insert new statechain entry into Sparse Merkle Tree and return proof
pub fn update_statechain_smt(db: &DB, funding_txid: &String, proof_key: &String) -> Result<Option<Proof>> {
    let key: &[u8; 32] = funding_txid[..32].as_bytes().try_into().unwrap();
    let entry: &[u8; 32] = proof_key[..32].as_bytes().try_into().unwrap();

    // get current root
    let root = get_root(db)?;

    // update smt
    let mut tree = Monotree::<RocksDB, Blake2b>::new("./db-statechain");
    let new_root = tree.insert(root.as_ref(), key, entry)?;

    // update root in DB
    update_root(db, new_root.unwrap())?;

    // generate inclusion proof
    let proof = tree.get_merkle_proof(new_root.as_ref(), key)?;

    Ok(proof)

}

pub fn verify_statechain_smt(root: &Option<[u8;32]>, entry: &[u8;32], proof: &Option<Proof>) -> bool {
    let hasher = Blake2b::new();
    verify_proof(&hasher, root.as_ref(), &entry, proof.as_ref())
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_update_sc_smt() {
        let db = DB::Local(rocksdb::DB::open_default("/tmp/db-statechain2").unwrap());
        let funding_txid = String::from("c1562f7f15d6b8a51ea2e7035b9cdb8c6c0c41fecb62d459a3a6bf738ff0db0e");
        let proof_key = String::from("03b971d624567214a2e9a53995ee7d4858d6355eb4e3863d9ac540085c8b2d12b3");

        let sc_smt_proof1 = update_statechain_smt(&db, &funding_txid, &proof_key).unwrap();

        let proof_key_arr: &[u8; 32] = proof_key[..32].as_bytes().try_into().unwrap();
        let root = get_root(&db).unwrap();
        assert!(verify_statechain_smt(&root, proof_key_arr, &sc_smt_proof1));

        // update and try again
        let proof_key = String::from("13b971d624567214a2e9a53995ee7d4858d6355eb4e3863d9ac540085c8b2d12b3");
        let sc_smt_proof2 = update_statechain_smt(&db, &funding_txid, &proof_key).unwrap();

        let root = get_root(&db).unwrap();
        let proof_key_arr: &[u8; 32] = proof_key[..32].as_bytes().try_into().unwrap();
        assert!(verify_statechain_smt(&root, proof_key_arr, &sc_smt_proof2));
    }

    #[test]
    fn test_overwrite() {
        let mut tree = Monotree::<RocksDB, Blake2b>::new("/tmp/monotree");
        let key = [245, 66, 111, 189, 149, 147, 160, 221, 29, 46, 132, 7, 216, 95, 123, 251, 227, 168, 221, 14, 61, 128, 234, 236, 19, 51, 58, 65, 230, 20, 246, 139];
        let root = None;

        let leaf = [137, 112, 186, 173, 219, 48, 93, 219, 240, 176, 164, 135, 67, 82, 128, 204, 247, 60, 157, 64, 229, 30, 205, 137, 33, 97, 179, 185, 199, 17, 57, 153];
        let root1 = tree.insert(root.as_ref(), &key, &leaf).unwrap();
        println!("root: {:?}",root);

        let found = tree.get(root.as_ref(), &key).unwrap();
        println!("found: {:?}",found);

        let leaf = [150, 112, 186, 173, 219, 48, 93, 219, 240, 176, 164, 135, 67, 82, 128, 204, 247, 60, 157, 64, 229, 30, 205, 137, 33, 97, 179, 185, 199, 17, 57, 153];
        let root2 = tree.insert(root.as_ref(), &key, &leaf).unwrap();
        println!("root2: {:?}",root2);

        let found1 = tree.get(root1.as_ref(), &key).unwrap();
        println!("found1: {:?}",found1);

        let found2 = tree.get(root2.as_ref(), &key).unwrap();
        println!("found2: {:?}",found2);
    }
}
