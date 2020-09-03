//! Postgres implementation for Monotree

use crate::PGDatabase;
use crate::Database;
use crate::storage::db::Table;
use monotree::database::{MemCache, Database as MonotreeDatabase, MemoryDB};
use monotree::Errors;
use std::collections::HashMap;

pub type Result<T> = std::result::Result<T, Errors>;

// Postgres Monotree implementation
impl MonotreeDatabase for PGDatabase {
    // Dummy function not used in Postgres. Connections are aquired within each monotree call due to
    // monotree::Database::new() contraints.
    fn new(_dbname: &str) -> Self {
        // Return dummy
        PGDatabase {
            pool: None,
            smt_cache: MemCache::new(),
            smt_batch_on: false,
            smt_batch: HashMap::new()
        }
    }
    /// Monotree get
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if self.smt_cache.contains(key) {
            return self.smt_cache.get(key);
        }

        let dbr = match self.database_r() {
            Ok(v) => v,
            Err(e) => return Err(Errors::new(&e.to_string()))
        };

        let stmt = match dbr.prepare(&format!(
            "SELECT value FROM {} WHERE key = ('{}')"
            ,Table::Smt.to_string(), serde_json::to_string(&key).unwrap())) {
                Ok(v) => v,
                Err(e) => return Err(Errors::new(&e.to_string()))
            };

        let rows = match stmt.query(&[]){
            Ok(v) => v,
            Err(e) => return Err(Errors::new(&e.to_string()))
        };

        if rows.is_empty() {
            return Err(Errors::new("No data for key"));
        };
        let row = rows.get(0);

        match row.get_opt::<usize, String>(0) {
            None => return Err(Errors::new("No data for key")),
            Some(data) => match data {
                Ok(v) => return Ok(Self::deser::<Option<Vec<u8>>>(v).unwrap()),
                Err(_) => return Err(Errors::new("No data for key")),
            },
        };
    }

    /// Monotree put
    fn put(&mut self, key: &[u8], value: Vec<u8>) -> Result<()> {
        self.smt_cache.put(key, value.to_owned())?;
        if self.smt_batch_on {
            let key_vec: Vec<u8> = key.iter().cloned().collect();
            self.smt_batch.insert(key_vec, value);
        } else {
            let dbw = match self.database_w() {
                Ok(v) => v,
                Err(e) => return Err(Errors::new(&e.to_string()))
            };

            let stmt = match dbw.prepare(&format!(
                "INSERT INTO {} (key, value)
                VALUES ('{}','{}')
                ON CONFLICT (key) DO UPDATE
                SET value = EXCLUDED.value;",
                Table::Smt.to_string(),
                serde_json::to_string(&key).unwrap(),
                serde_json::to_string(&value).unwrap())) {
                    Ok(v) => v,
                    Err(e) => return Err(Errors::new(&e.to_string()))
                };
            match stmt.execute(&[]) {
                Ok(v) => v,
                Err(e) => return Err(Errors::new(&e.to_string()))
            };
        };
        return Ok(());
    }
    /// Monotree delete
    fn delete(&mut self, key: &[u8]) -> Result<()> {
        self.smt_cache.delete(key)?;
        if self.smt_batch_on {
            self.smt_batch.remove(key);
        } else {
            let dbw = match self.database_w() {
                Ok(v) => v,
                Err(e) => return Err(Errors::new(&e.to_string()))
            };
            let stmt = match dbw.prepare(&format!(
                "DELETE FROM {} WHERE key = ('{}');",
                Table::Smt.to_string(), serde_json::to_string(&key).unwrap())){
                    Ok(v) => v,
                    Err(e) => return Err(Errors::new(&e.to_string()))
                };
            match stmt.execute(&[]) {
                Ok(v) => v,
                Err(e) => return Err(Errors::new(&e.to_string()))
            };
        }
        return Ok(());
    }
    /// Monotree init_batch
    fn init_batch(&mut self) -> Result<()> {
        self.smt_batch = HashMap::new();
        self.smt_cache.clear();
        self.smt_batch_on = true;
        Ok(())
    }
    /// Monotree finish_batch
    fn finish_batch(&mut self) -> Result<()> {
        self.smt_batch_on = false;
        if !self.smt_batch.is_empty() {
            let dbw = match self.database_w() {
                Ok(v) => v,
                Err(e) => return Err(Errors::new(&e.to_string()))
            };
            let mut stmt_str = format!("INSERT INTO {} (key, value) VALUES", Table::Smt.to_string());
            for (key, value) in &self.smt_batch {
                stmt_str.push_str(&format!(" ('{}','{}'),",
                serde_json::to_string(&key).unwrap(),
                serde_json::to_string(&value).unwrap()));
            }
            stmt_str.truncate(stmt_str.len() - 1);
            stmt_str.push_str(" ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;");

            let stmt = match dbw.prepare(&stmt_str) {
                Ok(v) => v,
                Err(e) => return Err(Errors::new(&e.to_string()))
            };
            match stmt.execute(&[]) {
                Ok(v) => v,
                Err(e) => return Err(Errors::new(&e.to_string()))
            };
        }
        Ok(())
    }
}

#[cfg(test)]
#[cfg(not(feature="mockdb"))] // Run tests only if mockdb feature disabled
pub mod tests {
    use super::*;
    use crate::config::Config;
    use monotree::hasher::{Hasher,Blake3};
    use monotree::Monotree;

    fn get_monotree_postgres_tree() -> Monotree<PGDatabase, Blake3> {
        let config_rs = Config::load().unwrap();
        let mut db = PGDatabase::get_new();
        db.set_connection_from_config(&config_rs).unwrap();
        db.database_w().unwrap().execute(&format!("TRUNCATE {};",Table::Smt.to_string()),&[]).unwrap();
        Monotree {
            db,
            hasher: Blake3::new()
        }
    }

    #[test]
    fn test_monotree_postgres_tree() {
        let mut tree = get_monotree_postgres_tree();

        let root = None;
        let key: &monotree::Hash = &[1; 32];
        let leaf: &monotree::Hash = &[2; 32];

        let root = tree.insert(root.as_ref(), key, leaf).unwrap();

        let res = tree.get(root.as_ref(), key);
        assert_eq!(leaf, &res.unwrap().unwrap());

        let root = tree.remove(root.as_ref(), key).unwrap();
        // Root returned to None
        assert_eq!(None, root);

        let res = tree.get(root.as_ref(), key);
        // Nothing returned from get
        assert_eq!(None, res.unwrap());
    }

    #[test]
    fn test_batch_monotree_postgres_tree() {
        let mut tree = get_monotree_postgres_tree();

        let root = None;
        let keys: &[monotree::Hash] = &[[1; 32], [2; 32], [3; 32]];
        let leaves: &[monotree::Hash] = &[[4; 32], [5; 32], [6; 32]];

        let root = tree.inserts(root.as_ref(), keys, leaves).unwrap();
        assert!(root.is_some());

        let res = tree.gets(root.as_ref(), keys).unwrap();
        assert!(res.contains(&Some(leaves[0])));
        assert!(res.contains(&Some(leaves[1])));
        assert!(res.contains(&Some(leaves[2])));

        let root = tree.removes(root.as_ref(), keys).unwrap();
        // Root returned to None
        assert_eq!(None, root);

        let res = tree.get(root.as_ref(), &keys[0]);
        assert_eq!(None, res.unwrap());
        let res = tree.get(root.as_ref(), &keys[1]);
        assert_eq!(None, res.unwrap());
        let res = tree.get(root.as_ref(), &keys[2]);
        assert_eq!(None, res.unwrap());
    }
}

// Dummy implementation. Unused.
use crate::MockDatabase;
impl monotree::database::Database for MockDatabase {
    fn new(_dbname: &str) -> Self {
        MockDatabase::new()
    }

    fn get(&mut self, _key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    fn put(&mut self, _key: &[u8], _value: Vec<u8>) -> Result<()> {
        Ok(())
    }

    fn delete(&mut self, _key: &[u8]) -> Result<()> {
        Ok(())
    }

    fn init_batch(&mut self) -> Result<()> {
        Ok(())
    }

    fn finish_batch(&mut self) -> Result<()> {
        Ok(())
    }
}
// Dummy implementation. Unused.
use rocket_contrib;
impl Database for MemoryDB {
    fn get_new() -> Self {
        unimplemented!()
    }
    fn set_connection_from_config(&mut self, _config: &crate::config::Config) -> crate::Result<()> {
        Ok(())
    }
    fn set_connection(&mut self, _url: &String) -> crate::Result<()> {
        unimplemented!()
    }
    fn from_pool(_pool: rocket_contrib::databases::r2d2::Pool<rocket_contrib::databases::r2d2_postgres::PostgresConnectionManager>) -> Self {
        unimplemented!()
    }
    fn get_user_auth(&self, _user_id: uuid::Uuid) -> crate::Result<uuid::Uuid> {
        unimplemented!()
    }
    fn has_withdraw_sc_sig(&self, _user_id: uuid::Uuid) -> crate::Result<()> {
        unimplemented!()
    }
    fn update_withdraw_sc_sig(&self, _user_id: &uuid::Uuid, _sig: shared_lib::state_chain::StateChainSig) -> crate::Result<()> {
        unimplemented!()
    }
    fn update_withdraw_tx_sighash(
        &self,
        _user_id: &uuid::Uuid,
        _sig_hash: crate::Hash,
        _tx: bitcoin::Transaction,
    ) -> crate::Result<()> {
        unimplemented!()
    }
    fn update_sighash(&self, _user_id: &uuid::Uuid, _sig_hash: crate::Hash) -> crate::Result<()> {
        unimplemented!()
    }
    fn update_user_backup_tx(&self,_user_id: &uuid::Uuid, _tx: bitcoin::Transaction) -> crate::Result<()> {
        unimplemented!()
    }
    fn get_user_backup_tx(&self,_user_id: uuid::Uuid) -> crate::Result<bitcoin::Transaction> {
        unimplemented!()
    }
    fn update_backup_tx(&self,_state_chain_id: &uuid::Uuid, _tx: bitcoin::Transaction) -> crate::Result<()> {
        unimplemented!()
    }
    fn get_withdraw_confirm_data(&self, _user_id: uuid::Uuid) -> crate::Result<crate::structs::WithdrawConfirmData> {
        unimplemented!()
    }
    fn root_update(&self, _rt: &super::Root) -> crate::Result<i64> {
        unimplemented!()
    }
    fn root_insert(&self, _root: super::Root) -> crate::Result<u64> {
        unimplemented!()
    }
    fn root_get_current_id(&self) -> crate::Result<i64> {
        unimplemented!()
    }
    fn get_root(&self, _id: i64) -> crate::Result<Option<super::Root>> {
        unimplemented!()
    }
    fn get_confirmed_smt_root(&self) -> crate::Result<Option<super::Root>> {
        unimplemented!()
    }
    fn get_statechain_id(&self, _user_id: uuid::Uuid) -> crate::Result<uuid::Uuid> {
        unimplemented!()
    }
    fn update_statechain_id(&self, _user_id: &uuid::Uuid, _state_chain_id: &uuid::Uuid) -> crate::Result<()> {
        unimplemented!()
    }
    fn get_statechain_amount(&self, _state_chain_id: uuid::Uuid) -> crate::Result<crate::structs::StateChainAmount> {
        unimplemented!()
    }
    fn update_statechain_amount(
        &self,
        _state_chain_id: &uuid::Uuid,
        _state_chain: super::StateChain,
        _amount: u64,
    ) -> crate::Result<()> {
        unimplemented!()
    }
    fn create_statechain(
        &self,
        _state_chain_id: &uuid::Uuid,
        _user_id: &uuid::Uuid,
        _state_chain: &super::StateChain,
        _amount: &i64,
    ) -> crate::Result<()> {
        unimplemented!()
    }
    fn get_statechain(&self, _state_chain_id: uuid::Uuid) -> crate::Result<super::StateChain> {
        unimplemented!()
    }
    fn update_statechain_owner(
        &self,
        _state_chain_id: &uuid::Uuid,
        _state_chain: super::StateChain,
        _new_user_id: &uuid::Uuid,
    ) -> crate::Result<()> {
        unimplemented!()
    }
    fn remove_statechain_id(&self, _user_id: &uuid::Uuid) -> crate::Result<()> {
        unimplemented!()
    }
    fn create_backup_transaction(
        &self,
        _state_chain_id: &uuid::Uuid,
        _tx_backup: &bitcoin::Transaction,
    ) -> crate::Result<()> {
        unimplemented!()
    }
    fn get_backup_transaction(&self, _state_chain_id: uuid::Uuid) -> crate::Result<bitcoin::Transaction> {
        unimplemented!()
    }
    fn get_backup_transaction_and_proof_key(&self, _user_id: uuid::Uuid) -> crate::Result<(bitcoin::Transaction, String)> {
        unimplemented!()
    }
    fn get_proof_key(&self, _user_id: uuid::Uuid) -> crate::Result<String> {
        unimplemented!()
    }
    fn get_sc_locked_until(&self, _state_chain_id: uuid::Uuid) -> crate::Result<chrono::NaiveDateTime> {
        unimplemented!()
    }
    fn update_locked_until(&self, _state_chain_id: &uuid::Uuid, _time: &chrono::NaiveDateTime) -> crate::Result<()> {
        unimplemented!()
    }
    fn get_transfer_batch_data(&self, _batch_id: uuid::Uuid) -> crate::Result<crate::structs::TransferBatchData> {
        unimplemented!()
    }
    fn has_transfer_batch_id(&self, _batch_id: uuid::Uuid) -> bool {
        unimplemented!()
    }
    fn get_transfer_batch_id(&self, _batch_id: uuid::Uuid) -> crate::Result<uuid::Uuid> {
        unimplemented!()
    }
    fn get_punished_state_chains(&self, _batch_id: uuid::Uuid) -> crate::Result<Vec<uuid::Uuid>> {
        unimplemented!()
    }
    fn create_transfer(
        &self,
        _state_chain_id: &uuid::Uuid,
        _state_chain_sig: &shared_lib::state_chain::StateChainSig,
        _x1: &curv::FE,
    ) -> crate::Result<()> {
        unimplemented!()
    }
    fn create_transfer_batch_data(
        &self,
        _batch_id: &uuid::Uuid,
        _state_chains: HashMap<uuid::Uuid, bool>,
    ) -> crate::Result<()> {
        unimplemented!()
    }
    fn get_transfer_data(&self, _state_chain_id: uuid::Uuid) -> crate::Result<crate::structs::TransferData> {
        unimplemented!()
    }
    fn remove_transfer_data(&self, _state_chain_id: &uuid::Uuid) -> crate::Result<()> {
        unimplemented!()
    }
    fn transfer_is_completed(&self, _state_chain_id: uuid::Uuid) -> bool {
        unimplemented!()
    }
    fn get_ecdsa_master(&self, _user_id: uuid::Uuid) -> crate::Result<Option<String>> {
        unimplemented!()
    }
    fn get_ecdsa_witness_keypair(
        &self,
        _user_id: uuid::Uuid,
    ) -> crate::Result<(crate::protocol::ecdsa::party_one::CommWitness, crate::protocol::ecdsa::party_one::EcKeyPair)> {
        unimplemented!()
    }
    fn get_ecdsa_s2(&self, _user_id: uuid::Uuid) -> crate::Result<curv::FE> {
        unimplemented!()
    }
    fn update_keygen_first_msg(
        &self,
        _user_id: &uuid::Uuid,
        _key_gen_first_msg: &crate::protocol::ecdsa::party_one::KeyGenFirstMsg,
        _comm_witness: crate::protocol::ecdsa::party_one::CommWitness,
        _ec_key_pair: crate::protocol::ecdsa::party_one::EcKeyPair,
    ) -> crate::Result<()> {
        unimplemented!()
    }
    fn update_keygen_second_msg(
        &self,
        _user_id: &uuid::Uuid,
        _party2_public: curv::GE,
        _paillier_key_pair: crate::protocol::ecdsa::party_one::PaillierKeyPair,
        _party_one_private: crate::protocol::ecdsa::party_one::Party1Private,
    ) -> crate::Result<()> {
        unimplemented!()
    }
    fn update_keygen_third_msg(
        &self,
        _user_id: &uuid::Uuid,
        _party_one_pdl_decommit: crate::protocol::ecdsa::party_one::PDLdecommit,
        _party_two_pdl_first_message: crate::protocol::ecdsa::party_two::PDLFirstMessage,
        _alpha: curv::BigInt,
    ) -> crate::Result<()> {
        unimplemented!()
    }
    fn init_ecdsa(&self, _user_id: &uuid::Uuid) -> crate::Result<u64> {
        unimplemented!()
    }
    fn get_ecdsa_party_1_private(&self, _user_id: uuid::Uuid) -> crate::Result<crate::protocol::ecdsa::party_one::Party1Private> {
        unimplemented!()
    }
    fn get_ecdsa_keypair(&self, _user_id: uuid::Uuid) -> crate::Result<crate::structs::ECDSAKeypair> {
        unimplemented!()
    }
    fn update_punished(&self, _batch_id: &uuid::Uuid, _punished_state_chains: Vec<uuid::Uuid>) -> crate::Result<()> {
        unimplemented!()
    }
    fn get_finalize_batch_data(&self, _batch_id: uuid::Uuid) -> crate::Result<crate::structs::TransferFinalizeBatchData> {
        unimplemented!()
    }
    fn update_finalize_batch_data(
        &self,
        _batch_id: &uuid::Uuid,
        _state_chains: HashMap<uuid::Uuid, bool>,
        _finalized_data_vec: Vec<crate::protocol::transfer::TransferFinalizeData>,
    ) -> crate::Result<()> {
        unimplemented!()
    }
    fn update_transfer_batch_finalized(&self, _batch_id: &uuid::Uuid, _b_finalized: &bool) -> crate::Result<()> {
        unimplemented!()
    }
    fn get_statechain_owner(&self, _state_chain_id: uuid::Uuid) -> crate::Result<crate::structs::StateChainOwner> {
        unimplemented!()
    }
    fn create_user_session(&self, _user_id: &uuid::Uuid, _auth: &String, _proof_key: &String) -> crate::Result<()> {
        unimplemented!()
    }
    fn transfer_init_user_session(
        &self,
        _new_user_id: &uuid::Uuid,
        _state_chain_id: &uuid::Uuid,
        _finalized_data: crate::protocol::transfer::TransferFinalizeData,
    ) -> crate::Result<()> {
        unimplemented!()
    }
    fn get_ecdsa_fourth_message_input(&self, _user_id: uuid::Uuid) -> crate::Result<crate::structs::ECDSAFourthMessageInput> {
        unimplemented!()
    }
    fn update_ecdsa_sign_first(
        &self,
        _user_id: uuid::Uuid,
        _eph_key_gen_first_message_party_two: crate::protocol::ecdsa::party_two::EphKeyGenFirstMsg,
        _eph_ec_key_pair_party1: crate::protocol::ecdsa::party_one::EphEcKeyPair,
    ) -> crate::Result<()> {
        unimplemented!()
    }
    fn get_ecdsa_sign_second_input(&self, _user_id: uuid::Uuid) -> crate::Result<crate::structs::ECDSASignSecondInput> {
        unimplemented!()
    }
    fn get_tx_withdraw(&self, _user_id: uuid::Uuid) -> crate::Result<bitcoin::Transaction> {
        unimplemented!()
    }
    fn update_tx_withdraw(&self, _user_id: uuid::Uuid, _tx: bitcoin::Transaction) -> crate::Result<()> {
        unimplemented!()
    }
    fn reset(&self) -> crate::Result<()> {
        unimplemented!()
    }
    fn init(&self) -> crate::Result<()> {
        unimplemented!()
    }
    fn get_ecdsa_master_key_input(&self, _user_id: uuid::Uuid) -> crate::Result<crate::structs::ECDSAMasterKeyInput> {
        unimplemented!()
    }
    fn update_ecdsa_master(&self, _user_id: &uuid::Uuid, _master_key: crate::protocol::ecdsa::MasterKey1) -> crate::Result<()> {
        unimplemented!()
    }
    fn get_sighash(&self, _user_id: uuid::Uuid) -> crate::Result<bitcoin::hashes::sha256d::Hash> {
        unimplemented!()
    }

}
