//! Postgres implementation for Monotree

use crate::PGDatabase;
use crate::storage::db::Table;
use monotree::database::{MemCache, Database as MonotreeDatabase};
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
            ,Table::Transfer.to_string(), serde_json::to_string(&key).unwrap())) {
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
        match row.get_opt(0) {
            None => return Err(Errors::new("No data for key")),
            Some(data) => match data {
                Ok(v) => Ok(v),
                Err(_) => return Err(Errors::new("No data for key")),
            },
        }
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
                Table::Transfer.to_string(),
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
                Table::Transfer.to_string(), serde_json::to_string(&key).unwrap())){
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
            let batch = std::mem::take(&mut self.smt_batch);
            let mut stmt_str = format!("INSERT INTO {} (key, value) VALUES", Table::Transfer.to_string());
            for (key, value) in batch.iter() {
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
