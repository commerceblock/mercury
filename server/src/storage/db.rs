//! DB
//!
//! Postgres DB access and update tools.

use super::super::Result;
use bitcoin::Transaction;
pub type Hash = bitcoin::hashes::sha256d::Hash;

use crate::server::{get_postgres_url, UserIDs};
use crate::{
    error::{
        DBErrorType::{ConnectionFailed, NoDataForID, UpdateFailed},
        SEError,
    },
    structs::*,
    Database, DatabaseR, DatabaseW, PGDatabase, PGDatabaseSmt,
};
use bitcoin::hashes::sha256d;
use chrono::NaiveDateTime;
use curv::{BigInt, FE, GE};
use kms::ecdsa::two_party::*;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one::Party1Private;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two};
use rocket_contrib::databases::postgres::{rows::Row, types::ToSql};
use rocket_contrib::databases::r2d2;
use rocket_contrib::databases::r2d2_postgres::{PostgresConnectionManager, TlsMode};
use shared_lib::mainstay::CommitmentInfo;
use shared_lib::state_chain::*;
use shared_lib::structs::{TransferMsg3,CoinValueInfo,TransferFinalizeData};
use shared_lib::Root;
use shared_lib::util::transaction_deserialise;
use rocket_okapi::JsonSchema;

use std::collections::{HashMap, HashSet};
use uuid::Uuid;
use std::convert::TryInto;
use std::sync::{Arc, Mutex};

use monotree::database::MemCache;
use std::num::NonZeroU64;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Alpha {
    pub value: BigInt,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct HDPos {
    pub pos: u32,
}

#[derive(Debug)]
pub enum Schema {
    StateChainEntity,
    Watcher,
}
impl Schema {
    pub fn to_string(&self) -> String {
        format!("{:?}", self)
    }
}

#[derive(Debug)]
pub enum Table {
    UserSession,
    Ecdsa,
    StateChain,
    Transfer,
    TransferBatch,
    Root,
    BackupTxs,
    Smt,
    Lockbox
}
impl Table {
    pub fn to_string(&self) -> String {
        match self {
            Table::BackupTxs => format!(
                "{:?}.{:?}",
                Schema::Watcher.to_string().to_lowercase(),
                self
            ),
            _ => format!(
                "{:?}.{:?}",
                Schema::StateChainEntity.to_string().to_lowercase(),
                self
            ),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone, Copy)]
pub enum Column {
    Data,
    Complete,

    // UserSession
    Id,
    Authentication,
    ProofKey,
    StateChainId,
    TxBackup,
    LockTime,
    TxWithdraw,
    SigHash,
    S2,
    S1PubKey,
    WithdrawScSig,
    MasterPublic,
    Challenge,

    // StateChain,
    // Id,
    Chain,
    Amount,
    LockedUntil,
    OwnerId,
    TransferFinalizeData,
    TransferReady,
    SharedPublic,
    Confirmed,

    // BackupTxs
    //Id,
    // TxBackup,

    // Transfer
    // Id,
    StateChainSig,
    X1,
    TransferMsg,
    BatchId,

    // TransferBatch
    // Id,
    StartTime,
    StateChains,
    PunishedStateChains,
    Finalized,

    // Ecdsa
    // Id,
    KeyGenFirstMsg,
    CommWitness,
    EcKeyPair,
    PaillierKeyPair,
    Party1Private,
    Party2Public,
    Party1MasterKey,
    EphEcKeyPair,
    EphKeyGenFirstMsg,
    KeyGenSecondMsg,
    POS,

    // Root
    // Id,
    Value,
    CommitmentInfo,

    // Smt
    Key,
    // Value
    Lockbox,
}


impl Column {
    pub fn to_string(&self) -> String {
        format!("{:?}", self)
    }
}

impl PGDatabase {
    fn get_postgres_connection_pool(
        rocket_url: &String,
    ) -> Result<r2d2::Pool<PostgresConnectionManager>> {
        let url: String = rocket_url.clone().to_string();
        let manager = PostgresConnectionManager::new(url.clone(), TlsMode::None)?;
        match r2d2::Pool::new(manager) {
            Ok(m) => Ok(m),
            Err(e) => Err(SEError::DBError(
                ConnectionFailed,
                format!(
                    "Failed to get postgres connection managerfor rocket url {}: {}",
                    url, e
                ),
            )),
        }
    }

    pub fn database_r(&self) -> Result<DatabaseR> {
        match &self.pool {
            Some(p) => match p.get() {
                Ok(c) => Ok(DatabaseR(c)),
                Err(e) => Err(SEError::DBError(
                    ConnectionFailed,
                    format!("Failed to get pooled connection for read: {}", e),
                )),
            },
            None => Err(SEError::DBError(
                ConnectionFailed,
                "Failed to get pooled connection for read: pool not set".to_string(),
            )),
        }
    }

    pub fn database_w(&self) -> Result<DatabaseW> {
        match &self.pool {
            Some(p) => match p.get() {
                Ok(c) => Ok(DatabaseW(c)),
                Err(e) => Err(SEError::DBError(
                    ConnectionFailed,
                    format!("Failed to get pooled connection for write: {}", e),
                )),
            },
            None => Err(SEError::DBError(
                ConnectionFailed,
                "Failed to get pooled connection for write: pool not set".to_string(),
            )),
        }
    }

    /// Build DB tables and Schemas
    pub fn make_tables(&self) -> Result<()> {
        // Create Schemas if they do not already exist
        let _ = self.database_w()?.execute(
            &format!(
                "
            CREATE SCHEMA IF NOT EXISTS statechainentity;
            "
            ),
            &[],
        )?;
        let _ = self.database_w()?.execute(
            &format!(
                "
            CREATE SCHEMA IF NOT EXISTS watcher;
            "
            ),
            &[],
        )?;

        // Create tables if they do not already exist
        self.database_w()?.execute(
            &format!(
                "
            CREATE TABLE IF NOT EXISTS {} (
                id uuid NOT NULL,
                statechainid uuid,
                authentication varchar,
                s2 varchar,
                s1pubkey varchar,
                sighash varchar,
                withdrawscsig varchar,
                txwithdraw varchar,
                proofkey varchar,
                txbackup varchar,
                masterpublic varchar,
                sharedpublic varchar,
                challenge varchar,
                PRIMARY KEY (id)
            );",
                Table::UserSession.to_string(),
            ),
            &[],
        )?;

        self.database_w()?.execute(
            &format!(
                "
            CREATE TABLE IF NOT EXISTS {} (
                id uuid NOT NULL,
                lockbox int8,
                PRIMARY KEY (id)
            );",
                Table::Lockbox.to_string(),
            ),
            &[],
        )?;




        self.database_w()?.execute(
            &format!(
                "
            CREATE TABLE IF NOT EXISTS {} (
                id uuid NOT NULL,
                keygenfirstmsg varchar,
                commwitness varchar,
                eckeypair varchar,
                party2public varchar,
                paillierkeypair varchar,
                party1private varchar,
                party1masterkey varchar,
                pos varchar,
                epheckeypair varchar,
                ephkeygenfirstmsg varchar,
                complete bool NOT NULL DEFAULT false,
                keygensecondmessage varchar,
                PRIMARY KEY (id)
            );",
                Table::Ecdsa.to_string(),
            ),
            &[],
        )?;

        self.database_w()?.execute(
            &format!(
                "
            CREATE TABLE IF NOT EXISTS {} (
                id uuid NOT NULL,
                chain varchar,
                amount int8,
                ownerid uuid,
                lockeduntil timestamp,
                transferfinalizedata varchar,
                transferready bool,
                sharedpublic varchar,
                confirmed bool NOT NULL DEFAULT false,
                PRIMARY KEY (id)
            );",
                Table::StateChain.to_string(),
            ),
            &[],
        )?;

        self.database_w()?.execute(
            &format!(
                "
            CREATE TABLE IF NOT EXISTS {} (
                id uuid NOT NULL,
                statechainsig varchar,
                x1 varchar,
                transfermsg varchar,
                proofkey varchar,
                batchid uuid,
                PRIMARY KEY (id)
            );",
                Table::Transfer.to_string(),
            ),
            &[],
        )?;

        self.database_w()?.execute(
            &format!(
                "
            CREATE TABLE IF NOT EXISTS {} (
                id uuid NOT NULL,
                starttime timestamp,
                statechains varchar,
                punishedstatechains varchar,
                finalized bool,
                PRIMARY KEY (id)
            );",
                Table::TransferBatch.to_string(),
            ),
            &[],
        )?;

        self.database_w()?.execute(
            &format!(
                "
            CREATE TABLE IF NOT EXISTS {} (
                id BIGSERIAL,
                value varchar,
                commitmentinfo varchar,
                PRIMARY KEY (id)
            );",
                Table::Root.to_string(),
            ),
            &[],
        )?;

        self.database_w()?.execute(
            &format!(
                "
            CREATE TABLE IF NOT EXISTS {} (
                id uuid NOT NULL,
                txbackup varchar,
                locktime int8,
                PRIMARY KEY (id)
            );",
                Table::BackupTxs.to_string(),
            ),
            &[],
        )?;

        self.database_w()?.execute(
            &format!(
                "
            CREATE TABLE IF NOT EXISTS {} (
                key varchar,
                value varchar,
                PRIMARY KEY (key)
            );",
                Table::Smt.to_string(),
            ),
            &[],
        )?;

        Ok(())
    }

    #[allow(dead_code)]
    /// Drop all DB tables and Schemas.
    fn drop_tables(&self) -> Result<()> {
        //statechainentity schema may not exist
        match self.database_w()?.execute(
            &format!(
                "
            DROP SCHEMA statechainentity CASCADE;",
            ),
            &[],
        ){
            Ok(_) => (),
            Err(e) => {
                let es = e.to_string();
                if es.find("database error").is_some() && 
                    es.find("does not exist").is_some() {
                        ()    
                } else {
                    return Err(e.into())
                } 
            }
        };
        let _ = self.database_w()?.execute(
            &format!(
                "
            DROP SCHEMA watcher CASCADE;",
            ),
            &[],
        )?;

        Ok(())
    }

    /// Drop all DB tables and schemas.
    fn truncate_tables(&self) -> Result<()> {
        self.database_w()?.execute(
            &format!(
                "
            TRUNCATE {},{},{},{},{},{},{},{},{} RESTART IDENTITY;",
                Table::UserSession.to_string(),
                Table::Ecdsa.to_string(),
                Table::StateChain.to_string(),
                Table::Transfer.to_string(),
                Table::TransferBatch.to_string(),
                Table::Root.to_string(),
                Table::BackupTxs.to_string(),
                Table::Smt.to_string(),
                Table::Lockbox.to_string(),
            ),
            &[],
        )?;
        Ok(())
    }

    /// Serialize data into string. To add custom types to Postgres they must be serialized to String.
    pub fn ser<T>(data: T) -> Result<String>
    where
        T: serde::ser::Serialize,
    {
        match serde_json::to_string(&data) {
            Ok(v) => Ok(v),
            Err(_) => Err(SEError::Generic(String::from("Failed to serialize data."))),
        }
    }

    /// Deserialize custom type data from string. Reverse of ser().
    pub fn deser<T>(data: String) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        match serde_json::from_str(&data) {
            Ok(v) => Ok(v),
            Err(_) => Err(SEError::Generic(String::from(
                "Failed to deserialize string.",
            ))),
        }
    }

    /// Create new item in table
    pub fn insert(&self, id: &Uuid, table: Table) -> Result<u64> {
        let dbw = self.database_w()?;
        let statement = dbw.prepare(&format!(
            "INSERT INTO {} (id) VALUES ($1)",
            table.to_string()
        ))?;

        Ok(statement.execute(&[id])?)
    }

    /// Remove row in table
    pub fn remove(&self, id: &Uuid, table: Table) -> Result<()> {
        let dbw = self.database_w()?;
        let statement =
            dbw.prepare(&format!("DELETE FROM {} WHERE id = $1;", table.to_string()))?;
        if statement.execute(&[&id])? == 0 {
            return Err(SEError::DBError(UpdateFailed, id.to_string()));
        }

        Ok(())
    }

    /// Returns str list of column names for SQL UPDATE prepare statement.
    fn update_columns_str(&self, cols: Vec<Column>) -> String {
        let cols_len = cols.len();
        let mut str = "".to_owned();
        for (i, col) in cols.iter().enumerate() {
            str.push_str(&col.to_string());
            str.push_str(&format!("=${}", i + 1));
            if i != cols_len - 1 {
                str.push_str(",");
            }
        }
        str
    }

    /// Update items in table for some ID with PostgreSql data types (String, int, bool, Uuid, chrono::NaiveDateTime).
    pub fn update<'a>(
        &self,
        id: &Uuid,
        table: Table,
        column: Vec<Column>,
        data: Vec<&'a dyn ToSql>,
    ) -> Result<()> {
        let num_items = column.len();
        let dbw = self.database_w()?;
        let statement = dbw.prepare(&format!(
            "UPDATE {} SET {} WHERE id = ${}",
            table.to_string(),
            self.update_columns_str(column),
            num_items + 1
        ))?;

        let mut owned_data = data.clone();
        owned_data.push(id);

        if statement.execute(&owned_data)? == 0 {
            return Err(SEError::DBError(UpdateFailed, id.to_string()));
        }

        Ok(())
    }

    /// Get items from table for some ID with PostgreSql data types (String, int, Uuid, bool, Uuid, chrono::NaiveDateTime).
    /// Err if ID not found. Return None if data item empty.
    fn get<T, U, V, W>(
        &self,
        id: Uuid,
        table: Table,
        column: Vec<Column>,
    ) -> Result<(Option<T>, Option<U>, Option<V>, Option<W>)>
    where
        T: rocket_contrib::databases::postgres::types::FromSql,
        U: rocket_contrib::databases::postgres::types::FromSql,
        V: rocket_contrib::databases::postgres::types::FromSql,
        W: rocket_contrib::databases::postgres::types::FromSql,
    {
        let num_items = column.len();
        let dbr = self.database_r()?;

        let fmt_str = format!(
            "SELECT {} FROM {} WHERE id = $1",
            self.get_columns_str(&column),
            table.to_string()
        );

        let statement = dbr.prepare(&fmt_str)?;

        let rows = statement.query(&[&id])?;

        if rows.is_empty() {
            return Err(SEError::DBError(NoDataForID, id.to_string()));
        };

        let row = rows.get(0);

        let col1 = self.get_item_from_row::<T>(&row, 0, &id.to_string(), column[0])?;
        if num_items == 1 {
            return Ok((Some(col1), None, None, None));
        }

        let col2 = self.get_item_from_row::<U>(&row, 1, &id.to_string(), column[1])?;
        if num_items == 2 {
            return Ok((Some(col1), Some(col2), None, None));
        }

        let col3 = self.get_item_from_row::<V>(&row, 2, &id.to_string(), column[2])?;
        if num_items == 3 {
            return Ok((Some(col1), Some(col2), Some(col3), None));
        }

        let col4 = self.get_item_from_row::<W>(&row, 3, &id.to_string(), column[3])?;
        if num_items == 4 {
            return Ok((Some(col1), Some(col2), Some(col3), Some(col4)));
        }

        Ok((None, None, None, None))
    }

    /// Returns str list of column names for SQL SELECT query statement.
    pub fn get_columns_str(&self, cols: &Vec<Column>) -> String {
        let cols_len = cols.len();
        let mut str = "".to_owned();
        for (i, col) in cols.iter().enumerate() {
            str.push_str(&col.to_string());
            if i != cols_len - 1 {
                str.push_str(",");
            }
        }
        str
    }

    fn get_item_from_row<T>(
        &self,
        row: &Row,
        index: usize,
        id: &String,
        column: Column,
    ) -> Result<T>
    where
        T: rocket_contrib::databases::postgres::types::FromSql,
    {
        match row.get_opt::<usize, T>(index) {
            None => return Err(SEError::DBError(NoDataForID, id.to_string())),
            Some(data) => match data {
                Ok(v) => Ok(v),
                Err(_) => return Err(SEError::DBErrorWC(NoDataForID, id.to_string(), column)),
            },
        }
    }

    /// Get 1 item from row in table. Err if ID not found. Return None if data item empty.
    pub fn get_1<T>(&self, id: Uuid, table: Table, column: Vec<Column>) -> Result<T>
    where
        T: rocket_contrib::databases::postgres::types::FromSql,
    {
        let (res, _, _, _) = self.get::<T, T, T, T>(id, table, column)?;
        res.ok_or(SEError::DBError(
            crate::error::DBErrorType::NoDataForID,
            "item not found".to_string(),
        ))
        //Ok(res.unwrap()) //  err returned from db_get if desired item is None
    }
    /// Get 2 items from row in table. Err if ID not found. Return None if data item empty.
    pub fn get_2<T, U>(&self, id: Uuid, table: Table, column: Vec<Column>) -> Result<(T, U)>
    where
        T: rocket_contrib::databases::postgres::types::FromSql,
        U: rocket_contrib::databases::postgres::types::FromSql,
    {
        let (res1, res2, _, _) = self.get::<T, U, U, U>(id, table, column)?;
        Ok((res1.unwrap(), res2.unwrap()))
    }
    /// Get 3 items from row in table. Err if ID not found. Return None if data item empty.
    pub fn get_3<T, U, V>(&self, id: Uuid, table: Table, column: Vec<Column>) -> Result<(T, U, V)>
    where
        T: rocket_contrib::databases::postgres::types::FromSql,
        U: rocket_contrib::databases::postgres::types::FromSql,
        V: rocket_contrib::databases::postgres::types::FromSql,
    {
        let (res1, res2, res3, _) = self.get::<T, U, V, V>(id, table, column)?;
        Ok((res1.unwrap(), res2.unwrap(), res3.unwrap()))
    }
    /// Get 4 items from row in table. Err if ID not found. Return None if data item empty.
    pub fn get_4<T, U, V, W>(
        &self,
        id: Uuid,
        table: Table,
        column: Vec<Column>,
    ) -> Result<(T, U, V, W)>
    where
        T: rocket_contrib::databases::postgres::types::FromSql,
        U: rocket_contrib::databases::postgres::types::FromSql,
        V: rocket_contrib::databases::postgres::types::FromSql,
        W: rocket_contrib::databases::postgres::types::FromSql,
    {
        let (res1, res2, res3, res4) = self.get::<T, U, V, W>(id, table, column)?;
        Ok((res1.unwrap(), res2.unwrap(), res3.unwrap(), res4.unwrap()))
    }
}

impl Database for PGDatabase {
    fn init(&self, coins_histo: &Mutex<CoinValueInfo>, user_ids: &Mutex<UserIDs>) -> Result<()> {
        self.make_tables()?;
        self.init_coins_histo(coins_histo)?;
        self.init_user_ids(user_ids)
    }

    fn from_pool(pool: r2d2::Pool<PostgresConnectionManager>) -> Self {
        Self {
            pool: Some(pool),
            smt: PGDatabaseSmt {
                table_name: Table::Smt.to_string(),
                cache: MemCache::new(),
                batch_on: false,
                batch: HashMap::new(),
            },
        }
    }

    fn get_new() -> Self {
        Self {
            pool: None,
            smt: PGDatabaseSmt {
                table_name: Table::Smt.to_string(),
                cache: MemCache::new(),
                batch_on: false,
                batch: HashMap::new(),
            },
        }
    }

    fn set_connection_from_config(&mut self, config: &crate::config::Config) -> Result<()> {
        let rocket_url = get_postgres_url(
            config.storage.db_host_w.clone(),
            config.storage.db_port_w.clone(),
            config.storage.db_user_w.clone(),
            config.storage.db_pass_w.clone(),
            config.storage.db_database_w.clone(),
        );
        self.set_connection(&rocket_url)
    }

    fn set_connection(&mut self, url: &String) -> Result<()> {
        match Self::get_postgres_connection_pool(url) {
            Ok(p) => {
                self.pool = Some(p.clone());
                Ok(())
            }
            Err(e) => Err(SEError::DBError(
                ConnectionFailed,
                format!("Error obtaining pool address for url {}: {}", url, e),
            )),
        }
    }

    fn reset(&self) -> Result<()> {
        info!("Resetting database");
        // truncate all postgres tables    
        let _ = self.truncate_tables();
        let _ = self.drop_tables();
        Ok(())
    }

    fn init_coins_histo(&self, coins_histo: &Mutex<CoinValueInfo> ) -> Result<()> {
        let mut guard = coins_histo.lock()?;
        let dbr = self.database_r()?;
        let statement =
            dbr.prepare(&format!("SELECT amount,count(CASE WHEN confirmed THEN 1 END) FROM {} GROUP BY amount", Table::StateChain.to_string(),))?;
        let rows = statement.query(&[])?;
        if rows.is_empty() {
            return Ok(());
        };
        for row in &rows {
            match NonZeroU64::new(row.get_opt::<usize, i64>(1).unwrap().unwrap().try_into().unwrap()){
                Some(count) => {
                    let amount: i64 = row.get_opt::<usize, i64>(0).unwrap().unwrap();
                    guard.values.insert(amount,count);
                },
                None => ()
            };
        }
        Ok(())
    }

    fn init_user_ids(&self, user_ids: &Mutex<UserIDs>) -> Result<()> {
        let mut guard = user_ids.lock()?;
        let dbr = self.database_r()?;
        let statement =
            dbr.prepare(&format!("SELECT * FROM {}", Table::UserSession.to_string()))?;
        let rows = statement.query(&[])?;
        for row in &rows {
            let id: Uuid = row.get_opt::<usize, Uuid>(0).unwrap().unwrap();
            guard.insert(id);
        }
        Ok(())
    }

    fn has_withdraw_sc_sig(&self, user_id: Uuid) -> Result<()> {
        match self.get_1::<String>(user_id, Table::UserSession, vec![Column::WithdrawScSig]) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn get_withdraw_sc_sig(&self, user_id: Uuid) -> Result<StateChainSig> {
        let withdraw_sc_sig_str = self.get_1::<String>(user_id, Table::UserSession, vec![Column::WithdrawScSig])?;
        let withdraw_sc_sig: StateChainSig = Self::deser(withdraw_sc_sig_str)?;
        Ok(withdraw_sc_sig)
    }    

    fn update_withdraw_sc_sig(&self, user_id: &Uuid, sig: StateChainSig) -> Result<()> {
        self.update(
            user_id,
            Table::UserSession,
            vec![Column::WithdrawScSig],
            vec![&Self::ser(sig)?],
        )
    }

    fn update_s1_pubkey(&self, user_id: &Uuid, pubkey: &GE) -> Result<()> {
        self.update(
            user_id,
            Table::UserSession,
            vec![Column::S1PubKey],
            vec![&Self::ser(pubkey)?],
        )
    }

    fn get_lockbox_index(&self, user_id: &Uuid) -> Result<Option<usize>> {
        match self.get_1::<i64>(*user_id, Table::Lockbox, vec![Column::Lockbox]){
            Ok(r) => Ok(Some(r as usize)),
            Err(e) => match e {
                        SEError::DBError(ref error_type, ref _message) => match error_type {
                            NoDataForID => Ok(None),
                            _ => Err(e),
                        },
                        SEError::DBErrorWC(ref error_type, ref _message, ref _column) => match error_type {
                            NoDataForID => Ok(None),
                            _ => Err(e),
                        },
                    _   => Err(e),
            }
        }
    }
  
    fn update_lockbox_index(&self, user_id: &Uuid, lockbox_index: &usize)->Result<()>{
        self.update(user_id,
                    Table::Lockbox,
                    vec![Column::Lockbox],
                    vec![&(*lockbox_index as i64)])
    }

    fn get_s1_pubkey(&self, user_id: &Uuid) -> Result<GE> {
        let pubkey: GE =
            Self::deser(self.get_1(*user_id, Table::UserSession, vec![Column::S1PubKey])?)?;
        Ok(pubkey)
    }

    fn update_withdraw_tx_sighash(
        &self,
        user_id: &Uuid,
        sig_hash: Hash,
        tx: Transaction,
    ) -> Result<()> {
        self.update(
            user_id,
            Table::UserSession,
            vec![Column::SigHash, Column::TxWithdraw],
            vec![&Self::ser(sig_hash)?, &Self::ser(tx)?],
        )
    }

    fn update_sighash(&self, user_id: &Uuid, sig_hash: Hash) -> Result<()> {
        self.update(
            user_id,
            Table::UserSession,
            vec![Column::SigHash],
            vec![&Self::ser(sig_hash)?],
        )
    }

    fn get_sighash(&self, user_id: Uuid) -> Result<sha256d::Hash> {
        let sig_hash: sha256d::Hash =
            Self::deser(self.get_1(user_id, Table::UserSession, vec![Column::SigHash])?)?;
        Ok(sig_hash)
    }

    fn update_user_backup_tx(&self, user_id: &Uuid, tx: Transaction) -> Result<()> {
        self.update(
            user_id,
            Table::UserSession,
            vec![Column::TxBackup],
            vec![&Self::ser(tx)?],
        )
    }

    fn get_user_backup_tx(&self, user_id: Uuid) -> Result<Transaction> {
        Self::deser(self.get_1(user_id, Table::UserSession, vec![Column::TxBackup])?)
    }

    fn update_backup_tx(&self,statechain_id: &Uuid, tx: Transaction) -> Result<()> {
        let locktime = tx.lock_time;
        self.update(
            statechain_id,
            Table::BackupTxs,
            vec![Column::TxBackup,Column::LockTime],
            vec![&Self::ser(tx)?,&(locktime as i64)],
        )
    }

    fn get_withdraw_confirm_data(&self, user_id: Uuid) -> Result<WithdrawConfirmData> {
        let (tx_withdraw_str, withdraw_sc_sig_str, statechain_id) = self
            .get_3::<String, String, Uuid>(
                user_id,
                Table::UserSession,
                vec![
                    Column::TxWithdraw,
                    Column::WithdrawScSig,
                    Column::StateChainId,
                ],
            )?;
        let tx_withdraw: Transaction = Self::deser(tx_withdraw_str)?;
        let withdraw_sc_sig: StateChainSig = Self::deser(withdraw_sc_sig_str)?;
        Ok(WithdrawConfirmData {
            tx_withdraw,
            withdraw_sc_sig,
            statechain_id,
        })
    }

    /// Update root value in DB. Update root with ID or insert new DB item.
    fn root_update(&self, rt: &Root) -> Result<i64> {
        let mut root = rt.clone();
        // Get previous ID, or use the one specified in root to update an existing root with mainstay proof
        let id = match root.id() {
            //This will update an existing root in the db
            Some(id) => {
                let existing_root = self.get_root(id as i64)?;
                match existing_root {
                    None => {
                        return Err(SEError::Generic(format!(
                            "error updating existing root - root not found with id {}",
                            id
                        )))
                    }
                    Some(r) => {
                        if r.hash() != root.hash() {
                            return Err(SEError::Generic(format!("error updating existing root - hashes do not match: existing: {} update: {}", r, root)));
                        }
                        id
                    }
                }
            }
            //new root, update id
            None => {
                match self.root_get_current_id() {
                    Ok(id) => id + 1,
                    Err(_) => 1, // No roots in DB
                }
            }
        };

        // Insert new root
        root.set_id(&id);
        self.root_insert(root.clone())?;

        debug!("Updated root at id {} with value: {:?}", id, root);
        Ok(id)
    }

    /// Insert a Root into root table
    fn root_insert(&self, root: Root) -> Result<u64> {
        let dbw = self.database_w()?;
        let statement = dbw.prepare(&format!(
            "INSERT INTO {} (value, commitmentinfo) VALUES ($1,$2)",
            Table::Root.to_string()
        ))?;
        let ci = root.commitment_info().clone();
        Ok(statement.execute(&[&Self::ser(root.hash())?, &Self::ser(ci)?])?)
    }

    /// Get Id of current Root
    fn root_get_current_id(&self) -> Result<i64> {
        let dbr = self.database_r()?;
        let statement =
            dbr.prepare(&format!("SELECT MAX(id) FROM {}", Table::Root.to_string(),))?;
        let rows = statement.query(&[])?;
        if rows.is_empty() {
            return Err(SEError::DBError(NoDataForID, String::from("Current Root")));
        };
        let row = rows.get(0);
        match row.get_opt::<usize, i64>(0) {
            None => return Ok(0),
            Some(data) => match data {
                Ok(v) => return Ok(v),
                Err(_) => return Ok(0),
            },
        }
    }

    /// Get vector of backup transactions that have nlocktimes less than or equal to the supplied locktime (lockheight)
    fn get_current_backup_txs(&self, locktime: i64) -> Result<Vec<BackupTxID>> {
        let dbr = self.database_r()?;
        let statement =
            dbr.prepare(&format!("SELECT * FROM {} WHERE locktime <= $1", Table::BackupTxs.to_string(),))?;
        let rows = statement.query(&[&locktime])?;
        let mut txs: Vec<BackupTxID> = Vec::new();
        if rows.is_empty() {
            return Ok(txs);
        };
        for row in &rows {
            let tx_backup: Transaction = Self::deser(row.get("txbackup"))?;
            let id: Uuid = row.get("id");
            let backup_obj = BackupTxID { tx: tx_backup, id };
            txs.push(backup_obj);
        }
        Ok(txs)
    }

    // remove confirmed backup transaction from db
    fn remove_backup_tx(&self, statechain_id: &Uuid) -> Result<()> {
        self.remove(statechain_id, Table::BackupTxs)
    }

    /// Get root with given ID
    fn get_root(&self, id: i64) -> Result<Option<Root>> {
        if id == 0 {
            return Ok(None);
        }
        let dbr = self.database_r()?;
        let statement = dbr.prepare(&format!(
            "SELECT * FROM {} WHERE id = $1",
            Table::Root.to_string(),
        ))?;
        let rows = statement.query(&[&id])?;
        if rows.is_empty() {
            return Err(SEError::DBError(NoDataForID, format!("Root id: {}", id)));
        };
        let row = rows.get(0);

        let id = match self.get_item_from_row::<i64>(&row, 0, &id.to_string(), Column::Id) {
            Ok(v) => v,
            Err(_) => {
                // No root in table yet. Return None
                return Ok(None);
            }
        };
        let root = Root::from(
            Some(id),
            Self::deser(self.get_item_from_row::<String>(
                &row,
                1,
                &id.to_string(),
                Column::Value,
            )?)?,
            &Self::deser::<Option<CommitmentInfo>>(self.get_item_from_row::<String>(
                &row,
                2,
                &id.to_string(),
                Column::CommitmentInfo,
            )?)?,
        )?;
        Ok(Some(root))
    }

    /// Find the latest confirmed root
    fn get_confirmed_smt_root(&self) -> Result<Option<Root>> {
        let current_id = self.root_get_current_id()?;
        for i in 0..=current_id - 1 {
            let id = current_id - i;
            let root = self.get_root(id)?;
            match root {
                Some(r) => {
                    if r.is_confirmed() {
                        return Ok(Some(r));
                    }
                    ()
                }
                None => (),
            };
        }
        Ok(None)
    }

    fn get_statechain_id(&self, user_id: Uuid) -> Result<Uuid> {
        self.get_1::<Uuid>(user_id, Table::UserSession, vec![Column::StateChainId])
    }

    fn get_owner_id(&self, statechain_id: Uuid) -> Result<Uuid> {
        self.get_1::<Uuid>(statechain_id, Table::StateChain, vec![Column::OwnerId])
    }

    fn get_user_auth(&self, user_id: &Uuid) -> Result<String> {
        self.get_1::<String>(*user_id, Table::UserSession, vec![Column::Authentication])
    }

    fn is_confirmed(&self, statechain_id: &Uuid) -> Result<bool> {
        self.get_1::<bool>(*statechain_id, Table::StateChain, vec![Column::Confirmed])
    }

    fn set_confirmed(&self, statechain_id: &Uuid) -> Result<()> {
        self.update(
            statechain_id,
            Table::StateChain,
            vec![Column::Confirmed],
            vec![&true],
        )
    }    

    fn get_challenge(&self, user_id: &Uuid) -> Result<String> {
        let challenge_str = self.get_1::<String>(*user_id, Table::UserSession, vec![Column::Challenge])?;
        Ok(challenge_str)
    }

    fn update_statechain_id(&self, user_id: &Uuid, statechain_id: &Uuid) -> Result<()> {
        self.update(
            user_id,
            Table::UserSession,
            vec![Column::StateChainId],
            vec![statechain_id],
        )
    }

    fn get_statechain_amount(&self, statechain_id: Uuid) -> Result<StateChainAmount> {
        let (amount, state_chain_str) = self.get_2::<i64, String>(
            statechain_id,
            Table::StateChain,
            vec![Column::Amount, Column::Chain],
        )?;
        let state_chain: StateChain = 
            Self::deser::<StateChainUnchecked>(state_chain_str)?.try_into()?;

        Ok(StateChainAmount {
            chain: state_chain,
            amount,
        })
    }

    fn update_statechain_amount(
        &self,
        statechain_id: &Uuid,
        state_chain: StateChain,
        amount: u64,
        coins_histo: Arc<Mutex<CoinValueInfo>>
    ) -> Result<()> {
        let prev_statechain_amount = &self.get_statechain_amount(*statechain_id)?.amount;
        match self.update(
            statechain_id,
            Table::StateChain,
            vec![Column::Chain, Column::Amount],
            vec![&Self::ser(state_chain)?, &(amount as i64)], // signals withdrawn funds
        )
        {
            Ok(_) => {
                let mut guard = coins_histo.as_ref().lock()?;
                if self.is_confirmed(&statechain_id)? {
                    guard.update(&(amount as i64),prev_statechain_amount)?;
                }
                Ok(())
            },
            Err(e) => {
                Err(e)
            }
        }
    }

    fn create_statechain(
        &self,
        statechain_id: &Uuid,
        user_id: &Uuid,
        state_chain: &StateChain,
        amount: &i64,
    ) -> Result<()> {
        self.insert(statechain_id, Table::StateChain)?;
        self.update(
            statechain_id,
            Table::StateChain,
            vec![
                Column::Chain,
                Column::Amount,
                Column::LockedUntil,
                Column::OwnerId,
            ],
            vec![
                &Self::ser(state_chain.to_owned())?,
                amount,
                &get_time_now(),
                &user_id.to_owned(),
            ],
        )?;
        Ok(())
    }

    fn get_statechain(&self, statechain_id: Uuid) -> Result<StateChain> {
        let (_, state_chain_str) = self.get_2::<i64, String>(
            statechain_id,
            Table::StateChain,
            vec![Column::Amount, Column::Chain],
        )?;
        let state_chain: StateChain = 
            Self::deser::<StateChainUnchecked>(state_chain_str)?.try_into()?;
        Ok(state_chain)
    }

    fn update_statechain_owner(
        &self,
        statechain_id: &Uuid,
        state_chain: StateChain,
        new_user_id: &Uuid,
    ) -> Result<()> {
        self.update(
            statechain_id,
            Table::StateChain,
            vec![Column::Chain, Column::OwnerId],
            vec![&Self::ser(state_chain)?, &new_user_id],
        )
    }

    // Remove statechain_id from user session to signal end of session
    fn remove_statechain_id(&self, user_id: &Uuid) -> Result<()> {
        self.update(
            user_id,
            Table::UserSession,
            vec![Column::StateChainId],
            vec![&Uuid::nil()],
        )
    }

    fn create_backup_transaction(
        &self,
        statechain_id: &Uuid,
        tx_backup: &Transaction,
    ) -> Result<()> {
        let locktime = tx_backup.lock_time;
        self.insert(statechain_id, Table::BackupTxs)?;
        self.update(
            statechain_id,
            Table::BackupTxs,
            vec![Column::TxBackup,Column::LockTime],
            vec![&Self::ser(tx_backup.clone())?,&(locktime as i64)],
        )
    }

    fn get_backup_transaction(&self, statechain_id: Uuid) -> Result<Transaction> {
        let (tx_backup_str) =
            self.get_1::<String>(statechain_id, Table::BackupTxs, vec![Column::TxBackup])?;
        let tx_backup: Transaction = Self::deser(tx_backup_str)?;
        Ok(tx_backup)
    }

    fn get_backup_locktime(&self, statechain_id: Uuid) -> Result<i64> {
        let backup_locktime =
            self.get_1::<i64>(statechain_id, Table::BackupTxs, vec![Column::LockTime])?;
        Ok(backup_locktime)
    }

    fn update_backup_locktime(&self,statechain_id: Uuid, locktime: i64) -> Result<()> {
        self.update(
            &statechain_id,
            Table::BackupTxs,
            vec![Column::LockTime],
            vec![&(locktime)],
        )
    }    

    fn get_proof_key(&self, user_id: Uuid) -> Result<String> {
        let proof_key =
            self.get_1::<String>(user_id, Table::UserSession, vec![Column::ProofKey])?;
        Ok(proof_key)
    }

    fn get_backup_transaction_and_proof_key(&self, user_id: Uuid) -> Result<(Transaction, String)> {
        let (tx_backup_str, proof_key) = self.get_2::<String, String>(
            user_id,
            Table::UserSession,
            vec![Column::TxBackup, Column::ProofKey],
        )?;
        let tx_backup: Transaction = Self::deser(tx_backup_str)?;
        Ok((tx_backup, proof_key))
    }

    fn get_sc_locked_until(&self, statechain_id: Uuid) -> Result<NaiveDateTime> {
        self.get_1::<NaiveDateTime>(statechain_id, Table::StateChain, vec![Column::LockedUntil])
    }

    fn update_locked_until(&self, statechain_id: &Uuid, time: &NaiveDateTime) -> Result<()> {
        self.update(
            statechain_id,
            Table::StateChain,
            vec![Column::LockedUntil],
            vec![time],
        )
    }

    fn get_transfer_batch_data(&self, batch_id: Uuid) -> Result<TransferBatchData> {
        let (state_chains_str, start_time, finalized, punished_state_chains_str) = self
            .get_4::<String, NaiveDateTime, bool, String>(
            batch_id,
            Table::TransferBatch,
            vec![
                Column::StateChains,
                Column::StartTime,
                Column::Finalized,
                Column::PunishedStateChains,
            ],
        )?;
        let state_chains: HashSet<Uuid> = Self::deser(state_chains_str)?;
        let punished_state_chains: Vec<Uuid> = Self::deser(punished_state_chains_str)?;
        Ok(TransferBatchData {
            state_chains,
            start_time,
            finalized,
            punished_state_chains,
        })
    }

    fn has_transfer_batch_id(&self, batch_id: Uuid) -> bool {
        self.get_transfer_batch_id(batch_id).is_ok()
    }

    fn get_transfer_batch_id(&self, batch_id: Uuid) -> Result<Uuid> {
        self.get_1::<Uuid>(batch_id, Table::TransferBatch, vec![Column::Id])
    }

    fn get_punished_state_chains(&self, batch_id: Uuid) -> Result<Vec<Uuid>> {
        Self::deser(self.get_1(
            batch_id,
            Table::TransferBatch,
            vec![Column::PunishedStateChains],
        )?)
    }

    fn create_transfer(
        &self,
        statechain_id: &Uuid,
        statechain_sig: &StateChainSig,
        x1: &FE,
        batch_id: Option<Uuid>
    ) -> Result<()> {
        // Create Transfer table entry
        if(!self.transfer_is_completed(statechain_id.clone())) {
            self.insert(&statechain_id, Table::Transfer)?;
        }
        if batch_id.is_some() {
            self.update(
                statechain_id,
                Table::Transfer,
                vec![Column::StateChainSig, Column::X1, Column::BatchId],
                vec![
                    &Self::ser(statechain_sig.to_owned())?,
                    &Self::ser(x1.to_owned())?,
                    &batch_id.unwrap().to_owned(),
                ],
            )
        } else {
            self.update(
                statechain_id,
                Table::Transfer,
                vec![Column::StateChainSig, Column::X1, Column::BatchId],
                vec![
                    &Self::ser(statechain_sig.to_owned())?,
                    &Self::ser(x1.to_owned())?,
                    &None::<Uuid>
                ],
            )
        }
    }

    fn update_transfer_msg(&self, statechain_id: &Uuid, msg: &TransferMsg3) -> Result<()> {
        let proof_key = msg.statechain_sig.data.clone();
        self.update(
            statechain_id,
            Table::Transfer,
            vec![Column::TransferMsg, Column::ProofKey],
            vec![
                &Self::ser(msg.to_owned())?,
                &proof_key.to_owned(),
            ],
        )
    }

    fn get_transfer_msg(&self, statechain_id: &Uuid) -> Result<TransferMsg3> {
        let msg = self.get_1(
            statechain_id.to_owned(),
            Table::Transfer,
            vec![Column::TransferMsg],
        )?;
        Self::deser(msg)
    }

    fn get_transfer_msg_addr(&self, receive_addr: &str) -> Result<Vec<TransferMsg3>> {
        let dbr = self.database_r()?;
        let statement =
            dbr.prepare(&format!("SELECT * FROM {} WHERE proofkey = $1", Table::Transfer.to_string(),))?;
        let rows = statement.query(&[&receive_addr])?;
        let mut msg_vec = vec![];
        for row in &rows {
            let msg: TransferMsg3 = Self::deser(row.get("transfermsg"))?;     
            msg_vec.push(msg);       
        }
        Ok(msg_vec)
    }

    fn create_transfer_batch_data(
        &self,
        batch_id: &Uuid,
        state_chains: Vec<Uuid>,
    ) -> Result<()> {
        self.insert(&batch_id, Table::TransferBatch)?;
        self.update(
            batch_id,
            Table::TransferBatch,
            vec![
                Column::StartTime,
                Column::StateChains,
                Column::PunishedStateChains,
                Column::Finalized,
            ],
            vec![
                &get_time_now(),
                &Self::ser(state_chains)?,
                &Self::ser(Vec::<String>::new())?,
                &false,
            ],
        )
    }

    fn get_transfer_data(&self, statechain_id: Uuid) -> Result<TransferData> {
        let (statechain_id, statechain_sig_str, x1_str, batch_id) = self.get_4::<Uuid, String, String, Option<Uuid>>(
            statechain_id,
            Table::Transfer,
            vec![Column::Id, Column::StateChainSig, Column::X1, Column::BatchId],
        )?;

        let statechain_sig: StateChainSig = Self::deser(statechain_sig_str)?;
        let x1: FE = Self::deser(x1_str)?;

        return Ok(TransferData {
            statechain_id,
            statechain_sig,
            x1,
            batch_id,
        });
    }

    fn remove_transfer_data(&self, statechain_id: &Uuid) -> Result<()> {
        self.remove(statechain_id, Table::Transfer)
    }

    fn transfer_is_completed(&self, statechain_id: Uuid) -> bool {
        self.get_1::<Uuid>(statechain_id, Table::Transfer, vec![Column::Id])
            .is_ok()
    }

    fn get_public_master(&self, user_id: Uuid) -> Result<Option<String>> {
        self.get_1::<Option<String>>(user_id, Table::UserSession, vec![Column::MasterPublic])
    }

    fn update_public_master(&self, user_id: &Uuid, master_public: Party1Public) -> Result<()> {
        self.update(
            user_id,
            Table::UserSession,
            vec![Column::MasterPublic],
            vec![&Self::ser(master_public)?],
        )
    }

    fn get_statecoin_pubkey(&self, statechain_id: Uuid) -> Result<Option<String>> {
        self.get_1::<Option<String>>(statechain_id, Table::StateChain, vec![Column::SharedPublic])
    }

    fn get_shared_pubkey(&self, user_id: Uuid) -> Result<Option<String>> {
        self.get_1::<Option<String>>(user_id, Table::UserSession, vec![Column::SharedPublic])
    }

    fn update_shared_pubkey(&self, user_id: Uuid, pubkey: GE) -> Result<()> {
        self.update(
            &user_id,
            Table::UserSession,
            vec![Column::SharedPublic],
            vec![&Self::ser(pubkey)?],
        )
    }

    fn set_shared_pubkey(&self, statechain_id: Uuid, pubkey: &String) -> Result<()> {
        self.update(
            &statechain_id,
            Table::StateChain,
            vec![Column::SharedPublic],
            vec![pubkey],
        )
    }

    fn get_ecdsa_master(&self, user_id: Uuid) -> Result<Option<String>> {
        self.get_1::<Option<String>>(user_id, Table::Ecdsa, vec![Column::Party1MasterKey])
    }

    //kms::ecdsa::two_party::MasterKey1
    fn update_ecdsa_master(&self, user_id: &Uuid, master_key: MasterKey1) -> Result<()> {
        self.update(
            user_id,
            Table::Ecdsa,
            vec![Column::Party1MasterKey],
            vec![&Self::ser(master_key)?],
        )
    }

    fn get_ecdsa_master_key_input(&self, user_id: Uuid) -> Result<ECDSAMasterKeyInput> {
        let (party2_public_str, paillier_key_pair_str, party_one_private_str, comm_witness_str) =
            self.get_4::<String, String, String, String>(
                user_id,
                Table::Ecdsa,
                vec![
                    Column::Party2Public,
                    Column::PaillierKeyPair,
                    Column::Party1Private,
                    Column::CommWitness,
                ],
            )?;

        let party2_public: GE = Self::deser(party2_public_str)?;
        let paillier_key_pair: party_one::PaillierKeyPair = Self::deser(paillier_key_pair_str)?;
        let party_one_private: party_one::Party1Private = Self::deser(party_one_private_str)?;
        let comm_witness: party_one::CommWitness = Self::deser(comm_witness_str)?;

        Ok(ECDSAMasterKeyInput {
            party2_public,
            paillier_key_pair,
            party_one_private,
            comm_witness,
        })
    }

    fn get_ecdsa_witness_keypair(
        &self,
        user_id: Uuid,
    ) -> Result<(party_one::CommWitness, party_one::EcKeyPair)> {
        let (comm_witness_str, ec_key_pair_str) = self.get_2::<String, String>(
            user_id,
            Table::Ecdsa,
            vec![Column::CommWitness, Column::EcKeyPair],
        )?;
        let comm_witness: party_one::CommWitness = Self::deser(comm_witness_str)?;
        let ec_key_pair: party_one::EcKeyPair = Self::deser(ec_key_pair_str)?;
        Ok((comm_witness, ec_key_pair))
    }

    fn get_ecdsa_s2(&self, user_id: Uuid) -> Result<FE> {
        let s2_str = self.get_1(user_id, Table::UserSession, vec![Column::S2])?;
        let s2: FE = Self::deser(s2_str)?;
        Ok(s2)
    }

    fn update_keygen_first_msg_and_witness(
        &self,
        user_id: &Uuid,
        key_gen_first_msg: &party_one::KeyGenFirstMsg,
        comm_witness: party_one::CommWitness,
        ec_key_pair: party_one::EcKeyPair,
    ) -> Result<()> {
        self.update(
            user_id,
            Table::Ecdsa,
            vec![
                Column::POS,
                Column::KeyGenFirstMsg,
                Column::CommWitness,
                Column::EcKeyPair,
            ],
            vec![
                &Self::ser(HDPos { pos: 0u32 })?,
                &Self::ser(key_gen_first_msg.to_owned())?,
                &Self::ser(comm_witness)?,
                &Self::ser(ec_key_pair)?,
            ],
        )?;

        Ok(())
    }


  fn update_keygen_first_msg(
        &self,
        user_id: &Uuid,
        key_gen_first_msg: &party_one::KeyGenFirstMsg
    ) -> Result<()> {
        self.update(
            user_id,
            Table::Ecdsa,
            vec![
                Column::KeyGenFirstMsg,
            ],
            vec![
                &Self::ser(key_gen_first_msg.to_owned())?,
            ],
        )?;
        Ok(())
    }

    fn get_keygen_first_msg(
        &self,
        user_id: &Uuid
    ) -> Result<party_one::KeyGenFirstMsg> {
        Self::deser(self.get_1(*user_id, Table::Ecdsa, vec![Column::KeyGenFirstMsg])?)
    }

  fn set_keygen_second_msg(
        &self,
        user_id: &Uuid,
        key_gen_second_msg: &party1::KeyGenParty1Message2
    ) -> Result<()> {
        self.update(
            user_id,
            Table::Ecdsa,
            vec![
                Column::KeyGenSecondMsg,
            ],
            vec![
                &Self::ser(key_gen_second_msg.to_owned())?,
            ],
        )?;
        Ok(())
    }

    fn get_keygen_second_msg(
        &self,
        user_id: &Uuid
    ) -> Result<party1::KeyGenParty1Message2> {
        Self::deser(self.get_1(*user_id, Table::Ecdsa, vec![Column::KeyGenSecondMsg])?)
    }

    fn update_keygen_second_msg(
        &self,
        user_id: &Uuid,
        party2_public: GE,
        paillier_key_pair: party_one::PaillierKeyPair,
        party_one_private: party_one::Party1Private,
    ) -> Result<()> {
        self.update(
            user_id,
            Table::Ecdsa,
            vec![
                Column::Party2Public,
                Column::PaillierKeyPair,
                Column::Party1Private,
            ],
            vec![
                &Self::ser(party2_public)?,
                &Self::ser(paillier_key_pair)?,
                &Self::ser(party_one_private)?,
            ],
        )?;
        Ok(())
    }

    fn init_ecdsa(&self, user_id: &Uuid) -> Result<u64> {
        self.insert(user_id, Table::Ecdsa)
    }

    fn get_ecdsa_party_1_private(&self, user_id: Uuid) -> Result<party_one::Party1Private> {
        Self::deser(self.get_1(user_id, Table::Ecdsa, vec![Column::Party1Private])?)
    }

    fn get_ecdsa_keypair(&self, user_id: Uuid) -> Result<ECDSAKeypair> {
        let (party_1_private_str, party_2_public_str) = self.get_2::<String, String>(
            user_id,
            Table::Ecdsa,
            vec![Column::Party1Private, Column::Party2Public],
        )?;

        let party_1_private: Party1Private = Self::deser(party_1_private_str)?;
        let party_2_public: GE = Self::deser(party_2_public_str)?;
        Ok(ECDSAKeypair {
            party_1_private,
            party_2_public,
        })
    }

    fn update_punished(&self, batch_id: &Uuid, punished_state_chains: Vec<Uuid>) -> Result<()> {
        self.update(
            batch_id,
            Table::TransferBatch,
            vec![Column::PunishedStateChains],
            vec![&Self::ser(punished_state_chains)?],
        )
    }

    fn get_transfer_batch_start_time(&self, batch_id: &Uuid) -> Result<NaiveDateTime> {
        self.get_1::<NaiveDateTime>(
            batch_id.to_owned(),
            Table::TransferBatch,
            vec![Column::StartTime],
        )
    }

    fn get_batch_transfer_statechain_ids(&self, batch_id: &Uuid) -> Result<HashSet<Uuid>>{
        let statechain_ids = self.get_1(
            batch_id.to_owned(),
            Table::TransferBatch,
            vec![Column::StateChains],
        )?;
        Self::deser(statechain_ids)
    }

    fn get_finalize_batch_data(&self, batch_id: Uuid) -> Result<TransferFinalizeBatchData> {
        let mut finalized_data_vec = vec![];

        for id in self.get_batch_transfer_statechain_ids(&batch_id)? {
            match self.get_sc_transfer_finalize_data(&id){
                Ok(v) => {
                    //Check the batch id
                    match v.batch_data {
                        Some(ref bd) => {
                            if bd.id == batch_id{
                                finalized_data_vec.push(v);
                            } else {
                                return Err(SEError::DBError(NoDataForID,
                                    format!("batch_id required:{}, found:{}", batch_id, bd.id)))
                            }
                        },
                        None => return Err(SEError::DBError(NoDataForID,
                                    format!("no batch data"))),
                    }
                },
                Err(e) => return Err(e),
            };
        }

        let start_time = self.get_transfer_batch_start_time(&batch_id)?;

        Ok(TransferFinalizeBatchData {
            finalized_data_vec,
            start_time,
        })
    }

    fn update_finalize_batch_data(
        &self,
        statechain_id: &Uuid,
        finalized_data: &TransferFinalizeData,
    ) -> Result<()> {
        self.update(
            statechain_id,
            Table::StateChain,
            vec![Column::TransferFinalizeData],
            vec![&Self::ser(finalized_data)?],
        )
    }

    fn get_sc_transfer_finalize_data(
        &self,
        statechain_id: &Uuid
    ) -> Result<TransferFinalizeData> {
        let tfd = self.get_1(statechain_id.to_owned(),
            Table::StateChain, vec![Column::TransferFinalizeData])?;
        Self::deser(tfd)
    }

    fn update_transfer_batch_finalized(&self, batch_id: &Uuid, b_finalized: &bool) -> Result<()> {
        self.update(
            batch_id,
            Table::TransferBatch,
            vec![Column::Finalized],
            vec![b_finalized],
        )
    }

    fn get_statechain_owner(&self, statechain_id: Uuid) -> Result<StateChainOwner> {
        let (locked_until, owner_id, state_chain_str) = self.get_3::<NaiveDateTime, Uuid, String>(
            statechain_id,
            Table::StateChain,
            vec![Column::LockedUntil, Column::OwnerId, Column::Chain],
        )?;

        let chain: StateChain = 
            Self::deser::<StateChainUnchecked>(state_chain_str)?.try_into()?;
        Ok(StateChainOwner {
            locked_until,
            owner_id,
            chain,
        })
    }

    // find statecoin and user information from supplied proof key to enable wallet recovery
    fn get_recovery_data(&self, proofkey: String) -> Result<Vec<(Uuid,Option<Uuid>,Option<Transaction>)>> {
        let dbr = self.database_r()?;
        let statement =
            dbr.prepare(&format!("SELECT * FROM {} WHERE proofkey = $1", Table::UserSession.to_string(),))?;
        let rows = statement.query(&[&proofkey])?;
        if rows.is_empty() {
            return Err(SEError::DBError(NoDataForID, String::from("Proof key")));
        };
        let mut rc_vec = vec![];
        for row in &rows {
            let statechain_id: Option<Uuid> = row.get("statechainid");
            if let Some(sid) = statechain_id {
                let user_id: Uuid = row.get("id");
                let owner_id = self.get_1::<Uuid>(sid, Table::StateChain, vec![Column::OwnerId])?;
                if (owner_id == user_id) {
                    let tx_backup_str = self.get_1::<String>(sid, Table::BackupTxs, vec![Column::TxBackup])?;
                    let tx_backup: Transaction = Self::deser(tx_backup_str)?;
                    rc_vec.push((user_id,Some(sid),Some(tx_backup)))
                }
            } else {
                let user_id: Uuid = row.get("id");
                rc_vec.push((user_id,None,None))
            }
        }

        Ok(rc_vec)
    }

    // Create DB entry for newly generated ID signalling that user has passed some
    // verification. For now use ID as 'password' to interact with state entity
    fn create_user_session(&self, user_id: &Uuid, auth: &String, 
        proof_key: &String, challenge: &String,
        user_ids: Arc<Mutex<UserIDs>>) -> Result<()> {
        let mut guard = user_ids.as_ref().lock()?;
        guard.insert(user_id.to_owned());
        self.insert(user_id, Table::UserSession).map_err(|e| { guard.remove(user_id); e })?;
        self.insert(user_id, Table::Lockbox).map_err(|e| { 
            guard.remove(user_id); 
            let _ = self.remove(user_id, Table::UserSession); 
            e
         })?;
        self.update(
            user_id,
            Table::UserSession,
            vec![Column::Authentication, Column::ProofKey, Column::Challenge],
            vec![&auth.clone(), &proof_key.to_owned(), &challenge.clone()],
        ).map_err(|e| { 
            guard.remove(user_id); 
            let _ = self.remove(user_id, Table::UserSession);
            let _ = self.remove(user_id, Table::Lockbox);
            e
         })?;
        Ok(())
    }

    // Create new UserSession to allow new owner to generate shared wallet
    fn transfer_init_user_session(
        &self,
        new_user_id: &Uuid,
        statechain_id: &Uuid,
        finalized_data: TransferFinalizeData,
        user_ids: Arc<Mutex<UserIDs>>
    ) -> Result<()> {
        let mut guard = user_ids.as_ref().lock()?;
        guard.insert(new_user_id.clone());
        self.insert(new_user_id, Table::UserSession).map_err(|e| { 
            guard.remove(new_user_id); 
            e
         })?;
        self.insert(new_user_id, Table::Lockbox).map_err(|e| { 
            guard.remove(new_user_id); 
            let _ = self.remove(new_user_id, Table::UserSession);
            e
         })?;
        self.update(
            new_user_id,
            Table::UserSession,
            vec![
                Column::Authentication,
                Column::ProofKey,
                Column::TxBackup,
                Column::StateChainId,
                Column::S2,
            ],
            vec![
                &String::from("auth"),
                &finalized_data.statechain_sig.data.to_owned(),
                &Self::ser(transaction_deserialise(&finalized_data.new_tx_backup_hex)?)?,
                &statechain_id,
                &Self::ser(finalized_data.s2)?,
            ],
        ).map_err(|e| { 
            guard.remove(new_user_id); 
            let _ = self.remove(new_user_id, Table::UserSession);
            let _ = self.remove(new_user_id, Table::Lockbox);
            e
         })?;
         Ok(())
    }

    fn update_ecdsa_sign_first(
        &self,
        user_id: Uuid,
        eph_key_gen_first_message_party_two: party_two::EphKeyGenFirstMsg,
        eph_ec_key_pair_party1: party_one::EphEcKeyPair,
    ) -> Result<()> {
        self.update(
            &user_id,
            Table::Ecdsa,
            vec![Column::EphKeyGenFirstMsg, Column::EphEcKeyPair],
            vec![
                &Self::ser(eph_key_gen_first_message_party_two)?,
                &Self::ser(eph_ec_key_pair_party1)?,
            ],
        )?;
        Ok(())
    }

    fn get_ecdsa_sign_second_input(&self, user_id: Uuid) -> Result<ECDSASignSecondInput> {
        let (shared_key_str, eph_ec_key_pair_party1_str, eph_key_gen_first_message_party_two_str) =
            self.get_3::<String, String, String>(
                user_id,
                Table::Ecdsa,
                vec![
                    Column::Party1MasterKey,
                    Column::EphEcKeyPair,
                    Column::EphKeyGenFirstMsg,
                ],
            )?;

        let shared_key: MasterKey1 = Self::deser(shared_key_str)?;
        let eph_ec_key_pair_party1: party_one::EphEcKeyPair =
            Self::deser(eph_ec_key_pair_party1_str)?;
        let eph_key_gen_first_message_party_two: party_two::EphKeyGenFirstMsg =
            Self::deser(eph_key_gen_first_message_party_two_str)?;

        // pub struct ECDSASignSecondInput {
        //     pub shared_key: MasterKey1,
        //     pub eph_ec_key_pair_party1: party_one::EphEcKeyPair,
        //     pub eph_key_gen_first_message_party_two: party_two::EphKeyGenFirstMsg,
        // }

        Ok(ECDSASignSecondInput {
            shared_key,
            eph_ec_key_pair_party1,
            eph_key_gen_first_message_party_two,
        })
    }

    fn get_tx_withdraw(&self, user_id: Uuid) -> Result<Transaction> {
        Self::deser(self.get_1(user_id, Table::UserSession, vec![Column::TxWithdraw])?)
    }

    fn update_tx_withdraw(&self, user_id: Uuid, tx: Transaction) -> Result<()> {
        self.update(
            &user_id,
            Table::UserSession,
            vec![Column::TxWithdraw],
            vec![&Self::ser(tx)?],
        )
    }
}