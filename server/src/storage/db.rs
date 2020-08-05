//! DB
//!
//! Postgres DB access and update tools.

use mockall::*;
use mockall::predicate::*;
use bitcoin::Transaction;
use super::super::Result;
use super::super::StateChainEntity;

use rocksdb::{Options, DB};
use rocket_contrib::databases::r2d2_postgres::{PostgresConnectionManager, TlsMode};

use crate::{
    error::{
        DBErrorType::{NoDataForID, UpdateFailed},
        SEError,
    },
    DatabaseR, DatabaseW, Database 
};
use rocket_contrib::databases::postgres::{rows::Row, types::ToSql};
use shared_lib::mainstay;
use mainstay::{Attestable, CommitmentInfo};
use shared_lib::{Root, structs::*, state_chain::*};
use uuid::Uuid;
#[cfg(test)]
use mockito::{mock, Matcher, Mock};
use rocket_contrib::databases::r2d2;
use crate::server::get_postgres_url;
use crate::protocol::transfer::TransferFinalizeData;
use chrono::NaiveDateTime;
use std::collections::HashMap;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one::Party1Private;

pub type Hash = bitcoin::hashes::sha256d::Hash;

use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    {BigInt, FE, GE},
};

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

#[derive(Debug, Deserialize, Clone, Copy)]
pub enum Column {
    Data,
    Complete,

    // UserSession
    Id,
    Authentication,
    ProofKey,
    StateChainId,
    TxBackup,
    TxWithdraw,
    SigHash,
    S2,
    WithdrawScSig,

    // StateChain
    // Id,
    Chain,
    Amount,
    LockedUntil,
    OwnerId,

    // BackupTxs
    //Id,
    // TxBackup,

    // Transfer
    // Id,
    StateChainSig,
    X1,

    // TransferBatch
    // Id,
    StartTime,
    StateChains,
    FinalizedData,
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
    PDLProver,
    PDLDecommit,
    Alpha,
    Party2PDLFirstMsg,
    Party1MasterKey,
    EphEcKeyPair,
    EphKeyGenFirstMsg,
    POS,

    // Root
    // Id,
    Value,
    CommitmentInfo,
}

impl Column {
    pub fn to_string(&self) -> String {
        format!("{:?}", self)
    }
}

 #[automock]
impl Database {

    pub fn new(con_fun: fn()->r2d2::PooledConnection<PostgresConnectionManager>)
        -> Self {
        Self{ db_connection: con_fun}
    }

    pub fn get_test() -> Self {
        Self::new(Self::get_test_postgres_connection)
    }

    pub fn get_user_auth(&self, user_id: &Uuid) -> Result<Uuid>{
        self.get_1::<Uuid>(user_id, Table::UserSession, vec![Column::Id])
    }
    
    pub fn get_test_postgres_connection() -> r2d2::PooledConnection<PostgresConnectionManager> {
        let rocket_url = get_postgres_url("TEST".to_string());
        let manager = PostgresConnectionManager::new(rocket_url, TlsMode::None).unwrap();
        r2d2::Pool::new(manager).unwrap().get().unwrap()
    }

    fn database_r(&self) -> DatabaseR {
        DatabaseR((self.db_connection)())
    }

    fn database_w(&self) -> DatabaseW {
        DatabaseW((self.db_connection)())
    }
   
    pub fn has_withdraw_sc_sig(&self, user_id: &Uuid) -> Result<()> {
        match self.get_1::<String>(
            &user_id,
            Table::UserSession,
            vec![Column::WithdrawScSig],
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(e)
        }
    }

    pub fn update_withdraw_sc_sig(&self, user_id: &Uuid, sig: &'static StateChainSig) -> Result<()> {
        self.update(
            user_id,
            Table::UserSession,
            vec![Column::WithdrawScSig],
            vec![&Self::ser(sig)?],
        )
    }

    pub fn update_withdraw_tx_sighash(&self, user_id: &Uuid, sig_hash: &'static Hash, tx: &'static Transaction) -> Result<()>{
        self.update(
            user_id,
            Table::UserSession,
            vec![Column::SigHash, Column::TxWithdraw],
            vec![&Self::ser(sig_hash)?, &Self::ser(tx)?],
        )
    }

    pub fn update_sighash(&self, user_id: &Uuid, sig_hash: &'static Hash) -> Result<()> {
        self.update(
            user_id,
            Table::UserSession,
            vec![Column::SigHash],
            vec![&Self::ser(sig_hash)?],
        )
    }

    pub fn update_user_backup_tx(&self,user_id: &Uuid, tx: &'static Transaction) -> Result<()> {
        self.update(
            user_id,
            Table::UserSession,
            vec![Column::TxBackup],
            vec![&Self::ser(tx)?],
        )
    }

    pub fn update_backup_tx(&self,state_chain_id: &Uuid, tx: &'static Transaction) -> Result<()> {
        self.update(
            &state_chain_id,
            Table::BackupTxs,
            vec![Column::TxBackup],
            vec![&Self::ser(tx)?],
        )
    }

    pub fn get_withdraw_confirm_data(&self, user_id: &Uuid) -> Result<WithdrawConfirmData> {
        let (tx_withdraw_str, withdraw_sc_sig_str, state_chain_id) =
        self.get_3::<String, String, Uuid>(
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
        Ok(WithdrawConfirmData{tx_withdraw, withdraw_sc_sig, state_chain_id})
    }

    /// Build DB tables and Schemas
    pub fn make_tables(&self) -> Result<()> {
    // Create Schemas if they do not already exist
    let _ = self.database_w().execute(
        &format!(
            "
        CREATE SCHEMA IF NOT EXISTS statechainentity;",
        ),
        &[],
    )?;
    let _ = self.database_w().execute(
        &format!(
            "
        CREATE SCHEMA IF NOT EXISTS watcher;",
        ),
        &[],
    )?;

    // Create tables if they do not already exist
    self.database_w().execute(
        &format!(
            "
        CREATE TABLE IF NOT EXISTS {} (
            id uuid NOT NULL,
            statechainid uuid,
            authentication varchar,
            s2 varchar,
            sighash varchar,
            withdrawscsig varchar,
            txwithdraw varchar,
            proofkey varchar,
            txbackup varchar,
            PRIMARY KEY (id)
        );",
            Table::UserSession.to_string(),
        ),
        &[],
    )?;

    self.database_w().execute(
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
            pdldecommit varchar,
            alpha varchar,
            party2pdlfirstmsg varchar,
            party1masterkey varchar,
            pos varchar,
            epheckeypair varchar,
            ephkeygenfirstmsg varchar,
            complete bool NOT NULL DEFAULT false,
            PRIMARY KEY (id)
        );",
            Table::Ecdsa.to_string(),
        ),
        &[],
    )?;

    self.database_w().execute(
        &format!(
            "
        CREATE TABLE IF NOT EXISTS {} (
            id uuid NOT NULL,
            chain varchar,
            amount int8,
            ownerid uuid,
            lockeduntil timestamp,
            PRIMARY KEY (id)
        );",
            Table::StateChain.to_string(),
        ),
        &[],
    )?;

    self.database_w().execute(
        &format!(
            "
        CREATE TABLE IF NOT EXISTS {} (
            id uuid NOT NULL,
            statechainsig varchar,
            x1 varchar,
            PRIMARY KEY (id)
        );",
            Table::Transfer.to_string(),
        ),
        &[],
    )?;

    self.database_w().execute(
        &format!(
            "
        CREATE TABLE IF NOT EXISTS {} (
            id uuid NOT NULL,
            starttime timestamp,
            statechains varchar,
            finalizeddata varchar,
            punishedstatechains varchar,
            finalized bool,
            PRIMARY KEY (id)
        );",
            Table::TransferBatch.to_string(),
        ),
        &[],
    )?;

    self.database_w().execute(
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

    self.database_w().execute(
        &format!(
            "
        CREATE TABLE IF NOT EXISTS {} (
            id uuid NOT NULL,
            txbackup varchar,
            PRIMARY KEY (id)
        );",
            Table::BackupTxs.to_string(),
        ),
        &[],
    )?;

    Ok(())
}

#[allow(dead_code)]
/// Drop all DB tables and Schemas.
fn drop_tables(&self) -> Result<()> {
    let _ = self.database_w().execute(
        &format!(
            "
        DROP SCHEMA statechainentity CASCADE;",
        ),
        &[],
    )?;
    let _ = self.database_w().execute(
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
    self.database_w().execute(
        &format!(
            "
        TRUNCATE {},{},{},{},{},{},{} RESTART IDENTITY;",
            Table::UserSession.to_string(),
            Table::Ecdsa.to_string(),
            Table::StateChain.to_string(),
            Table::Transfer.to_string(),
            Table::TransferBatch.to_string(),
            Table::Root.to_string(),
            Table::BackupTxs.to_string(),
        ),
        &[],
    )?;
    Ok(())
}

pub fn reset_dbs(&self, smt_db_loc: &String) -> Result<()> {
    // truncate all postgres tables
    self.truncate_tables()?;

    // Destroy Sparse Merkle Tree RocksDB instance
    let _ = DB::destroy(&Options::default(), smt_db_loc); // ignore error
    Ok(())
}

/// Serialize data into string. To add custom types to Postgres they must be serialized to String.
pub fn ser<T:'static>(data: T) -> Result<String>
where
    T: serde::ser::Serialize,
{
    match serde_json::to_string(&data) {
        Ok(v) => Ok(v),
        Err(_) => Err(SEError::Generic(String::from("Failed to serialize data."))),
    }
}

/// Deserialize custom type data from string. Reverse of ser().
pub fn deser<T:'static>(data: String) -> Result<T>
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
    let statement = self.database_w().prepare(&format!(
        "INSERT INTO {} (id) VALUES ($1)",
        table.to_string()
    ))?;

    Ok(statement.execute(&[id])?)
}

/// Remove row in table
pub fn remove(&self, id: &Uuid, table: Table) -> Result<()> {
    let statement =
        self.database_w().prepare(&format!("DELETE FROM {} WHERE id = $1;", table.to_string()))?;
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
    let statement = self.database_w().prepare(&format!(
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
fn get<T:'static, U:'static, V:'static, W:'static>(
    &self,
    id: &Uuid,
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
    let statement = self.database_r().prepare(&format!(
        "SELECT {} FROM {} WHERE id = $1",
        self.get_columns_str(&column),
        table.to_string(),
    ))?;

    let rows = statement.query(&[id])?;
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

fn get_item_from_row<T:'static>(&self, row: &'static Row<'static>, index: usize, id: &String, column: Column) -> Result<T>
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
pub fn get_1<T:'static>(&self, id: &Uuid, table: Table, column: Vec<Column>) -> Result<T>
where
    T: rocket_contrib::databases::postgres::types::FromSql,
{
    let (res, _, _, _) = self.get::<T, T, T, T>(id, table, column)?;
    Ok(res.unwrap())  //  err returned from db_get if desired item is None
}
/// Get 2 items from row in table. Err if ID not found. Return None if data item empty.
pub fn get_2<T:'static, U:'static>(
    &self,
    id: &Uuid,
    table: Table,
    column: Vec<Column>,
) -> Result<(T, U)>
where
    T: rocket_contrib::databases::postgres::types::FromSql,
    U: rocket_contrib::databases::postgres::types::FromSql,
{
    let (res1, res2, _, _) = self.get::<T, U, U, U>(id, table, column)?;
    Ok((res1.unwrap(), res2.unwrap()))
}
/// Get 3 items from row in table. Err if ID not found. Return None if data item empty.
pub fn get_3<T:'static, U:'static, V:'static>(
    &self,
    id: &Uuid,
    table: Table,
    column: Vec<Column>,
) -> Result<(T, U, V)>
where
    T: rocket_contrib::databases::postgres::types::FromSql,
    U: rocket_contrib::databases::postgres::types::FromSql,
    V: rocket_contrib::databases::postgres::types::FromSql,
{
    let (res1, res2, res3, _) = self.get::<T, U, V, V>(id, table, column)?;
    Ok((res1.unwrap(), res2.unwrap(), res3.unwrap()))
}
/// Get 4 items from row in table. Err if ID not found. Return None if data item empty.
pub fn get_4<T:'static, U:'static, V:'static, W:'static>(
    &self,
    id: &Uuid,
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

/// Update root value in DB. Update root with ID or insert new DB item.
pub fn root_update(&self, rt: &Root) -> Result<i64> {
    let mut root = rt.clone();
    // Get previous ID, or use the one specified in root to update an existing root with mainstay proof
    let id = match root.id() {
        //This will update an existing root in the db
        Some(id) => {
            let existing_root = self.get_root(&(id as i64))?;
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
    self.root_insert(&root)?;

    debug!("Updated root at id {} with value: {:?}", id, root);
    Ok(id)
}

/// Insert a Root into root table
pub fn root_insert(&self, root: &'static Root) -> Result<u64> {
    let statement = self.database_w().prepare(&format!(
        "INSERT INTO {} (value, commitmentinfo) VALUES ($1,$2)",
        Table::Root.to_string()
    ))?;
    Ok(statement.execute(&[&Database::ser(root.hash())?, &Database::ser(root.commitment_info())?])?)
}

/// Get Id of current Root
pub fn root_get_current_id(&self) -> Result<i64> {
    let statement =
        self.database_r().prepare(&format!("SELECT MAX(id) FROM {}", Table::Root.to_string(),))?;
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

/// Get root with given ID
pub fn get_root(&self, id: &i64) -> Result<Option<Root>> {
    if id == &0 {
        return Ok(None);
    }
    let statement = self.database_r().prepare(&format!(
        "SELECT * FROM {} WHERE id = $1",
        Table::Root.to_string(),
    ))?;
    let rows = statement.query(&[id])?;
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
        Database::deser(self.get_item_from_row::<String>(
            &row,
            1,
            &id.to_string(),
            Column::Value,
        )?)?,
        &Database::deser::<Option<CommitmentInfo>>(self.get_item_from_row::<String>(
            &row,
            2,
            &id.to_string(),
            Column::CommitmentInfo,
        )?)?,
    )?;
    Ok(Some(root))
}

/// Find the latest confirmed root
pub fn get_confirmed_smt_root(&self) -> Result<Option<Root>> {
    let current_id = self.root_get_current_id()?;
    for i in 0..=current_id - 1 {
        let id = current_id - i;
        let root = self.get_root(&id)?;
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

pub fn get_statechain_id(&self, user_id: &Uuid) -> Result<Uuid>{
    self.get_1::<Uuid>(
        &user_id,
        Table::UserSession,
        vec![Column::StateChainId],
    )
}

pub fn update_statechain_id(&self, user_id: &Uuid, state_chain_id: &Uuid)
->Result<()> {
    self.update(
        user_id,
        Table::UserSession,
        vec![Column::StateChainId],
        vec![state_chain_id],
    )
}

pub fn get_statechain_amount(
    &self,
    state_chain_id: &Uuid,
) -> Result<StateChainAmount> {
    let (amount, state_chain_str) = self.get_2::<i64, String>(
        &state_chain_id,
        Table::StateChain,
        vec![Column::Amount, Column::Chain],
    )?;
    let state_chain: StateChain = Self::deser(state_chain_str)?;
    Ok(StateChainAmount{chain: state_chain, amount})
}

pub fn update_statechain_amount(&self, state_chain_id: &Uuid, state_chain: &'static StateChain, amount: u64) -> Result<()> {
    self.update(
        &state_chain_id,
        Table::StateChain,
        vec![Column::Chain, Column::Amount],
        vec![&Self::ser(state_chain)?, &(amount as i64)], // signals withdrawn funds
    )
}

pub fn create_statechain(&self, 
    state_chain_id: &Uuid, 
    user_id: &Uuid, 
    state_chain: &StateChain,
    amount: &i64) -> Result<()>{
        self.insert(&state_chain_id, Table::StateChain)?;
        self.update(
            &state_chain_id,
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
        )
}

pub fn get_statechain(
    &self,
    state_chain_id: &Uuid,
) -> Result<StateChain> {
    let (amount, state_chain_str) = self.get_2::<i64, String>(
        &state_chain_id,
        Table::StateChain,
        vec![Column::Amount, Column::Chain],
    )?;
    let state_chain: StateChain = Self::deser(state_chain_str)?;
    Ok(state_chain)
}

pub fn update_statechain_owner(&self, state_chain_id: &Uuid, 
                        state_chain: &'static StateChain, new_user_id: &Uuid) 
                        -> Result<()> {  
    self.update(
        &state_chain_id,
        Table::StateChain,
        vec![Column::Chain, Column::OwnerId],
        vec![
            &Self::ser(state_chain)?,
            &new_user_id,
        ],
    )
}

 // Remove state_chain_id from user session to signal end of session
pub fn remove_statechain_id(&self, user_id: &Uuid) -> Result<()> {
    self.update(
        user_id,
        Table::UserSession,
        vec![Column::StateChainId],
        vec![&Uuid::nil()],
    )
}

pub fn create_backup_transaction(&self, 
    state_chain_id: &Uuid,
    tx_backup: &Transaction) -> Result<()> {
        self.insert(state_chain_id, Table::BackupTxs)?;
        self.update(
            state_chain_id,
            Table::BackupTxs,
            vec![Column::TxBackup],
            vec![&Self::ser(tx_backup.clone())?],
        )
}

pub fn get_backup_transaction(&self, state_chain_id: &Uuid) -> Result<Transaction> {
    let (tx_backup_str) = self.get_1::<String>(
        state_chain_id,
        Table::BackupTxs,
        vec![Column::TxBackup],
    )?;
    let tx_backup: Transaction = Self::deser(tx_backup_str)?;
    Ok(tx_backup)
}

pub fn get_backup_transaction_and_proof_key(&self, user_id: &Uuid)
-> Result<(Transaction, String)> {

    let (tx_backup_str, proof_key) = self.get_2::<String, String>(
        &user_id,
        Table::UserSession,
        vec![Column::TxBackup, Column::ProofKey],
    )?;
    let tx_backup: Transaction = Self::deser(tx_backup_str)?;
    Ok((tx_backup, proof_key))
}

    pub fn get_sc_locked_until(&self, state_chain_id: &Uuid) -> Result<NaiveDateTime>{
        self.get_1::<NaiveDateTime>(
            state_chain_id,
            Table::StateChain,
            vec![Column::LockedUntil],
        )
    }

    pub fn update_locked_until(&self, state_chain_id: &Uuid, 
                                time: &NaiveDateTime)->Result<()>{
        self.update( 
            state_chain_id,
            Table::StateChain,
            vec![Column::LockedUntil],
            vec![time]
        )
    }

    pub fn get_transfer_batch_data(&self, batch_id: &Uuid) -> Result<TransferBatchData> {
        let (state_chains_str, start_time, finalized, punished_state_chains_str) = 
        self.get_4::<String, NaiveDateTime, bool, String>(
            &batch_id,
            Table::TransferBatch,
            vec![Column::StateChains, 
                Column::StartTime, 
                Column::Finalized, 
                Column::PunishedStateChains],
        )?;
        let state_chains: HashMap<Uuid, bool> = Self::deser(state_chains_str)?;
        let punished_state_chains: Vec<Uuid> = Self::deser(punished_state_chains_str)?;
        Ok(TransferBatchData{state_chains, start_time, finalized, punished_state_chains})
    }

    pub fn has_transfer_batch_id(&self, batch_id: &Uuid) -> bool {
        self.get_transfer_batch_id(batch_id).is_ok()
    }

    pub fn get_transfer_batch_id(&self, batch_id: &Uuid) -> Result<Uuid> {
        self.get_1::<Uuid>(&batch_id, 
            Table::TransferBatch, 
            vec![Column::Id])
    }

    pub fn get_punished_state_chains(&self, batch_id: &Uuid) -> Result<Vec<Uuid>>{
        Self::deser(self.get_1(
            batch_id,
            Table::TransferBatch,
            vec![Column::PunishedStateChains],
        )?)
    }

    pub fn create_transfer(&self, state_chain_id: &Uuid,
        state_chain_sig: &StateChainSig,
        x1: &FE) -> Result<()> {
          // Create Transfer table entry
          self.insert(&state_chain_id, Table::Transfer)?;
          self.update(
              &state_chain_id,
              Table::Transfer,
              vec![Column::StateChainSig, Column::X1],
              vec![
                  &Self::ser(state_chain_sig.to_owned())?,
                  &Self::ser(x1.to_owned())?,
              ],
          )
    }

    pub fn create_transfer_batch_data(&self, 
        batch_id: &Uuid, 
        state_chains: &'static HashMap<Uuid, bool>) -> Result<()> {

        self.insert(&batch_id, Table::TransferBatch)?;
        self.update(
            &batch_id,
            Table::TransferBatch,
            vec![
                Column::StartTime,
                Column::StateChains,
                Column::FinalizedData,
                Column::PunishedStateChains,
                Column::Finalized,
            ],
            vec![
                &get_time_now(),
                &Self::ser(state_chains)?,
                &Self::ser(Vec::<TransferFinalizeData>::new())?,
                &Self::ser(Vec::<String>::new())?,
                &false,
            ],
        )
    }

    pub fn get_transfer_data(&self, state_chain_id: &Uuid) -> Result<TransferData> {
        let (state_chain_id, state_chain_sig_str, x1_str) = self.get_3::<Uuid, String, String>(
            &state_chain_id,
            Table::Transfer,
            vec![Column::Id, Column::StateChainSig, Column::X1],
        )?;

        let state_chain_sig: StateChainSig = Self::deser(state_chain_sig_str)?;
        let x1: FE = Self::deser(x1_str)?;

        return Ok(TransferData{state_chain_id, state_chain_sig, x1})
    }

    pub fn remove_transfer_data(&self, state_chain_id: &Uuid) -> Result<()>{
        self.remove(state_chain_id, Table::Transfer)
    }

    pub fn transfer_is_completed(&self, state_chain_id: &Uuid) -> bool {
        self.get_1::<Uuid>(
            &state_chain_id, 
            Table::Transfer, 
            vec![Column::Id]).is_ok() 
    }

    pub fn get_ecdsa_keypair(&self, user_id: &Uuid) -> Result<ECDSAKeypair> {

        let (party_1_private_str, party_2_public_str) = self.get_2::<String, String>(
            &user_id,
            Table::Ecdsa,
            vec![Column::Party1Private, Column::Party2Public],
        )?;

        let party_1_private: Party1Private = Self::deser(party_1_private_str)?;
        let party_2_public: GE = Self::deser(party_2_public_str)?;
        Ok(ECDSAKeypair{party_1_private, party_2_public})
    }

    pub fn update_punished(&self, batch_id: &Uuid, punished_state_chains: &'static Vec<Uuid>) -> Result<()>{
        self.update(
            batch_id,
            Table::TransferBatch,
            vec![Column::PunishedStateChains],
            vec![&Self::ser(punished_state_chains)?],
        )
    }

    pub fn get_finalize_batch_data(&self, batch_id: &Uuid)-> Result<TransferFinalizeBatchData> {
        let (state_chains_str, finalized_data_vec_str, start_time) = self.get_3::<String, String, NaiveDateTime>(
            batch_id,
            Table::TransferBatch,
            vec![Column::StateChains, Column::FinalizedData, Column::StartTime],
        )?;

        let state_chains: HashMap<Uuid, bool> = Self::deser(state_chains_str)?;
        let finalized_data_vec: Vec<TransferFinalizeData> = Self::deser(finalized_data_vec_str)?;
        Ok(TransferFinalizeBatchData{state_chains, finalized_data_vec, start_time})
    }

    pub fn update_finalize_batch_data(&self, batch_id: &Uuid, 
            state_chains:&'static HashMap<Uuid, bool>, 
            finalized_data_vec: &'static Vec<TransferFinalizeData>) -> Result<()>{
                self.update(
                    &batch_id,
                    Table::TransferBatch,
                    vec![Column::StateChains, Column::FinalizedData],
                    vec![&Self::ser(state_chains)?, &Self::ser(finalized_data_vec)?],
                )
    }

    pub fn update_transfer_batch_finalized(&self, batch_id: &Uuid, b_finalized: &bool) -> Result<()>{
        self.update(
            batch_id,
            Table::TransferBatch,
            vec![Column::Finalized],
            vec![b_finalized],
        )
    }

    pub fn get_statechain_owner(&self, state_chain_id: &Uuid) -> Result<StateChainOwner> {
        let (locked_until, owner_id, state_chain_str) = 
            self.get_3::<NaiveDateTime, Uuid, String>(
                &state_chain_id,
                Table::StateChain,
                vec![Column::LockedUntil, Column::OwnerId, Column::Chain],
            )?;

        let  chain: StateChain = Self::deser(state_chain_str)?;
        Ok(StateChainOwner{locked_until, owner_id, chain})
    }

    // Create DB entry for newly generated ID signalling that user has passed some
    // verification. For now use ID as 'password' to interact with state entity
    pub fn create_user_session(&self, user_id: &Uuid, auth: &String, 
        proof_key: &String) -> Result<()> {
            self.insert(user_id, Table::UserSession)?;
            self.update(
                &user_id,
                Table::UserSession,
                vec![Column::Authentication, Column::ProofKey],
                vec![
                    &auth.clone(),
                    &proof_key.to_owned(),
                ],
            )
    }



    // Create new UserSession to allow new owner to generate shared wallet
    pub fn transfer_init_user_session(&self, new_user_id: &Uuid,
        state_chain_id: &Uuid, 
        finalized_data: &TransferFinalizeData) -> Result<()> {
    
        self.insert(new_user_id, Table::UserSession)?;
        self.update(
            &new_user_id,
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
                &finalized_data.state_chain_sig.data.to_owned(),
                &Self::ser(finalized_data.new_tx_backup)?,
                &state_chain_id,
                &Self::ser(finalized_data.s2)?,
            ],
        )
    }
}

pub struct StateChainAmount {
    pub chain: StateChain,
    pub amount: i64,
}

struct TransferBatchData {
    pub state_chains: HashMap<Uuid, bool>,
    pub punished_state_chains: Vec<Uuid>,
    pub start_time: NaiveDateTime,
    pub finalized: bool,
}

struct TransferFinalizeBatchData {
    pub state_chains: HashMap<Uuid, bool>,
    pub finalized_data_vec: Vec<TransferFinalizeData>,
    pub start_time: NaiveDateTime,
}

pub struct StateChainOwner {
    pub locked_until: NaiveDateTime,
    pub owner_id: Uuid,
    pub chain: StateChain,
}

pub struct WithdrawConfirmData {
    pub tx_withdraw: Transaction,
    pub withdraw_sc_sig: StateChainSig,
    pub state_chain_id: Uuid,
}

pub struct TransferData {
    pub state_chain_id: Uuid,
    pub state_chain_sig: StateChainSig,
    pub x1: FE,
}

pub struct ECDSAKeypair {
    pub party_1_private: Party1Private,
    pub party_2_public: GE
}