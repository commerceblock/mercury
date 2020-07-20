//! DB
//!
//! Postgres DB access and update tools.

use super::super::Result;
use crate::error::{DBErrorType::{UpdateFailed,NoDataForID}, SEError};
use rocket_contrib::databases::postgres::{Connection,
    types::ToSql,
    rows::Row};
use uuid::Uuid;


#[derive(Debug)]
pub enum Schema {
    StateChainEntity,
    Watcher
}
impl Schema {
    pub fn to_string(&self) -> String {
        format!("{:?}", self)
    }
}

#[derive(Debug)]
pub enum Table {
    Testing,
    Ecdsa,
    UserSession,
    StateChain,
    BackupTxs,
    Transfer,
    TransferBatch,
}
impl Table {
    fn to_string(&self) -> String {
        match self {
            Table::BackupTxs => {
                format!("{:?}.{:?}", Schema::Watcher.to_string().to_lowercase(), self)
            },
            _ => format!("{:?}.{:?}", Schema::StateChainEntity.to_string().to_lowercase(), self)
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
    POS
}
impl Column {
    pub fn to_string(&self) -> String {
        format!("{:?}", self)
    }
}


/// Serialize data into string. To add custom types to Postgres they must be serialized to String.
pub fn db_ser<T>(data: T) -> Result<String>
where
    T: serde::ser::Serialize
{
    match serde_json::to_string(&data) {
        Ok(v) => Ok(v),
        Err(_) => Err(SEError::Generic(String::from("Failed to serialize data.")))
    }
}

/// Deserialize custom type data from string. Reverse of db_ser().
pub fn db_deser<T>(data: String) -> Result<T>
where
    T: serde::de::DeserializeOwned
{
    match serde_json::from_str(&data) {
        Ok(v) => Ok(v),
        Err(_) => Err(SEError::Generic(String::from("Failed to deserialize string.")))
    }
}

// Create new item in table
pub fn db_insert(conn: &Connection, id: &Uuid, table: Table) -> Result<u64> {
    let statement = conn.prepare(&format!("INSERT INTO {} (id) VALUES ($1)",table.to_string()))?;

    Ok(statement.execute(&[id])?)
}

// Remove row in table
pub fn db_remove(conn: &Connection, id: &Uuid, table: Table) -> Result<()> {
    let statement = conn.prepare(&format!("DELETE FROM {} WHERE id = $1;",table.to_string()))?;
    if statement.execute(&[&id])? == 0 {
        return Err(SEError::DBError(UpdateFailed, id.to_string()));
    }

    Ok(())
}

/// Update items in table for some ID with PostgreSql data types (String, int, bool, Uuid, chrono::NaiveDateTime).
pub fn db_update(conn: &Connection, id: &Uuid, table: Table, column: Vec<Column>, data: Vec<&dyn ToSql>) -> Result<()>
{
    let num_items = column.len();
    let statement = conn.prepare(&format!(
        "UPDATE {} SET {} WHERE id = ${}",
            table.to_string(),
            update_columns_str(column),
            num_items+1
        ))?;

    let mut owned_data = data.clone();
    owned_data.push(id);

    if statement.execute(&owned_data)? == 0 {
        return Err(SEError::DBError(UpdateFailed, id.to_string()));
    }

    Ok(())
}
/// Returns str list of column names for SQL UPDATE prepare statement.
fn update_columns_str(cols: Vec<Column>) -> String {
    let cols_len = cols.len();
    let mut str = "".to_owned();
    for (i, col) in cols.iter().enumerate() {
        str.push_str(&col.to_string());
        str.push_str(&format!("=${}",i+1));
        if i != cols_len-1 {
            str.push_str(",");
        }
    }
    str
}

/// Get items from table for some ID with PostgreSql data types (String, int, Uuid, bool, Uuid, chrono::NaiveDateTime).
/// Err if ID not found. Return None if data item empty.
fn db_get<T,U,V,W>(conn: &Connection, id: &Uuid, table: Table, column: Vec<Column>) -> Result<(Option<T>,Option<U>,Option<V>,Option<W>)>
where
    T: rocket_contrib::databases::postgres::types::FromSql,
    U: rocket_contrib::databases::postgres::types::FromSql,
    V: rocket_contrib::databases::postgres::types::FromSql,
    W: rocket_contrib::databases::postgres::types::FromSql
{
    let num_items = column.len();
    let statement = conn.prepare(&format!(
        "SELECT {} FROM {} WHERE id = $1",
            get_columns_str(&column),
            table.to_string(),
        ))?;

    let rows = statement.query(&[id])?;
    if rows.is_empty() {
        return Err(SEError::DBError(NoDataForID, id.to_string()))
    };
    let row = rows.get(0);

    let col1 = get_item_from_row::<T>(&row, 0, id, column[0])?;
    if num_items == 1 {
        return Ok((Some(col1), None, None, None))
    }

    let col2 = get_item_from_row::<U>(&row, 1, id, column[1])?;
    if num_items == 2 {
        return Ok((Some(col1), Some(col2), None, None))
    }

    let col3 = get_item_from_row::<V>(&row, 2, id, column[2])?;
    if num_items == 3 {
        return Ok((Some(col1), Some(col2), Some(col3), None))
    }

    let col4 = get_item_from_row::<W>(&row, 3, id, column[3])?;
    if num_items == 4 {
        return Ok((Some(col1), Some(col2), Some(col3), Some(col4)))
    }

    Ok((None,None,None,None))
}
/// Returns str list of column names for SQL SELECT query statement.
pub fn get_columns_str(cols: &Vec<Column>) -> String {
    let cols_len = cols.len();
    let mut str = "".to_owned();
    for (i, col) in cols.iter().enumerate() {
        str.push_str(&col.to_string());
        if i != cols_len-1 {
            str.push_str(",");
        }
    }
    str
}

fn get_item_from_row<T>(row: &Row, index: usize, id: &Uuid, column: Column) -> Result<T>
    where
        T: rocket_contrib::databases::postgres::types::FromSql
{
    match row.get_opt::<usize, T>(index) {
        None => return Err(SEError::DBError(NoDataForID, id.to_string())),
        Some(data) => {
            match data {
                Ok(v) => Ok(v),
                Err(_) => return Err(SEError::DBErrorWC(NoDataForID, id.to_string(), column))
            }
        }
    }
}

/// Get 1 item from row in table. Err if ID not found. Return None if data item empty.
pub fn db_get_1<T>(conn: &Connection, id: &Uuid, table: Table, column: Vec<Column>) -> Result<T>
where
    T: rocket_contrib::databases::postgres::types::FromSql
{
    let (res,_,_,_) =
        db_get::<T,T,T,T>(conn, id, table, column)?;
    Ok(res.unwrap()) // err returned from db_get if desired item is None
}
/// Get 2 items from row in table. Err if ID not found. Return None if data item empty.
pub fn db_get_2<T,U>(conn: &Connection, id: &Uuid, table: Table, column: Vec<Column>) -> Result<(T,U)>
where
    T: rocket_contrib::databases::postgres::types::FromSql,
    U: rocket_contrib::databases::postgres::types::FromSql
{
    let (res1,res2,_,_) =
        db_get::<T,U,U,U>(conn, id, table, column)?;
    Ok((res1.unwrap(),res2.unwrap()))
}
/// Get 3 items from row in table. Err if ID not found. Return None if data item empty.
pub fn db_get_3<T,U,V>(conn: &Connection, id: &Uuid, table: Table, column: Vec<Column>) -> Result<(T,U,V)>
where
    T: rocket_contrib::databases::postgres::types::FromSql,
    U: rocket_contrib::databases::postgres::types::FromSql,
    V: rocket_contrib::databases::postgres::types::FromSql
{
    let (res1,res2,res3,_) =
        db_get::<T,U,V,V>(conn, id, table, column)?;
    Ok((res1.unwrap(),res2.unwrap(),res3.unwrap()))
}
/// Get 4 items from row in table. Err if ID not found. Return None if data item empty.
pub fn db_get_4<T,U,V,W>(conn: &Connection, id: &Uuid, table: Table, column: Vec<Column>) -> Result<(T,U,V,W)>
where
    T: rocket_contrib::databases::postgres::types::FromSql,
    U: rocket_contrib::databases::postgres::types::FromSql,
    V: rocket_contrib::databases::postgres::types::FromSql,
    W: rocket_contrib::databases::postgres::types::FromSql
{
    let (res1,res2,res3,res4) =
        db_get::<T,U,V,W>(conn, id, table, column)?;
    Ok((res1.unwrap(),res2.unwrap(),res3.unwrap(),res4.unwrap()))
}
