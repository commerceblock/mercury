//! DB
//!
//! Postgres DB access and update tools.
//! Use db_get, db_update for rust types convertable to postgres types (String, int, bool, Uuid, chrono::NaiveDateTime).
//! Use db_get_serialized, db_update_serialized for custom types.


use super::super::Result;

use rocket_contrib::databases::postgres::Connection;
use rocket_contrib::databases::postgres::types::ToSql;
use rocket_contrib::databases::postgres::rows::Row;
use crate::error::{DBErrorType::{UpdateFailed,NoDataForID}, SEError};
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

// Update item in table with PostgreSql data types (String, int, bool, Uuid, chrono::NaiveDateTime)
pub fn db_update<T>(conn: &Connection, id: &Uuid, data: T, table: Table, column: Column) -> Result<()>
where
    T: rocket_contrib::databases::postgres::types::ToSql
{
    let statement = conn.prepare(&format!("UPDATE {} SET {} = $1 WHERE id = $2",table.to_string(),column.to_string()))?;
    if statement.execute(&[&data, &id])? == 0 {
        return Err(SEError::DBError(UpdateFailed, *id));
    }

    Ok(())
}

// Get item from table with PostgreSql data types (String, int, Uuid, bool)
// Err if ID not found. Return None if data item empty.
pub fn db_get<T>(conn: &Connection, id: &Uuid, table: Table, column: Column) -> Result<Option<T>>
where
    T: rocket_contrib::databases::postgres::types::FromSql
{
    let statement = conn.prepare(&format!("SELECT {} FROM {} WHERE id = $1",column.to_string(),table.to_string()))?;
    let rows = statement.query(&[&id])?;

    if rows.is_empty() {
        return Err(SEError::DBError(NoDataForID, *id))
    };
    let row = rows.get(0);

    match row.get_opt::<usize, T>(0) {
        None => return Err(SEError::DBError(NoDataForID, *id)),
        Some(data) => {
            match data {
                Ok(v) => Ok(Some(v)),
                Err(_) => Ok(None)
            }
        }
    }
}

// Remove row in table
pub fn db_remove(conn: &Connection, id: &Uuid, table: Table) -> Result<()> {
    let statement = conn.prepare(&format!("DELETE FROM {} WHERE id = $1;",table.to_string()))?;
    if statement.execute(&[&id])? == 0 {
        return Err(SEError::DBError(UpdateFailed, *id));
    }

    Ok(())
}


pub fn db_update_row(conn: &Connection, id: &Uuid, table: Table, column: Vec<Column>, data: Vec<&dyn ToSql>) -> Result<()>
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
        return Err(SEError::DBError(UpdateFailed, *id));
    }

    Ok(())
}
/// Returns str list of column names for SQL statement.
pub fn update_columns_str(cols: Vec<Column>) -> String {
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


fn db_get_row<T,U,V,W>(conn: &Connection, id: &Uuid, table: Table, column: Vec<Column>) -> Result<(Option<T>,Option<U>,Option<V>,Option<W>)>
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
        return Err(SEError::DBError(NoDataForID, id.clone()))
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
/// Returns str list of column names for SQL statement.
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
        None => return Err(SEError::DBError(NoDataForID, *id)),
        Some(data) => {
            match data {
                Ok(v) => Ok(v),
                Err(_) => return Err(SEError::DBErrorWC(NoDataForID, *id, column))
            }
        }
    }
}

pub fn db_get_1<T>(conn: &Connection, id: &Uuid, table: Table, column: Vec<Column>) -> Result<T>
where
    T: rocket_contrib::databases::postgres::types::FromSql
{
    let (res,_,_,_) =
        db_get_row::<T,T,T,T>(conn, id, table, column)?;
    Ok(res.unwrap()) // err returned from db_get_row if desired item is None
}

pub fn db_get_2<T,U>(conn: &Connection, id: &Uuid, table: Table, column: Vec<Column>) -> Result<(T,U)>
where
    T: rocket_contrib::databases::postgres::types::FromSql,
    U: rocket_contrib::databases::postgres::types::FromSql
{
    let (res1,res2,_,_) =
        db_get_row::<T,U,U,U>(conn, id, table, column)?;
    Ok((res1.unwrap(),res2.unwrap()))
}

pub fn db_get_3<T,U,V>(conn: &Connection, id: &Uuid, table: Table, column: Vec<Column>) -> Result<(T,U,V)>
where
    T: rocket_contrib::databases::postgres::types::FromSql,
    U: rocket_contrib::databases::postgres::types::FromSql,
    V: rocket_contrib::databases::postgres::types::FromSql
{
    let (res1,res2,res3,_) =
        db_get_row::<T,U,V,V>(conn, id, table, column)?;
    Ok((res1.unwrap(),res2.unwrap(),res3.unwrap()))
}

pub fn db_get_4<T,U,V,W>(conn: &Connection, id: &Uuid, table: Table, column: Vec<Column>) -> Result<(T,U,V,W)>
where
    T: rocket_contrib::databases::postgres::types::FromSql,
    U: rocket_contrib::databases::postgres::types::FromSql,
    V: rocket_contrib::databases::postgres::types::FromSql,
    W: rocket_contrib::databases::postgres::types::FromSql
{
    let (res1,res2,res3,res4) =
        db_get_row::<T,U,V,W>(conn, id, table, column)?;
    Ok((res1.unwrap(),res2.unwrap(),res3.unwrap(),res4.unwrap()))
}




#[cfg(test)]
mod tests {

    use super::*;
    use std::{env, str::FromStr};

    #[test]
    fn test_db_postgres() {
        use postgres::{Connection, TlsMode};

        let rocket_url = env::var("ROCKET_DATABASES").unwrap();
        let url = &rocket_url[16..68];

        let conn = Connection::connect(url, TlsMode::None).unwrap();
        let user_id = Uuid::from_str(&"3cf795d8-3a98-4ceb-9f68-4d5e2e306b87").unwrap();

        let dbget1: Option<String> = db_get_1(&conn, &user_id, Table::StateChain,
            vec!(
                Column::Chain,
            )).unwrap();
        println!("dbget1: {:?}",dbget1);


        let (dbget1, dbget2) = db_get_2::<Option<String>,Option<i64>>(&conn, &user_id, Table::StateChain,
            vec!(
                Column::Chain,
                Column::Amount,
            )).unwrap();
        println!("dbget1: {:?}",dbget1);
        println!("dbget2: {:?}",dbget2);

        let (dbget1, dbget2, dbget3) = db_get_3::<Option<String>,Option<i64>,Option<Uuid>>(&conn, &user_id, Table::StateChain,
            vec!(
                Column::Chain,
                Column::Amount,
                Column::OwnerId,
            )).unwrap();
        println!("dbget1: {:?}",dbget1);
        println!("dbget2: {:?}",dbget2);
        println!("dbget3: {:?}",dbget3);

        // let res =
        //     db_get_row::<String,i64,Uuid>(&conn, &user_id, Table::StateChain,
        //         vec!(
        //             Column::Chain,
        //             Column::Amount,
        //             Column::OwnerId,
        //         ));
    }
}
