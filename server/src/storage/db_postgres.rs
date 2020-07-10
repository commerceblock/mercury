//! DB
//!
//! Postgres DB access and update tools.
//! Use db_get, db_update for rust types convertable to postgres types (String, int, bool, Uuid, chrono::NaiveDateTime).
//! Use db_get_serialized, db_update_serialized for custom types.


use super::super::Result;

use rocket_contrib::databases::postgres::Connection;
use rocket_contrib::databases::postgres::types::ToSql;
use crate::error::{DBErrorType::{UpdateFailed,NoDataForID}, SEError};
use uuid::Uuid;

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
        format!("{:?}", self)
    }
}

#[derive(Debug, Deserialize)]
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
        return Err(SEError::DBError(UpdateFailed, id.to_string()));
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
        return Err(SEError::DBError(NoDataForID, id.to_string().clone()))
    };
    let row = rows.get(0);

    match row.get_opt::<usize, T>(0) {
        None => return Err(SEError::DBError(NoDataForID, id.to_string().clone())),
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
        return Err(SEError::DBError(UpdateFailed, id.to_string()));
    }

    Ok(())
}


pub fn db_update_row(conn: &Connection, id: &Uuid, table: Table, column: Vec<Column>, data: Vec<&dyn ToSql>) -> Result<()>
{
    let num_items = data.len();
    let statement = conn.prepare(&format!(
        "UPDATE {} SET {} WHERE id = ${}",
            table.to_string(),
            format_stmt_multiple_columns(column),
            num_items+1
        ))?;

    let mut owned_data = data.clone();
    owned_data.push(id);

    if statement.execute(&owned_data)? == 0 {
        return Err(SEError::DBError(UpdateFailed, id.to_string()));
    }

    Ok(())
}

/// Returns str list of column names for SQL statement.
pub fn format_stmt_multiple_columns(cols: Vec<Column>) -> String {
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

#[cfg(test)]
mod tests {

    use super::*;
    use std::{env, str::FromStr};
    use shared_lib::state_chain::StateChain;

    #[test]
    fn test_db_postgres() {
        use postgres::{Connection, TlsMode};

        let rocket_url = env::var("ROCKET_DATABASES").unwrap();
        let url = &rocket_url[16..68];

        let conn = Connection::connect(url, TlsMode::None).unwrap();
        let user_id = Uuid::from_str(&"052563d0-5b43-4138-b13d-58a434a21eac").unwrap();

        let state_chain = StateChain::new("data".to_string());
        let res =
            db_update_row(&conn, &user_id, Table::StateChain,
                vec!(
                    Column::Chain,
                    Column::Amount,
                    Column::OwnerId
                ),
                vec!(
                    &db_ser(state_chain).unwrap(),
                    &(1234 as i64),
                    &Uuid::new_v4()
                ));


        println!("res: {:?}",res);

        // let res: StateChain =
        //     db_deser(db_get(&conn, &user_id, Table::StateChain, Column::Chain).unwrap().unwrap()).unwrap();
        // println!("res: {:?}",res);

    }
}
