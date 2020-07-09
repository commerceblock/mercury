//! DB
//!
//! Postgres DB access and update tools.
//! Use db_get, db_update for rust types convertable to postgres types (String, int, bool, Uuid, chrono::NaiveDateTime).
//! Use db_get_serialized, db_update_serialized for custom types.


use super::super::Result;

use rocket_contrib::databases::postgres::Connection;
use crate::error::{DBErrorType::{UpdateFailed,NoDataForID}, SEError};
use uuid::Uuid;

#[derive(Debug)]
pub enum Table {
    Testing,
    Ecdsa,
    UserSession,
    StateChain,
    TransferData
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

    // TransferData
    // Id,
    StateChainSig,
    X1,

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

// Update item in table whose type is serialized to String
pub fn db_update_serialized<T>(conn: &Connection, id: &Uuid, data: T, table: Table, column: Column) -> Result<()>
where
    T: serde::ser::Serialize
{
    let item_string = serde_json::to_string(&data).unwrap();
    db_update(conn, id, item_string, table, column)
}

// Get item in table whose type is serialized to String
pub fn db_get_serialized<T>(conn: &Connection, id: &Uuid, table: Table, column: Column) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    match db_get::<String>(conn, id, table, column)? {
        Some(data) => return Ok(Some(serde_json::from_str(&data).unwrap())),
        None => Ok(None)
    }
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
        let user_id = Uuid::from_str(&"9eb05678-5275-451b-910c-a7179057d91d").unwrap();

        let res =
            db_remove(&conn, &user_id, Table::TransferData);

        println!("res: {:?}",res);
    }
}
