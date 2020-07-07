//! DB
//!
//! Postgres DB access and update tools.
//! Use db_get, db_update for rust types convertable to postgres types (String, int, Uuid, bool).
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

    // User
    Id,
    Authentication,
    ProofKey,
    StateChainId,
    TxBackup,
    TxWithdraw,
    SigHash,
    S2,
    WithdrawScSig,

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

// Update item in table with PostgreSql data types (String, int, Uuid, bool)
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

// // Update item in table with PostgreSql data types (String, int, Uuid, bool)
// pub fn db_remove<T>(conn: &Connection, id: &Uuid, data: T, table: Table, column: Column) -> Result<()>
// where
//     T: rocket_contrib::databases::postgres::types::ToSql
// {
//     let statement = conn.prepare(&format!("UPDATE {} SET {} = $1 WHERE id = $2",table.to_string(),column.to_string()))?;
//     if statement.execute(&[&data, &id])? == 0 {
//         return Err(SEError::DBError(UpdateFailed, id.to_string()));
//     }
//
//     Ok(())
// }


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
    use std::str::FromStr;

    #[test]
    fn test_db_postgres() {
        use postgres::{Connection, TlsMode};

        let url = "postgresql://mercury:px3kdjRe5ex2pz@95.179.134.31:5432";
        let conn = Connection::connect(url, TlsMode::None).unwrap();
        let user_id = Uuid::from_str(&"792064a6-9a0b-439c-afa2-a69477d5bb15").unwrap();
        let res = db_get::<String>(&conn, &user_id, Table::Testing, Column::CommWitness);
        println!("res: {:?}",res);
        // db_insert(&conn, &user_id, Table::UserSession).unwrap();

        let user_id = Uuid::from_str(&"1e771114-589d-4607-9446-e4f0998c329f").unwrap();
        let res = db_get::<String>(&conn, &user_id, Table::Testing, Column::CommWitness);
        println!("res: {:?}",res);

        let user_id = Uuid::from_str(&"1b771114-589d-4607-9446-e4f0998c329f").unwrap();
        let res = db_get::<String>(&conn, &user_id, Table::Testing, Column::CommWitness);
        println!("res: {:?}",res);


    }
}
