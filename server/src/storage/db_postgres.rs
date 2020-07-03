use super::{db::MPCStruct, super::Result};

use rocket_contrib::databases::postgres::Connection;
use uuid::Uuid;
use crate::error::{DBErrorType::{UpdateFailed,NoDataForID}, SEError};

#[derive(Debug, Clone)]
pub struct TestingStruct {
    pub id: Uuid,
    pub data: String
}


pub fn db_ecdsa_new(conn: &Connection, id: &Uuid) -> Result<u64> {
    let statement = conn.prepare("INSERT INTO ecdsa (id) VALUES ($1)")?;

    Ok(statement.execute(&[id])?)
}

pub fn db_ecdsa_update<T>(conn: &Connection, id: Uuid, data: T, name: &dyn MPCStruct) -> Result<()>
where
    T: serde::ser::Serialize
{
    let statement = conn.prepare(&format!("UPDATE ecdsa SET {} = $1 WHERE id = $2",name.to_string()))?;
    let item_string = serde_json::to_string(&data).unwrap();

    if statement.execute(&[&item_string, &id])? == 0 {
        return Err(SEError::EcdsaDBError(UpdateFailed, id.to_string(), name.to_string()));
    }
    Ok(())
}

pub fn db_ecdsa_get<T>(conn: &Connection, id: Uuid, name: &dyn MPCStruct) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let statement = conn.prepare(&format!("SELECT {} FROM ecdsa WHERE id = $1",name.to_string()))?;

    let rows = statement.query(&[&id])?;
    if rows.len() == 0 { return Err(SEError::EcdsaDBError(NoDataForID, id.to_string().clone(), name.to_string())) };
    let row = rows.get(0);
    let data: String = row.get(0);

    return Ok(serde_json::from_str(&data).unwrap())
}
