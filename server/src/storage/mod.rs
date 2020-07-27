pub mod db;

use super::Result;
use postgres::Connection;
use db::Table;


/// Build DB tables and Schemas
pub fn db_make_tables(conn: &Connection) -> Result<()> {
    // Create Schemas if they do not already exist
    let _ = conn.execute(&format!("
        CREATE SCHEMA statechainentity;",
    ), &[])?;
    let _ = conn.execute(&format!("
        CREATE SCHEMA watcher;",
    ), &[])?;

    // Create tables if they do not already exist
    conn.execute(&format!("
        CREATE TABLE {} (
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
    ), &[])?;

    conn.execute(&format!("
        CREATE TABLE {} (
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
    ), &[])?;

    conn.execute(&format!("
        CREATE TABLE {} (
            id uuid NOT NULL,
            chain varchar,
            amount int8,
            ownerid uuid,
            lockeduntil timestamp,
            PRIMARY KEY (id)
        );",
        Table::StateChain.to_string(),
    ), &[])?;

    conn.execute(&format!("
        CREATE TABLE {} (
            id uuid NOT NULL,
            statechainsig varchar,
            x1 varchar,
            PRIMARY KEY (id)
        );",
        Table::Transfer.to_string(),
    ), &[])?;

    conn.execute(&format!("
        CREATE TABLE {} (
            id uuid NOT NULL,
            starttime timestamp,
            statechains varchar,
            finalizeddata varchar,
            punishedstatechains varchar,
            finalized bool,
            PRIMARY KEY (id)
        );",
        Table::TransferBatch.to_string(),
    ), &[])?;

    conn.execute(&format!("
        CREATE TABLE {} (
            id BIGSERIAL,
            value varchar,
            commitmentinfo varchar,
            PRIMARY KEY (id)
        );",
        Table::Root.to_string(),
    ), &[])?;

    conn.execute(&format!("
        CREATE TABLE {} (
            id uuid NOT NULL,
            txbackup varchar,
            PRIMARY KEY (id)
        );",
        Table::BackupTxs.to_string(),
    ), &[])?;

    Ok(())
}

/// Drop all DB tables and Schemas.
pub fn db_drop_tables(conn: &Connection) ->  Result<()> {
    let _ = conn.execute(&format!("
        DROP SCHEMA statechainentity CASCADE;",
    ), &[])?;
    let _ = conn.execute(&format!("
        DROP SCHEMA watcher CASCADE;",
    ), &[])?;

    Ok(())
}

/// Drop all DB tables and schemas.
pub fn db_truncate_tables(conn: &Connection) ->  Result<()> {
    conn.execute(&format!("
        TRUNCATE {},{},{},{},{},{},{} RESTART IDENTITY;",
        Table::UserSession.to_string(),
        Table::Ecdsa.to_string(),
        Table::StateChain.to_string(),
        Table::Transfer.to_string(),
        Table::TransferBatch.to_string(),
        Table::Root.to_string(),
        Table::BackupTxs.to_string(),
    ), &[])?;
    Ok(())
}


#[cfg(test)]
mod tests {

    use super::*;
    use postgres::{Connection, TlsMode};
    use std::env;
    use db::db_root_get_current_id;

    fn postgres_conn() -> Connection {
        let rocket_url = env::var("ROCKET_DATABASES").unwrap();
        Connection::connect(&rocket_url[16..84], TlsMode::None).unwrap()
    }

    #[test]
    fn test_db() {
        let conn = postgres_conn();
        let res = db_drop_tables(&conn);
        // println!("res: {:?}",res);
        let res = db_make_tables(&conn).unwrap();
        // db_truncate_tables(&conn);
        let res = db_root_get_current_id(&conn);
        println!("res: {:?}",res);
    }
}
