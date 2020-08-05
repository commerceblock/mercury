pub mod db;

use super::Result;
use crate::server::get_postgres_url;
use db::Table;
use postgres::Connection;
use rocket_contrib::databases::r2d2;
use rocket_contrib::databases::r2d2_postgres::{PostgresConnectionManager, TlsMode};
use rocksdb::{Options, DB};

/// Build DB tables and Schemas
pub fn db_make_tables(conn: &Connection) -> Result<()> {
    // Create Schemas if they do not already exist
    let _ = conn.execute(
        &format!(
            "
        CREATE SCHEMA IF NOT EXISTS statechainentity;",
        ),
        &[],
    )?;
    let _ = conn.execute(
        &format!(
            "
        CREATE SCHEMA IF NOT EXISTS watcher;",
        ),
        &[],
    )?;

    // Create tables if they do not already exist
    conn.execute(
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

    conn.execute(
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

    conn.execute(
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

    conn.execute(
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

    conn.execute(
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

    conn.execute(
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

    conn.execute(
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
fn db_drop_tables(conn: &Connection) -> Result<()> {
    let _ = conn.execute(
        &format!(
            "
        DROP SCHEMA statechainentity CASCADE;",
        ),
        &[],
    )?;
    let _ = conn.execute(
        &format!(
            "
        DROP SCHEMA watcher CASCADE;",
        ),
        &[],
    )?;

    Ok(())
}

/// Drop all DB tables and schemas.
fn db_truncate_tables(conn: &Connection) -> Result<()> {
    conn.execute(
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

pub fn db_reset_dbs(conn: &Connection, smt_db_loc: &String) -> Result<()> {
    // truncate all postgres tables
    db_truncate_tables(&conn)?;

    // Destroy Sparse Merkle Tree RocksDB instance
    let _ = DB::destroy(&Options::default(), smt_db_loc); // ignore error
    Ok(())
}

pub fn get_test_postgres_connection() -> r2d2::PooledConnection<PostgresConnectionManager> {
    let rocket_url = get_postgres_url(
        std::env::var("MERC_DB_HOST_W").unwrap(),
        std::env::var("MERC_DB_PORT_W").unwrap(),
        std::env::var("MERC_DB_USER_W").unwrap(),
        std::env::var("MERC_DB_PASS_W").unwrap(),
        std::env::var("MERC_DB_DATABASE_W").unwrap(),
    );
    let manager = PostgresConnectionManager::new(rocket_url, TlsMode::None).unwrap();
    r2d2::Pool::new(manager).unwrap().get().unwrap()
}
