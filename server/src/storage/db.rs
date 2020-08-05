//! DB
//!
//! Postgres DB access and update tools.

use super::super::Result;
use crate::{
    error::{
        DBErrorType::{NoDataForID, UpdateFailed},
        SEError,
    },
    DatabaseR, DatabaseW,
};
use mainstay::{Attestable, CommitmentInfo};
#[cfg(test)]
use mockito::{mock, Matcher, Mock};
use rocket_contrib::databases::postgres::{rows::Row, types::ToSql};
use shared_lib::mainstay;
use shared_lib::Root;
use uuid::Uuid;

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

/// Serialize data into string. To add custom types to Postgres they must be serialized to String.
pub fn db_ser<T>(data: T) -> Result<String>
where
    T: serde::ser::Serialize,
{
    match serde_json::to_string(&data) {
        Ok(v) => Ok(v),
        Err(_) => Err(SEError::Generic(String::from("Failed to serialize data."))),
    }
}

/// Deserialize custom type data from string. Reverse of db_ser().
pub fn db_deser<T>(data: String) -> Result<T>
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
pub fn db_insert(db_write: &DatabaseW, id: &Uuid, table: Table) -> Result<u64> {
    let statement = db_write.prepare(&format!(
        "INSERT INTO {} (id) VALUES ($1)",
        table.to_string()
    ))?;

    Ok(statement.execute(&[id])?)
}

/// Remove row in table
pub fn db_remove(db_write: &DatabaseW, id: &Uuid, table: Table) -> Result<()> {
    let statement =
        db_write.prepare(&format!("DELETE FROM {} WHERE id = $1;", table.to_string()))?;
    if statement.execute(&[&id])? == 0 {
        return Err(SEError::DBError(UpdateFailed, id.to_string()));
    }

    Ok(())
}

/// Update items in table for some ID with PostgreSql data types (String, int, bool, Uuid, chrono::NaiveDateTime).
pub fn db_update(
    db_write: &DatabaseW,
    id: &Uuid,
    table: Table,
    column: Vec<Column>,
    data: Vec<&dyn ToSql>,
) -> Result<()> {
    let num_items = column.len();
    let statement = db_write.prepare(&format!(
        "UPDATE {} SET {} WHERE id = ${}",
        table.to_string(),
        update_columns_str(column),
        num_items + 1
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
        str.push_str(&format!("=${}", i + 1));
        if i != cols_len - 1 {
            str.push_str(",");
        }
    }
    str
}

/// Get items from table for some ID with PostgreSql data types (String, int, Uuid, bool, Uuid, chrono::NaiveDateTime).
/// Err if ID not found. Return None if data item empty.
fn db_get<T, U, V, W>(
    db_read: &DatabaseR,
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
    let statement = db_read.prepare(&format!(
        "SELECT {} FROM {} WHERE id = $1",
        get_columns_str(&column),
        table.to_string(),
    ))?;

    let rows = statement.query(&[id])?;
    if rows.is_empty() {
        return Err(SEError::DBError(NoDataForID, id.to_string()));
    };
    let row = rows.get(0);

    let col1 = get_item_from_row::<T>(&row, 0, &id.to_string(), column[0])?;
    if num_items == 1 {
        return Ok((Some(col1), None, None, None));
    }

    let col2 = get_item_from_row::<U>(&row, 1, &id.to_string(), column[1])?;
    if num_items == 2 {
        return Ok((Some(col1), Some(col2), None, None));
    }

    let col3 = get_item_from_row::<V>(&row, 2, &id.to_string(), column[2])?;
    if num_items == 3 {
        return Ok((Some(col1), Some(col2), Some(col3), None));
    }

    let col4 = get_item_from_row::<W>(&row, 3, &id.to_string(), column[3])?;
    if num_items == 4 {
        return Ok((Some(col1), Some(col2), Some(col3), Some(col4)));
    }

    Ok((None, None, None, None))
}
/// Returns str list of column names for SQL SELECT query statement.
pub fn get_columns_str(cols: &Vec<Column>) -> String {
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

fn get_item_from_row<T>(row: &Row, index: usize, id: &String, column: Column) -> Result<T>
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
pub fn db_get_1<T>(db_read: &DatabaseR, id: &Uuid, table: Table, column: Vec<Column>) -> Result<T>
where
    T: rocket_contrib::databases::postgres::types::FromSql,
{
    let (res, _, _, _) = db_get::<T, T, T, T>(db_read, id, table, column)?;
    Ok(res.unwrap()) //  err returned from db_get if desired item is None
}
/// Get 2 items from row in table. Err if ID not found. Return None if data item empty.
pub fn db_get_2<T, U>(
    db_read: &DatabaseR,
    id: &Uuid,
    table: Table,
    column: Vec<Column>,
) -> Result<(T, U)>
where
    T: rocket_contrib::databases::postgres::types::FromSql,
    U: rocket_contrib::databases::postgres::types::FromSql,
{
    let (res1, res2, _, _) = db_get::<T, U, U, U>(db_read, id, table, column)?;
    Ok((res1.unwrap(), res2.unwrap()))
}
/// Get 3 items from row in table. Err if ID not found. Return None if data item empty.
pub fn db_get_3<T, U, V>(
    db_read: &DatabaseR,
    id: &Uuid,
    table: Table,
    column: Vec<Column>,
) -> Result<(T, U, V)>
where
    T: rocket_contrib::databases::postgres::types::FromSql,
    U: rocket_contrib::databases::postgres::types::FromSql,
    V: rocket_contrib::databases::postgres::types::FromSql,
{
    let (res1, res2, res3, _) = db_get::<T, U, V, V>(db_read, id, table, column)?;
    Ok((res1.unwrap(), res2.unwrap(), res3.unwrap()))
}
/// Get 4 items from row in table. Err if ID not found. Return None if data item empty.
pub fn db_get_4<T, U, V, W>(
    db_read: &DatabaseR,
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
    let (res1, res2, res3, res4) = db_get::<T, U, V, W>(db_read, id, table, column)?;
    Ok((res1.unwrap(), res2.unwrap(), res3.unwrap(), res4.unwrap()))
}

/// Update the database with the latest available mainstay attestation info
pub fn get_confirmed_root(
    db_read: &DatabaseR,
    db_write: &DatabaseW,
    mc: &Option<mainstay::Config>,
) -> Result<Option<Root>> {
    use crate::shared_lib::mainstay::{Commitment, CommitmentIndexed, MainstayAPIError};

    fn update_db_from_ci(
        db_read: &DatabaseR,
        db_write: &DatabaseW,
        ci: &CommitmentInfo,
    ) -> Result<Option<Root>> {
        let mut root = Root::from_commitment_info(ci);
        let current_id = db_root_get_current_id(db_read)?;
        let mut id;
        for x in 0..=current_id - 1 {
            id = current_id - x;
            let root_get = db_root_get(db_read, &id)?;
            match root_get {
                Some(r) => {
                    if r.hash() == ci.commitment().to_hash() {
                        match r.id() {
                            Some(r_id) => {
                                root.set_id(&r_id);
                                break;
                            }
                            None => (),
                        }
                    }
                }
                None => (),
            };
        }

        let root = root;

        match db_root_update(db_read, db_write, &root) {
            Ok(_) => Ok(Some(root)),
            Err(e) => Err(e),
        }
    }

    match mc {
        Some(conf) => {
            match &db_get_confirmed_root(db_read)? {
                Some(cr_db) => {
                    //Search for update

                    //First try to find the latest root in the latest commitment
                    let result = match &CommitmentInfo::from_latest(conf) {
                        Ok(ci) => match cr_db.commitment_info() {
                            Some(ci_db) => {
                                if ci_db == ci {
                                    Ok(Some(cr_db.clone()))
                                } else {
                                    update_db_from_ci(db_read, db_write, ci)
                                }
                            }
                            None => update_db_from_ci(db_read, db_write, ci),
                        },
                        Err(e) => Err(SEError::SharedLibError(e.to_string())),
                    };

                    //Search for the roots in historical mainstay commitments if not found from latest
                    match result? {
                        Some(r) => Ok(Some(r)),
                        None => {
                            let current_id = db_root_get_current_id(db_read)?;
                            for x in 0..=current_id - 1 {
                                let id = current_id - x;
                                let _ = match db_root_get(db_read, &id)? {
                                    Some(r) => {
                                        match &CommitmentInfo::from_commitment(
                                            conf,
                                            &Commitment::from_hash(&r.hash()),
                                        ) {
                                            Ok(ci) => {
                                                let mut root = Root::from_commitment_info(ci);
                                                root.set_id(&id);
                                                //Latest confirmed commitment found. Updating db
                                                return match db_root_update(
                                                    db_read, db_write, &root,
                                                ) {
                                                    Ok(_) => Ok(Some(root)),
                                                    Err(e) => Err(e),
                                                };
                                            }

                                            //MainStay::NotFoundRrror is acceptable - continue the search. Otherwise return the error
                                            Err(e) => match e.downcast_ref::<MainstayAPIError>() {
                                                Some(e) => match e {
                                                    MainstayAPIError::NotFoundError(_) => (),
                                                    _ => {
                                                        return Err(SEError::Generic(e.to_string()))
                                                    }
                                                },
                                                None => {
                                                    return Err(SEError::Generic(e.to_string()))
                                                }
                                            },
                                        };
                                    }
                                    None => (),
                                };
                            }
                            Ok(None)
                        }
                    }
                }
                None => match &CommitmentInfo::from_latest(conf) {
                    Ok(ci) => update_db_from_ci(db_read, db_write, ci),
                    Err(e) => Err(SEError::SharedLibError(e.to_string())),
                },
            }
        }
        None => Ok(None),
    }
}

/// Update the database and the mainstay slot with the SMT root, if applicable
pub fn root_update(
    db_read: &DatabaseR,
    db_write: &DatabaseW,
    _mc: &Option<mainstay::Config>,
    root: &Root,
) -> Result<i64> {
    //db_root_update_mainstay(mc, root)?;
    let id = db_root_update(db_read, db_write, root)?;
    Ok(id)
}

#[allow(dead_code)]
fn db_root_update_mainstay(config: &Option<mainstay::Config>, root: &Root) -> Result<()> {
    match config {
        Some(c) => match root.attest(&c) {
            Ok(_) => Ok(()),
            Err(e) => Err(SEError::SharedLibError(e.to_string())),
        },
        None => Ok(()),
    }
}

/// Update root value in DB. Update root with ID or insert new DB item.
fn db_root_update(db_read: &DatabaseR, db_write: &DatabaseW, rt: &Root) -> Result<i64> {
    let mut root = rt.clone();
    // Get previous ID, or use the one specified in root to update an existing root with mainstay proof
    let id = match root.id() {
        //This will update an existing root in the db
        Some(id) => {
            let existing_root = db_root_get(db_read, &(id as i64))?;
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
            match db_root_get_current_id(db_read) {
                Ok(id) => id + 1,
                Err(_) => 1, // No roots in DB
            }
        }
    };

    // Insert new root
    root.set_id(&id);
    db_root_insert(db_write, &root)?;

    debug!("Updated root at id {} with value: {:?}", id, root);
    Ok(id)
}

/// Insert a Root into root table
pub fn db_root_insert(db_write: &DatabaseW, root: &Root) -> Result<u64> {
    let statement = db_write.prepare(&format!(
        "INSERT INTO {} (value, commitmentinfo) VALUES ($1,$2)",
        Table::Root.to_string()
    ))?;
    Ok(statement.execute(&[&db_ser(root.hash())?, &db_ser(root.commitment_info())?])?)
}

/// Get Id of current Root
pub fn db_root_get_current_id(db_read: &DatabaseR) -> Result<i64> {
    let statement =
        db_read.prepare(&format!("SELECT MAX(id) FROM {}", Table::Root.to_string(),))?;
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
pub fn db_root_get(db_read: &DatabaseR, id: &i64) -> Result<Option<Root>> {
    if id == &0 {
        return Ok(None);
    }
    let statement = db_read.prepare(&format!(
        "SELECT * FROM {} WHERE id = $1",
        Table::Root.to_string(),
    ))?;
    let rows = statement.query(&[id])?;
    if rows.is_empty() {
        return Err(SEError::DBError(NoDataForID, format!("Root id: {}", id)));
    };
    let row = rows.get(0);

    let id = match get_item_from_row::<i64>(&row, 0, &id.to_string(), Column::Id) {
        Ok(v) => v,
        Err(_) => {
            // No root in table yet. Return None
            return Ok(None);
        }
    };
    let root = Root::from(
        Some(id),
        db_deser(get_item_from_row::<String>(
            &row,
            1,
            &id.to_string(),
            Column::Value,
        )?)?,
        &db_deser::<Option<CommitmentInfo>>(get_item_from_row::<String>(
            &row,
            2,
            &id.to_string(),
            Column::CommitmentInfo,
        )?)?,
    )?;
    Ok(Some(root))
}

/// Find the latest confirmed root
pub fn db_get_confirmed_root(db_read: &DatabaseR) -> Result<Option<Root>> {
    let current_id = db_root_get_current_id(&db_read)?;
    for i in 0..=current_id - 1 {
        let id = current_id - i;
        let root = db_root_get(db_read, &id)?;
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

#[cfg(test)]
mod mocks {
    use super::{mock, Matcher, Mock};

    pub mod ms {
        use super::*;
        pub fn commitment_proof_not_found() -> Mock {
            mock(
                "GET",
                Matcher::Regex(r"^/commitment/commitment\?commitment=[abcdef\d]{64}".to_string()),
            )
            .with_header("Content-Type", "application/json")
            .with_body(
                "{\"error\":\"Not found\",\"timestamp\":1596123963077,
                \"allowance\":{\"cost\":3796208}}",
            )
        }

        pub fn post_commitment() -> Mock {
            mock("POST", "/commitment/send")
                .match_header("content-type", "application/json")
                .with_body(
                    serde_json::json!({"response":"Commitment added","timestamp":1541761540,
            "allowance":{"cost":4832691}})
                    .to_string(),
                )
                .with_header("content-type", "application/json")
        }

        pub fn commitment() -> Mock {
            mock("GET", "/latestcommitment?position=1")
               .with_header("Content-Type", "application/json")
               .with_body("{
                   \"response\":
                    {
                        \"commitment\": \"71c7f2f246caf3e4f0b94ea4ad54b6c506687069bf1e17024cd5961b0df78d6d\",
                        \"merkle_root\": \"47fc767ebc5095133d6de9a060c248c115b3fdf5f30921de2ee111225690de01\",
                        \"txid\": \"4be7f5fbd3272cec65e520f5b04c79c2059548c4576558aac3f4f6655138d5d4\"
                    },
                    \"timestamp\": 1548329166363,
                    \"allowance\":
                    {
                        \"cost\": 3119659
                    }
                }")
        }

        pub fn commitment_proof() -> Mock {
            mock("GET",
                        "/commitment/commitment?commitment=71c7f2f246caf3e4f0b94ea4ad54b6c506687069bf1e17024cd5961b0df78d6d")
                        .with_header("Content-Type", "application/json")
                        .with_body("{\"response\":{
                            \"attestation\":{\"merkle_root\":\"47fc767ebc5095133d6de9a060c248c115b3fdf5f30921de2ee111225690de01\",
                    \"txid\":\"4be7f5fbd3272cec65e520f5b04c79c2059548c4576558aac3f4f6655138d5d4\",\"confirmed\":true,
                    \"inserted_at\":\"12:07:54 05/02/2020 UTC\"},
                    \"merkleproof\":{\"position\":1,
                    \"merkle_root\":\"47fc767ebc5095133d6de9a060c248c115b3fdf5f30921de2ee111225690de01\",
                    \"commitment\":\"71c7f2f246caf3e4f0b94ea4ad54b6c506687069bf1e17024cd5961b0df78d6d\",
                    \"ops\":[{\"append\":false,\"commitment\":\"31e66288b9074bcfeb3bc5734f2d0b189ad601b61f86b8241ee427648b59fdbc\"},
                    {\"append\":true,\"commitment\":\"60da74551926c4283dd4b4e295d2a1eb5147b5cf6c7c2019e8b64c22a1ba5bab\"},{\"append\":true,
                    \"commitment\":\"94adb04ab09036fbc6cc164ec6df4d9d8fba45bcd7901a03d2e91b123071a5ec\"}]}}
                    ,\"timestamp\":1593160486862,
                    \"allowance\":{\"cost\":17954530}
                    }")
        }
    }
}

#[cfg(test)]
mod tests {

    use super::super::super::server::get_settings_as_map;
    use super::super::super::StateChainEntity;
    use super::*;
    use crate::{server::SMT_DB_LOC_TESTING, storage::get_test_postgres_connection};
    use std::str::FromStr;

    #[allow(dead_code)]
    fn test_sc_entity() -> StateChainEntity {
        let mut sc_entity = StateChainEntity::load(get_settings_as_map()).unwrap();
        sc_entity.mainstay_config = mainstay::Config::from_test();
        sc_entity.smt_db_loc = SMT_DB_LOC_TESTING.to_string();
        sc_entity
    }

    fn test_url() -> String {
        String::from(&mockito::server_url())
    }

    #[test]
    #[serial]
    fn test_verify_root() {
        let db_read = DatabaseR(get_test_postgres_connection());
        let db_write = DatabaseW(get_test_postgres_connection());
        let mc = Some(mainstay::Config::mock_from_url(&test_url()));

        //No commitments initially
        let _m = mocks::ms::commitment_proof_not_found();

        assert_eq!(
            db_get_confirmed_root(&db_read).unwrap(),
            None,
            "expected Ok(None)"
        );

        let com1 = mainstay::Commitment::from_str(
            "71c7f2f246caf3e4f0b94ea4ad54b6c506687069bf1e17024cd5961b0df78d6d",
        )
        .unwrap();

        let root1 = Root::from_hash(&com1.to_hash());

        assert_eq!(root1.hash(), com1.to_hash(), "expected roots to match");

        let _m_send = mocks::ms::post_commitment().create();

        let _root1_id = match root_update(&db_read, &db_write, &mc, &root1) {
            Ok(id) => id,
            Err(e) => {
                assert!(false, e.to_string());
                0
            }
        };

        // Root posted but not confirmed yet

        //Update the local copy of root1
        //let root1 = db_root_get(&db_read, &(root1_id as i64)).unwrap().unwrap();

        assert!(root1.is_confirmed() == false);

        //Some time later, the root is committed to mainstay
        let _m_com = mocks::ms::commitment().create();
        let _m_com_proof = mocks::ms::commitment_proof().create();

        //The root should be confirmed now
        let rootc = get_confirmed_root(&db_read, &db_write, &mc)
            .unwrap()
            .unwrap();
        assert!(rootc.is_confirmed(), "expected the root to be confirmed");

        //let root1 = db_root_get(&db_read, &(root1_id as i64)).unwrap().unwrap();

        assert_eq!(
            rootc.hash(),
            root1.hash(),
            "expected equal Root hashes:\n{:?}\n\n{:?}",
            rootc,
            root1
        );

        assert!(rootc.is_confirmed(), "expected root to be confirmed");
    }

    // #[test]
    // #[serial]
    // fn test_update_root_smt() {
    //     let db_read = DatabaseR(get_test_postgres_connection());
    //     let db_write = DatabaseW(get_test_postgres_connection());
    //     let sc_entity = test_sc_entity();
    //
    //     let (_, new_root) = sc_entity
    //         .update_smt_db(
    //             &db_read,
    //             &db_write,
    //             &"1dcaca3b140dfbfe7e6a2d6d7cafea5cdb905178ee5d377804d8337c2c35f62e".to_string(),
    //             &"026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e".to_string(),
    //         )
    //         .unwrap();
    //
    //     let current_root = db_root_get(&db_read, &db_root_get_current_id(&db_read).unwrap())
    //         .unwrap()
    //         .unwrap();
    //     assert_eq!(new_root.hash(), current_root.hash());
    // }
}
