use super::super::{Result, Config};
use crate::error::SEError;
use rocksdb::DB;
use serde;
use shared_lib::Root;
use crate::mainstay::Hash;
use crate::mainstay;
use rocket::State;
use crate::shared_lib::mainstay::Attestable;
use crate::shared_lib::mainstay::CommitmentIndexed;

static ROOTID: &str = "rootid";
pub static DB_LOC: &str = "./db";
pub static DB_SC_LOC: &str = "./db-statechain";


pub trait MPCStruct {
    fn to_string(&self) -> String;

    fn to_table_name(&self, env: &str) -> String {
        format!("{}_{}", env, self.to_string())
    }

    fn require_customer_id(&self) -> bool {
        true
    }
}

fn idify(user_id: &str, id: &str, name: &dyn MPCStruct) -> String {
    format!("{}_{}_{}", user_id, id, name.to_string())
}

pub fn insert<T>(db: &DB, user_id: &str, id: &str, name: &dyn MPCStruct, v: T) -> Result<()>
where
    T: serde::ser::Serialize,
{
    let identifier = idify(user_id, id, name);
    debug!("Inserting in db ({})", identifier);

    insert_by_identifier(db, &identifier, v)
}

pub fn get<T>(db: &DB, user_id: &str, id: &str, name: &dyn MPCStruct) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    let identifier = idify(user_id, id, name);
    debug!("Getting from db ({})", identifier);

    get_by_identifier(db, &identifier)
}

pub fn remove(db: &DB, user_id: &str, id: &str, name: &dyn MPCStruct) -> Result<()> {
    let identifier = idify(user_id, id, name);
    debug!("Getting from db ({})", identifier);

    match db.delete(identifier) {
        Err(e) => return Err(SEError::Generic(e.to_string())),
        Ok(_) => Ok(())
    }
}


fn idify_root(id: &u32) -> String {
    format!("{}_{}", id, String::from("root"))
}


fn insert_by_identifier<T>(db: &DB, identifier: &str, item: T) -> Result<()>
where
    T: serde::ser::Serialize,
{
    let item_string = serde_json::to_string(&item).unwrap();
    match db.put(&identifier, &item_string) {
        Err(e) => Err(SEError::Generic(e.to_string())),
        Ok(_) => Ok(())
    }
}

fn get_by_identifier<T>(db: &DB, identifier: &str) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    match db.get(identifier) {
        Err(e) => return Err(SEError::Generic(e.to_string())),
        Ok(res) => {
            match res {
                Some(vec) => return Ok(serde_json::from_slice(&vec).unwrap()),
                None => return Ok(None)
            }
        }
    }
}

//Update the database and the mainstay slot with the SMT root, if applicable
pub fn update_root(state: &State<Config>, root: Hash) -> Result<()>{
    update_root_db(&state.db, root)?;
    update_root_mainstay(&state.mainstay_config, root)?;
    Ok(())  
}

fn update_root_mainstay(config: &Option<mainstay::Config>, root: Hash) -> Result<()>{
    match config {
        Some(c) => {
           match root.attest(&c) {
                Ok(_) => {
                    match mainstay::CommitmentInfo::from_attestable(c,&root){
                        Ok(_) => Ok(()),
                        Err(e) => Err(SEError::SharedLibError(e.to_string()))
                    }
                },
                Err(e) => Err(SEError::SharedLibError(e.to_string()))
            }
        },
        None => Ok(())
    }
}

/// Update state chain root value
fn update_root_db(db: &DB, new_root: [u8;32]) -> Result<()> {
        // Get previous ID
        let mut id = match get_by_identifier(db, ROOTID)? {
            None =>  0,
            Some(id_option) => id_option
        };

        // update id
        id = id + 1;
        let identifier = idify_root(&id);
        insert_by_identifier(&db, &identifier, new_root.clone())?;

        //update root id
        insert_by_identifier(&db, ROOTID, id.clone())?;

        debug!("Updated root at id {} with value: {:?}", id, new_root);
        Ok(())
}

/// get root with id
pub fn get_root<T>(db: &DB, id: &u32) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    get_by_identifier(db, &idify_root(&id))
}

/// get current statechain Root. This should be done via Mainstay in the future
pub fn get_current_root<T>(db: &DB) -> Result<Root>
where
    T: serde::de::DeserializeOwned,
{
    // Get previous ID
    let id = match get_by_identifier(db, ROOTID)? {
        None =>  0,
        Some(id_option) => id_option
    };

    Ok(Root {
        id,
        value: get_root(db, &id)?
    })
}


#[cfg(test)]
mod tests {

    use super::*;
    use rocksdb::Options;
    const TEST_DB_LOC: &str = "/tmp/db-statechain";

    #[test]
    fn test_db_get_insert() {
        let db = rocksdb::DB::open_default(TEST_DB_LOC).unwrap();

        let root = String::from("12345");
        let id = String::from("0");
        let insert_res = insert_by_identifier(&db, &id, root.clone());
        assert!(insert_res.is_ok());

        let get_res: Option<String> = get_by_identifier(&db, &id).unwrap();
        assert_eq!(get_res, Some(root));

        let get_res2: Option<String> = get_by_identifier(&db, &String::from("1")).unwrap();
        assert!(get_res2.is_none());

        let _ = rocksdb::DB::destroy(&Options::default(), TEST_DB_LOC);
    }

    #[test]
    fn test_db_root_update() {
        let db = rocksdb::DB::open_default(TEST_DB_LOC).unwrap();
        let root1: [u8;32] = [1;32];
        let root2: [u8;32] = [2;32];

        let _ = update_root_db(&db, root1.clone());
        let _ = update_root_db(&db, root2.clone());

        let root2_id: u32 = get_by_identifier(&db, ROOTID).unwrap().unwrap();
        assert_eq!(root2, get_by_identifier::<[u8;32]>(&db, &idify_root(&root2_id)).unwrap().unwrap());
        let root1_id = root2_id - 1;
        assert_eq!(root1, get_by_identifier::<[u8;32]>(&db, &idify_root(&root1_id)).unwrap().unwrap());

        let new_root = get_current_root::<[u8;32]>(&db).unwrap();
        assert_eq!(root2, new_root.value.unwrap());

        // remove them after incase of messing up other tests
        let _ = db.delete(&idify_root(&root2_id));
        let _ = db.delete(&idify_root(&root1_id));

        let _ = rocksdb::DB::destroy(&Options::default(), TEST_DB_LOC);
    }
}
