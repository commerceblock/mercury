use super::super::Result;
use crate::error::SEError;
use rocksdb::DB;
use serde;
use shared_lib::Root;
use crate::mainstay::{Hash, CommitmentInfo};
use crate::mainstay;
use crate::shared_lib::mainstay::{Attestable, CommitmentIndexed, MainstayError};
#[allow(unused_imports)]
use std::str::FromStr;

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

fn idify_commitment_info(id: &u32) -> String {
    format!("{}_{}", id, String::from("commitment_info"))
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
                Some(vec) => {
                    match serde_json::from_slice(&vec){
                        Ok(obj) => Ok(Some(obj)),
                        Err(e) => Err(SEError::Generic(e.to_string()))
                    }
                },
                None => return Ok(None)
            }
        }
    }
}

//Update the database with the latest available mainstay attestation info
pub fn update_root_attestation(db: &DB, mc: &Option<mainstay::Config>) -> Result <()>{

    fn update_db_from_ci(db: &DB, ci: &CommitmentInfo) -> Result<()>{
        let mut root = Root::from_commitment_info(ci);
        let current_id = get_current_root_id(db)?;
        let mut id;
        for x in 0..=current_id {
            id = current_id-x;
            match get_root_from_id::<Root>(db, &id)?{
                Some(r) => {
                    if r.hash() == ci.commitment().to_hash() {
                        match r.id(){
                            Some(r_id) => {
                                root.set_id(&r_id);
                                break;
                            },
                            None => ()
                        }
                    }
                },
                None => ()
            };  
        }

        let root = root;

        match update_root_db(db, &root){
            Ok(_) => Ok(()),
            Err(e) => Err(e)
        }
    }

    match mc {
        Some(conf)=>{
            match &get_confirmed_root::<Root>(db, mc)?{
                Some(cr_db) => {
                    match &CommitmentInfo::from_latest(conf){
                        Ok(ci) => {
                            match cr_db.commitment_info(){
                                Some(ci_db) => {
                                    if ci_db == ci {
                                       
                                        Ok(())
                                    }  else {
                                        update_db_from_ci(db, ci)
                                    }
                                },
                                None => {
                                    update_db_from_ci(db, ci)
                                }
                            }     
                        },
                        Err(e) => Err(SEError::SharedLibError(e.to_string()))
                    }
                },
                None => {
                    match &CommitmentInfo::from_latest(conf){
                        Ok(ci) => update_db_from_ci(db, ci),
                        Err(e) => Err(SEError::SharedLibError(e.to_string()))
                    }                    
                }
                
            }
        },
        None => Ok(())
    }
}

//Update the database and the mainstay slot with the SMT root, if applicable
pub fn update_root(db: &DB, mc: &Option<mainstay::Config>, root: &Root) -> Result<u32>{
    let id = update_root_db(db, root)?;
    update_root_mainstay(mc, root)?;
    Ok(id)  
}

fn update_root_mainstay(config: &Option<mainstay::Config>, root: &Root) -> Result<()>{
    match config {
        Some(c) => match root.attest(&c){
            Ok(_)=> Ok(()),
            Err(e) => Err(SEError::SharedLibError(e.to_string()))
        },
        None => Ok(())
    }
}


/// Update state chain root value
fn update_root_db(db: &DB, rt: &Root) -> Result<u32> {
    let mut root = rt.clone();
        // Get previous ID, or use the one specified in root to update an existing root with mainstay proof
        let id = match root.id(){
            //This will update an existing root in the db
            Some(id) => {
                let existing_root = get_root_from_id::<Root>(db, &id)?;
                match existing_root {
                    None => return Err(SEError::Generic(format!("error updating existing root - root not found with id {}", id))),
                    Some(r) => {
                        if r.hash() != root.hash() {
                            return Err(SEError::Generic(format!("error updating existing root - hashes do not match: existing: {} update: {}", r, root)));
                        }
                        id
                    }
                }
            },
            // new root, update id
            None => get_current_root_id(db)? + 1,
        };
        
        let identifier = idify_root(&id);
        root.set_id(&id);
        insert_by_identifier(&db, &identifier, root.clone())?;

        //update root id
        insert_by_identifier(&db, ROOTID, id)?;

        debug!("Updated root at id {} with value: {}", id, root);
        Ok(id)
}

/// get root with id
pub fn get_root<T>(db: &DB, id: &u32) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    
    get_by_identifier(db, &idify_root(&id))
}

pub fn get_current_root_id(db: &DB) -> Result<u32> {
    // Get previous ID
    match get_by_identifier::<u32>(db, ROOTID)? {
        None =>  Ok(0),
        Some(id_option) => Ok(id_option)
    }
}

pub fn get_current_attested_root_id(db: &DB) -> Result<u32> {
    // Get previous ID
    match get_by_identifier::<u32>(db, ROOTID)? {
        None =>  Ok(0),
        Some(id_option) => Ok(id_option)
    }
}



/// get current statechain Root. 
pub fn get_current_root<T>(db: &DB) -> Result<Option<Root>>
where

   T: serde::de::DeserializeOwned,
{   
    
    let id = &get_current_root_id(db)?;
    get_root_from_id::<Root>(db, id)
}

fn get_root_from_id<T>(db: &DB, id: &u32) -> Result<Option<Root>> 
where

   T: serde::de::DeserializeOwned,
{
    
    Ok(get_root::<Root> (db, &id)?)
}

pub fn get_confirmed_root<T>(db: &DB, mc: &Option<mainstay::Config>) -> Result<Option<Root>>
where

   T: serde::de::DeserializeOwned,
{
    let current_id = get_current_root_id(db)?;

    for i in 0..=current_id {
        let id = current_id - i;
        let root = get_root_from_id::<Root>(db, &id)?;
        match root{
            Some(r) => {
                if r.is_confirmed() {
                    return Ok(Some(r));
                }
                ()
            },
            None => ()
        };
    }

    Ok(None)
}

 //Delete all the roots from the db
 fn delete_all_roots(db: &DB){
     let _ = insert_by_identifier(&db, ROOTID, 0u32);
    let current_id = get_current_root_id(db).unwrap();  
    for x in 0..=current_id {
        let id = current_id - x;
        let _ = db.delete(&idify_root(&id));
    }
    let _ = insert_by_identifier(&db, ROOTID, 0u32);
}


#[cfg(test)]
mod tests {

    use super::*;
    use rocksdb::Options;
    const TEST_DB_LOC: &str = "/tmp/db-statechain";

            
    #[test]
    #[serial]
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
    #[serial]
    fn test_db_root_update() {
        let db = rocksdb::DB::open_default(TEST_DB_LOC).unwrap();
        let root1: Root = Root::from_random();
        let root2: Root = Root::from_random();

        let _ = update_root_db(&db, &root1);
        let _ = update_root_db(&db, &root2);

        let root2_id: u32 = get_by_identifier(&db, ROOTID).unwrap().unwrap();
        assert_eq!(root2.hash(), get_by_identifier::<Root>(&db, &idify_root(&root2_id)).unwrap().unwrap().hash());
        let root1_id = root2_id - 1;
        assert_eq!(root1.hash(), get_by_identifier::<Root>(&db, &idify_root(&root1_id)).unwrap().unwrap().hash());

        let new_root = get_current_root::<Root>(&db).unwrap().unwrap();
        assert_eq!(root2.hash(), new_root.hash());

        // remove them after incase of messing up other tests
        let _ = db.delete(&idify_root(&root2_id));
        let _ = db.delete(&idify_root(&root1_id));

        let _ = rocksdb::DB::destroy(&Options::default(), TEST_DB_LOC);
    }

    #[test]
    #[serial]
    fn test_db_commitment_info_update() {
        let mc = mainstay::Config::from_test();
        assert!(mc.is_some(),"To configure mainstay tests set the following environment variables: MERC_MS_TEST_SLOT=<slot> MERC_MS_TEST_TOKEN=<token>");

        let db = rocksdb::DB::open_default(TEST_DB_LOC).unwrap();
        //delete_all_roots(&db);

        //root1 has already been attested to mainstay
        let com1 = mainstay::Commitment::from_str("ade8d33571d52014537a76b2c0c0062442b70d73f469094cb45dc69615f5e218").unwrap();
        let root1 = Root::from_hash(&com1.to_hash());
        let root2: Root = Root::from_random();

        let root1_id = match update_root(&db, &mc, &root1){
            Ok(id) => id,
            Err(e) => {
                assert!(false, e.to_string());
                0
            }
        };

        //assert!(update_root(&db, &mc, root1.clone()).is_ok());
        assert!(update_root(&db, &mc, &root2).is_ok());

        //Update root attestations to get mainstay confirmation into DB
        assert!(update_root_attestation(&db, &mc).is_ok()); 

        //Update the local copy of root1
        let root1 = get_root_from_id::<Root>(&db, &root1_id).unwrap().unwrap();

        //assert!(root1.is_confirmed(), format!("not confirmed: {}", root1));
        assert!(root2.is_confirmed() == false);

        //delete_all_roots(&db);
        //assert that there is a confirmed root
        assert!(get_confirmed_root::<Root>(&db,&mc).unwrap().unwrap().is_confirmed());

        let _ = rocksdb::DB::destroy(&Options::default(), TEST_DB_LOC);
    }
}
