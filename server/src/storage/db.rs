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
//Attested root id
static ATTROOTID: &str = "attrootid";
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
                Some(vec) => return Ok(serde_json::from_slice(&vec).unwrap()),
                None => return Ok(None)
            }
        }
    }
}

//Update the database with the latest available mainstay attestation info
pub fn update_root_attestation(db: &DB, mc: &Option<mainstay::Config>) -> Result <()>{
    match mc {
        Some(conf)=>{
            match GetCommitmentInfo::new(db, mc).noupdate().run()?{
                Some(ci_db) => {
                    match CommitmentInfo::from_latest(conf){
                        Ok(ci) => {
                            if ci_db == ci {
                                println!("commitment info is in db");
                                Ok(())
                            }  else {
                                println!("commitment info is not in db, adding");
                                update_commitment_info(db, &ci)?;
                                Ok(())        
                            }
                        },
                        Err(e) => Err(SEError::SharedLibError(e.to_string()))
                    }
                },
                None => {
                    println!("commitment info is not in db, adding");
                    match &CommitmentInfo::from_latest(conf){
                        Ok(ci) => update_commitment_info(db, &ci),
                        Err(e) => Err(SEError::SharedLibError(e.to_string()))
                    }                    
                }
                
            }
        },
        None => Ok(())
    }
}

struct GetCommitmentInfo<'a> {
    db: &'a DB,
    mainstay_config: &'a Option<mainstay::Config>,
    update: bool
}

/// get commitment info with commitment:
//A command builder that updates the root attestations by default
//The default behaviour can be changed by calling noupdate()
//e.g. GetCommitmentInfo::new(db,mc,comm).noupdate().run()
impl<'a> GetCommitmentInfo<'a> {
    fn new(db: &'a DB, mc: &'a Option<mainstay::Config>) -> Self {
        Self {db: db, mainstay_config: mc, update: true}
    }

    fn noupdate(&mut self) -> &Self {
        self.update=false;
        self
    }

    fn run(&self) -> Result<Option<mainstay::CommitmentInfo>> {
        println!("db: get commitment info: run");
        if self.update{
            println!("updating root attestation");
            update_root_attestation(self.db, self.mainstay_config)?;            
        }
        let current_id = get_current_attested_root_id(self.db)?;
        let ident = idify_commitment_info(&current_id);
        println!("getting commitment info from identifier: {}", ident);
        debug!("getting commitment info from identifier: {}", ident);
        Ok(get_by_identifier(self.db, &ident)?)
    }
}

fn update_commitment_info(db: &DB, info: &mainstay::CommitmentInfo) -> Result<()>{

    let id = get_current_attested_root_id(db)?;

    let ident = idify_commitment_info(&id);

    insert_by_identifier(&db, &ident, info.clone())?;

    debug!("Updated commitment_info at id {} with value: {:?}", id, info);
    Ok(())
}

//Update the database and the mainstay slot with the SMT root, if applicable
pub fn update_root(db: &DB, mc: &Option<mainstay::Config>, root: Hash) -> Result<()>{
    update_root_db(db, root)?;
    update_root_mainstay(mc, root)?;
    Ok(())  
}

fn update_root_mainstay(config: &Option<mainstay::Config>, root: Hash) -> Result<()>{
    match config {
        Some(c) => match root.attest(&c){
            Ok(_)=> Ok(()),
            Err(e) => Err(SEError::SharedLibError(e.to_string()))
        },
        None => Ok(())
    }
}


/// Update state chain root value
fn update_root_db(db: &DB, new_root: [u8;32]) -> Result<()> {
        // Get previous ID
        let mut id = get_current_root_id(db)?;

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
pub fn get_current_root<T>(db: &DB, mc: &Option<mainstay::Config>) -> Result<Root>
where

   T: serde::de::DeserializeOwned,
{   
    println!("db: get current root");
    get_root_from_id::<Root>(db, mc, &get_current_root_id(db)?)
}

fn get_root_from_id<T>(db: &DB, mc: &Option<mainstay::Config>, id: &u32) -> Result<Root> 
where

   T: serde::de::DeserializeOwned,
{
    println!("db: get root from id");
    let root = get_root::<Hash> (db, &id)?;

    Ok(Root {
        id: *id,
        value: root,
        commitment_info: None
    })
}

fn get_confirmed_root<T>(db: &DB, mc: &Option<mainstay::Config>) -> Result<Root>
where

   T: serde::de::DeserializeOwned,
{
    let ci = match mc{
        Some(_) => {
            GetCommitmentInfo::new(db, mc).run()?
        },
        None => None
    };

    let id = 0;

    Ok(Root {
        id,
        value: None,
        commitment_info: ci
    })
}

#[cfg(test)]
mod tests {

    use super::*;
    use rocksdb::Options;
    const TEST_DB_LOC: &str = "/tmp/db-statechain";

    //Delete all the roots from the db
    fn delete_all_roots(db: &DB){
        let current_id = get_current_root_id(db).unwrap();  
        for x in 0..=current_id {
            let id = current_id - x;
            match get_root::<Hash>(db, &id){
                Ok(root) => {
                    match root {
                        Some(r) => {
                            let _ = db.delete(&idify_commitment_info(&mainstay::Commitment::from_hash(&r)));
                        },
                        None => ()
                    }
                },
                Err(_) => ()
            };
            let _ = db.delete(&idify_root(&id));
        }
    }
            
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
        let root1: [u8;32] = monotree::utils::random_hash();
        let root2: [u8;32] = monotree::utils::random_hash();

        let _ = update_root_db(&db, root1.clone());
        let _ = update_root_db(&db, root2.clone());

        let root2_id: u32 = get_by_identifier(&db, ROOTID).unwrap().unwrap();
        assert_eq!(root2, get_by_identifier::<[u8;32]>(&db, &idify_root(&root2_id)).unwrap().unwrap());
        let root1_id = root2_id - 1;
        assert_eq!(root1, get_by_identifier::<[u8;32]>(&db, &idify_root(&root1_id)).unwrap().unwrap());

        let new_root = get_current_root::<[u8;32]>(&db, &None).unwrap();
        assert_eq!(root2, new_root.value.unwrap());

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
        delete_all_roots(&db);

        //root1 has already been attested to mainstay
        let com1 = mainstay::Commitment::from_str("a886c4cc504984b271c0347b4a5a6f5802e15f92262bb75d263598b7192b7ef9").unwrap();
        let root1 = com1.to_hash();
        let root2: [u8;32] = monotree::utils::random_hash();

        match update_root(&db, &mc, root1.clone()){
            Ok(_) => (),
           Err(e) => assert!(false, e.to_string())
        };

        //assert!(update_root(&db, &mc, root1.clone()).is_ok());
        assert!(update_root(&db, &mc, root2.clone()).is_ok());

    
        //Get the commitment info for each of the roots
        let com2 = mainstay::Commitment::from_hash(&root2);
    
        let ci1 =  GetCommitmentInfo::new(&db, &mc, &com1).run().unwrap().unwrap();
        let ci2 =  GetCommitmentInfo::new(&db, &mc, &com2).run().unwrap();


        assert!(ci1.is_confirmed());
        assert!(ci2 == None);

        // remove them after incase of messing up other tests
        let _ = db.delete(&idify_commitment_info(&com1));
        let _ = db.delete(&idify_commitment_info(&com2));

        let _ = rocksdb::DB::destroy(&Options::default(), TEST_DB_LOC);
    }
}
