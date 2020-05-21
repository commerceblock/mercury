use super::super::Result;
use crate::error::SEError;
use rocksdb::DB;
use serde;

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


fn idify_root(id: &str) -> String {
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
                Some(vec) => return  Ok(serde_json::from_slice(&vec).unwrap()),
                None => return Ok(None)
            }
        }
    }
}


// Update state chain root value
pub fn update_root(db: &DB, new_root: [u8;32]) -> Result<()> {
        // Get previous ID
        let mut id: String;
        match get_by_identifier(db, ROOTID)? {
            None => id = String::from("0"),
            Some(id_option) => id = id_option
        }

        // update id
        id = (id.parse::<u32>().unwrap() + 1).to_string();

        let identifier = idify_root(&id);
        insert_by_identifier(&db, &identifier, new_root.clone())?;

        //update root id
        insert_by_identifier(&db, ROOTID, id.clone())?;

        debug!("Updated root at id {} with value: {:?}", id, new_root);
        Ok(())
}

// get current statechain root value
pub fn get_root<T>(db: &DB) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    // Get previous ID
    let id: String;
    match get_by_identifier(db, ROOTID)? {
        None => id = String::from("0"),
        Some(id_option) => id = id_option
    }

    get_by_identifier(db, &idify_root(&id))
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_db_get_insert() {
        let db = rocksdb::DB::open_default("/tmp/db-statechain").unwrap();

        let root = String::from("12345");
        let id = String::from("0");
        let insert_res = insert_by_identifier(&db, &id, root.clone());
        assert!(insert_res.is_ok());

        let get_res: Option<String> = get_by_identifier(&db, &id).unwrap();
        assert_eq!(get_res, Some(root));

        let get_res2: Option<String> = get_by_identifier(&db, &String::from("1")).unwrap();
        assert!(get_res2.is_none());
    }

    #[test]
    fn test_db_root_update() {
        let db = rocksdb::DB::open_default("/tmp/db-statechain").unwrap();
        let root1: [u8;32] = [1;32];
        let root2: [u8;32] = [2;32];

        let _ = update_root(&db, root1.clone());
        let _ = update_root(&db, root2.clone());

        let root2_id: String = get_by_identifier(&db, ROOTID).unwrap().unwrap();
        assert_eq!(root2, get_by_identifier::<[u8;32]>(&db, &idify_root(&root2_id)).unwrap().unwrap());
        let root1_id = (root2_id.parse::<u32>().unwrap() - 1).to_string();
        assert_eq!(root1, get_by_identifier::<[u8;32]>(&db, &idify_root(&root1_id)).unwrap().unwrap());

        let new_root: [u8; 32] = get_root(&db).unwrap().unwrap();
        assert_eq!(root2, new_root);
    }
}
