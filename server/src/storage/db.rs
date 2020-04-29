// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//
use super::super::Result;
use crate::error::SEError;
use rocksdb;
use serde;

use super::aws;

pub enum DB {
    Local(rocksdb::DB),
    AWS(rusoto_dynamodb::DynamoDbClient, String),
}

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
    match db {
        DB::AWS(dynamodb_client, env) => {
            let table_name = name.to_table_name(env);
            match aws::dynamodb::insert(&dynamodb_client, user_id, id, &table_name, v) {
                Err(e) => Err(SEError::Generic(e.to_string())),
                Ok(_) => Ok(())
            }
        }
        DB::Local(rocksdb_client) => {
            let identifier = idify(user_id, id, name);
            let v_string = serde_json::to_string(&v).unwrap();
            match rocksdb_client.put(identifier.as_ref(), v_string.as_ref()) {
                Err(e) => Err(SEError::Generic(e.to_string())),
                Ok(_) => Ok(())
            }
        }
    }
}

pub fn get<T>(db: &DB, user_id: &str, id: &str, name: &dyn MPCStruct) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    match db {
        DB::AWS(dynamodb_client, env) => {
            let table_name = name.to_table_name(env);
            println!("table_name = {}", table_name);
            let require_customer_id = name.require_customer_id();
            println!("require_customer_id = {}", require_customer_id);
            println!("user_id = {}", user_id);
            println!("id = {}", id);
            match aws::dynamodb::get(&dynamodb_client, user_id, id, table_name, require_customer_id) {
                Err(e) => Err(SEError::Generic(e.to_string())),
                Ok(res) => {
                    println!("res.is_none() = {}", res.is_none());
                    Ok(res)
                }
            }
        }
        DB::Local(rocksdb_client) => {
            let identifier = idify(user_id, id, name);
            debug!("Getting from db ({})", identifier);

            let db_option: Option<rocksdb::DBVector>;
            match rocksdb_client.get(identifier.as_ref()) {
                Err(e) => return Err(SEError::Generic(e.to_string())),
                Ok(res) => db_option = res
            };
            let vec_option: Option<Vec<u8>> = db_option.map(|v| v.to_vec());
            match vec_option {
                Some(vec) => Ok(serde_json::from_slice(&vec).unwrap()),
                None => Ok(None),
            }
        }
    }
}
