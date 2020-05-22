//
extern crate hex;
extern crate bitcoin;
extern crate rocket;
extern crate rocket_contrib;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

pub mod util;
pub mod structs;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Root {
    pub id: u32,
    pub value: Option<[u8;32]>
}
