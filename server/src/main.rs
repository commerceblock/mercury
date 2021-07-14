#![feature(proc_macro_hygiene, decl_macro)]

extern crate server_lib;
use server_lib::{server, Database, PGDatabase};

fn main() {
    server::get_server::<PGDatabase, PGDatabase>(
        None,
        PGDatabase::get_new(),
        PGDatabase::get_new(),
    )
    .map_err(|e| {dbg!(format!("error initializing server: {}", &e)); e})
    .unwrap()
    .launch();
}
