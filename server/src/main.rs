use server_lib::{server, Database, PGDatabase};

fn main() {
    server::get_server::<PGDatabase>(None, PGDatabase::get_new())
        .unwrap()
        .launch();
}
