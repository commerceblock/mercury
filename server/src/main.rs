use server_lib::{server, PGDatabase, Database};

fn main() {
    server::get_server::<PGDatabase>(None, PGDatabase::get_test()).unwrap().launch();
}
