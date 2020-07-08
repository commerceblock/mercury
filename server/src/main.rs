use server_lib::server;

fn main() {
    server::get_server().unwrap().launch();
}
