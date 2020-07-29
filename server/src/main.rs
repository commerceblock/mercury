use server_lib::server;

fn main() {
    server::get_server(false).unwrap().launch();
}
