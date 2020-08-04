use server_lib;

mod tools;
use tools::spawn_test_server;

#[test]
fn regression_test_deposit() {
    let client = spawn_test_server();

}
