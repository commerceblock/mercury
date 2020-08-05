use server_lib;

mod tools;
use tools::spawn_test_server;

#[test]
fn regtest_deposit() {
    let client = spawn_test_server();
    // regtest_run_deposit();
}
