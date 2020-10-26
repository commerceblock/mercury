# Integration tests

Runs the State Entity server and tests with basic client implementation.<br>

Ensure testing_mode is set to "true" in `Settings.toml`.

To run integration tests with a real database - database and mainstay environment variables should be set. See server/README.
1. ```(cd integration-tests && cargo test --no-default-features -- --test-threads=1)```
