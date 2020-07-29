# Mercury Server

## Introduction
Mercury Server is a RESTful web service exposing APIs for state chain functionality and two party ECDSA key generation and signing.

## Installation

### Configuration
Settings can be toggled in `Settings.toml`.

Database connection information should be provided via the environment variables
`DB_HOST_`, `DB_PORT_`, `DB_USER_`, `DB_PASS_`, `DB_DATABASE_` with suffix one of
`TEST`, `W` or `R`, where `W` is the database for writes and `R` the database for reads.


### Launching the server
```bash
git clone https://github.com/commerceblock/mercury.git
cd mercury/server
cargo run --release
```

* By default, the server will use a local [RocksDB](https://rocksdb.org/).<br>

* By default, the server will use no authentication (PASSTHROUGH).<br>

### Running tests
Ensure a testing DB connection has been specified with environment variables `DB_HOST_TEST`,
`DB_PORT_TEST`, `DB_USER_TEST`, `DB_PASS_TEST`, `DB_DATABASE_TEST`.
#### Without timing output
```bash
RUST_TEST_THREADS=1 cargo test
```

#### With timing output
```bash
RUST_TEST_THREADS=1  cargo test -- --nocapture
```
