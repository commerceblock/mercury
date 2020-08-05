# Mercury Server

## Introduction
Mercury Server is a RESTful web service exposing APIs for state chain functionality and two party ECDSA key generation and signing.

## Installation

### Configuration
Settings can be toggled in `Settings.toml` or via environment variables of the form `MERC_[SETTING]`, where
`setting` is the uppercase of parameters in `Settings.toml`.

Database connection information should be provided via the environment variables
`MERC_DB_HOST_`, `MERC_DB_PORT_`, `MERC_DB_USER_`, `MERC_DB_PASS_`, `MERC_DB_DATABASE_` with suffix one of,
`W` or `R`, where `W` is the database for writes and `R` the database for reads.


### Launching the server
```bash
git clone https://github.com/commerceblock/mercury.git
cd mercury/server
cargo run --release
```

* By default, the server will use a local [RocksDB](https://rocksdb.org/).<br>

* By default, the server will use no authentication (PASSTHROUGH).<br>

### Running tests
Ensure a testing DB connection has been specified with environment variables `MERC_DB_HOST_W`,
`MERC_DB_PORT_W`, `MERC_DB_USER_W`, `MERC_DB_PASS_W`, `MERC_DB_DATABASE_W`.

#### Without timing output
```bash
RUST_TEST_THREADS=1 cargo test
```

#### With timing output
```bash
RUST_TEST_THREADS=1  cargo test -- --nocapture
```
