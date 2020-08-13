# Mercury Server

## Introduction
Mercury Server is a RESTful web service exposing APIs for state chain functionality and two party ECDSA key generation and signing.

## Installation

### Configuration
Settings can be toggled in `Settings.toml` or via environment variables of the form `MERC_{param}`, where
`param` is the uppercase of parameters in the table below. Environment variables override Settings.toml.

Database connection information should be provided via the environment variables
`MERC_DB_HOST_`, `MERC_DB_PORT_`, `MERC_DB_USER_`, `MERC_DB_PASS_`, `MERC_DB_DATABASE_` with suffix one of,
`W` or `R`, where `W` is the database for writes and `R` the database for reads.

| Parameter | Type | Description |
| ----------- | ----- | ----------- |
| ELECTRUM_SERVER | String | Network address of Electrum Server |
| NETWORK | String | Bitcoin network: "mainnet", "regtest", "testnet" | 
| BLOCK_TIME | int | Block time of network. This is useful for testing  | 
| TESTING_MODE | bool | If set to true then mock electrum server is used and DBs are reset upon restart |
| FEE_ADDRESS | String | Bitcoin address for StateChain Entity fees |
| FEE_DEPOSIT | int | Deposit fee in Satoshis |
| FEE_WITHDRAW | int | Withdraw fee in Satoshis |
| PUNISHMENT_DURATION | int | Time in seconds that a StateChain is punished for  
| BATCH_LIFETIME | int | Lifetime of batch-transfers |
| MS_SLOT | int | Mainstay slot |
| MS_TOKEN | String | Mainstay token |
| DB_HOST | String | Database host name |
| DB_PORT | String | Database port |
| DB_USER | String | Database user name |
| DB_PASS | String | Database password |
| DB_DATABASE | String | Database name |

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
