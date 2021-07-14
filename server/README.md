# Mercury Server

## Introduction
Mercury Server is a RESTful web service exposing an API for StateChain functionality which is based on 2P-ECDSA key generation, signing and key transfer.

## Installation

### Configuration
Settings can be toggled in `Settings.toml` or via environment variables of the form `MERC_{param}`, where
`param` is the uppercase of parameters in the table below. Environment variables override Settings.toml.

Database connection information should be provided via the environment variables
`MERC_DB_HOST_`, `MERC_DB_PORT_`, `MERC_DB_USER_`, `MERC_DB_PASS_`, `MERC_DB_DATABASE_` with suffix one of,
`W` or `R`, where `W` is the database for writes and `R` the database for reads.

The server can be run in one of 3 modes by selecting the `MERC_MODE` environment variable: "core", which runs the core server only, "conductor" which runs a swap conductor server only, or "both" which includes both of these functions in the same server. The default is "both".

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
| WATCH_ONLY | bool | If true, server watches blockheight for backup tx broadcast |
| MODE       | String | Server mode: "conductor", "core" or "both". Default is "both" |
| BITCOIND | String | RPC connection to bitcoind - username:password@host:port - empty string causes no connection or watch function |
| LOCKBOX | \[String\] | Array of URLs of the secret key lockbox |
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


### Running tests

#### Without timing output
```bash
cargo test
```
