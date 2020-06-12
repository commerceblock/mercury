# Mercury Server

## Introduction
Mercury Server is a RESTful web service exposing APIs for state chain functionality and two party ECDSA key generation and signing.

## Installation
### Launching the server
```bash
git clone https://github.com/commerceblock/mercury.git
cd mercury/server
cargo run --release
```

* By default, the server will use a local [RocksDB](https://rocksdb.org/).<br>

* By default, the server will use no authentication (PASSTHROUGH).<br>

### Running tests
Ensure testing_mode is set to "true" in `Settings.toml`.
#### Without timing output
```bash
RUST_TEST_THREADS=1 cargo test
```

#### With timing output
```bash
RUST_TEST_THREADS=1  cargo test -- --nocapture
```
