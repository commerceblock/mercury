Mercury
=====================================
Mercury is a [statechain](https://github.com/RubenSomsen/rubensomsen.github.io/blob/master/img/statechains.pdf) client/server implementation modified to be compatible with current Bitcoin network technology.

Ownership of deposited Bitcoin (or Elements based) UTXOs can be transferred between parties without performing on-chain transactions. This allows for near instant payments, increased privacy and novation of DLCs/Lightning Channels.

Swaps are a method of performing many off-chain transfers atomically. The number of participants in a swap is unlimited. If `n` participants take part in a swap with one distinct UTXO each they receive back ownership of any one of the `n` UTXOs of the same value. 

This repository contains the Server and Client implementation for the protocol. For more information on the components of Mercury see their respective crates.

You can read the whitepaper [here](doc/statechains.md).

## Running / Building from code

### 1. Install dependencies:

* Ubuntu 20.04 / 21.10

 ```
 sudo apt install -y build-essential libssl-dev python3-dev libgmp-dev
 ```

* Ubuntu 22.04

Ubuntu 22.04 comes with OpenSSL 3.0.0 or higher installed. This project is only compatible with version 1.1.1.
As it is not recommended to downgrade OpenSSL, it is better to run this project in a VM if using Ubuntu 22.04.

```
# download binary openssl packages from Impish builds
wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/openssl_1.1.1f-1ubuntu2.17_amd64.deb
wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl-dev_1.1.1f-1ubuntu2.17_amd64.deb
wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.17_amd64.deb

# install downloaded binary packages
sudo dpkg -i libssl1.1_1.1.1f-1ubuntu2.17_amd64.deb
sudo dpkg -i libssl-dev_1.1.1f-1ubuntu2.17_amd64.deb
sudo dpkg -i openssl_1.1.1f-1ubuntu2.17_amd64.deb

sudo apt install -y build-essential libssl-dev python3-dev libgmp-dev
```

* Fedora 35

 ```
sudo yum install -y openssl-devel python3-devel gmp-devel.x86_64
 ```
### 2. Clone the project and Change to specific version of Rust Nightly:

```
git clone https://github.com/commerceblock/mercury.git
cd mercury/
rustup toolchain install nightly-2021-07-16
rustup override set nightly-2021-07-16-x86_64-unknown-linux-gnu
```

### 4. Export Env Vars

The env vars below must be filled with a local (or remote) Postgres instance.
The values for the `R` and `W` variables can be the same.

```
export MERC_DB_HOST_R=
export MERC_DB_HOST_W=
export MERC_DB_PORT_R=
export MERC_DB_PORT_W=
export MERC_DB_USER_R=
export MERC_DB_USER_W=
export MERC_DB_PASS_R=
export MERC_DB_PASS_W=
export MERC_DB_DATABASE_R=
export MERC_DB_DATABASE_W=
```

### 4. Run server

```
cd server
cargo run
```

### 4. Run the client

1. First run the wallet deamon

```
cd client
cargo run --bin run_wallet_daemon
```

2. Then run the CLI

```
cargo run --bin cli -- wallet --help
cargo run --bin cli -- wallet -a
```

### 5. Build server and client

```
cargo buid --release

# Run the server
./target/release/server_exec

# Run deamon
cp client/Settings.toml .
mkdir wallet
./target/release/run_wallet_daemon

# Run the wallet CLI
./target/release/cli wallet -a
```

> **_NOTE:_**  The Mercury Wallet and Client do not support OpenSSL 3.0.0 or higher. Version 1.1.1 must be used. Running them on Ubuntu 22.04 requires downgrading the OpenSSL version to 1.1.1.

Running / Building from Docker
-------

Run steps:
To run the software, use Docker image from DockerHub.

1. Download and start: ```docker run --rm -it -p 8000:8000 commerceblock/mercury server```
2. Test: ```curl -vk localhost:8000/ping```

Build steps:
To build the software use Dockerfile provided.

1. Clone repo
2. Build: ```cd mercury && docker build -t commerceblock/mercury:my_build .```
3. Run: ```docker run --rm -it -p 8000:8000 commerceblock/mercury:my_build server```
4. Test: ```curl -vk localhost:8000/ping```

Tests
-------

To run the tests:
1. ```cargo test```

To run integration tests with a real database - database and mainstay environment variables should be set. See server/README.
1. ```(cd integration-tests && cargo test --no-default-features -- --test-threads=1)```

# Issue Tracker

# License

Mercury Wallet is released under the terms of the GNU General Public License. See for more information https://opensource.org/licenses/GPL-3.0
