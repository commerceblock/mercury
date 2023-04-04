## Test Tutorial

This tutorial details how to manually test the three components of this project on testnet: `server`, `wallet daemon` and `wallet cli`.

### 1. Start Bitcoin Core

Both the server and the wallet connect to an Electrum server which requires Bitcoin Core.

```bash
$ curl -O https://bitcoincore.org/bin/bitcoin-core-24.0.1/bitcoin-24.0.1-x86_64-linux-gnu.tar.gz
$ tar -xf bitcoin-24.0.1-x86_64-linux-gnu.tar.gz
$ cd bitcoin-24.0.1
$ ./bin/bitcoind --testnet
```

### 2. Start Electrs

```bash
$ sudo apt update
$ sudo apt install -y clang cmake build-essential git cargo 
$ git clone https://github.com/romanz/electrs.git
$ cd electrs
$ cargo build --locked --release
$ ./target/release/electrs --log-filters=INFO --db-dir ./db --daemon-dir ~/.bitcoin --network testnet --electrum-rpc-addr="127.0.0.1:50001"
```

### 3. Start the Server (State Entity)

```bash
git clone https://github.com/commerceblock/mercury.git
```

Change the following properties in `server/Settings.toml`:

```bash
electrum_server = "127.0.0.1:50001"
```

Then run the server.

```bash
$ cd mercury/server
$ cargo run
```

### 4. Start the first wallet

Change the following properties in `mercury/client/Settings.toml`:

```bash
electrum_server = "127.0.0.1:50001"
testing_mode = "false" # Use testing wallet
```

`testing_mode` refers to whether or not to use the test wallet. The test wallet is always the same and when this option is enabled, the electrums server is not used.

Then run the daemon

```bash
$ cd mercury/client
$ cargo run --bin run_wallet_daemon
```

If the Electrum Server is not running, the daemon will fail to start.

### 5. Start the second wallet

Clone the `mercury` project in a new folder.

```bash
cd ~ # or any other directory
git clone https://github.com/commerceblock/mercury.git mercury2
cd mercury2
```

Change the following properties in `mercury2/client/Settings.toml`:

```bash
electrum_server = "127.0.0.1:50001"
testing_mode = "false" # Use testing wallet
daemon_address = "/tmp/rustd2.sock"
```

The `daemon_address` needs to be different for each wallet.

run the daemon

```bash
$ cd mercury2/client
$ cargo run --bin run_wallet_daemon
```

### 6. Test connection to State Entity

```bash
$ cd mercury/client
$ cargo run --bin cli -- state-entity fee-info
```

This should return something like:

```bash
Fee address: tb1qzvv6yfeg0navfkrxpqc0fjdsu9ey4qgqqsarq4,
Deposit fee rate: 0
Withdrawal fee rate: 300
Lock interval: 10
Initial lock: 1000
```

The second wallet (`mercury2/client`) should also succesfully return the fee info.

### 7. Generate new address

On both wallets, run `cargo run --bin cli --wallet -a` and send some coins to the address shown.

### 8. Confirm the balance

The wallet balance can be verified with:

```bash
cargo run --bin cli -- wallet -b
```

Wait until there is enough amount confirmed before proceeding to the next step.

This command, for unknown reason so far, sometimes throws the below error.

In this case, it is necessary to stop the daemon, run it again and run the command again.

```
thread 'tokio-runtime-worker-0' panicked at 'called `Result::unwrap()` on an `Err` value: Error("missing field `id`", line: 1, column: 256)', client/src/wallet/wallet.rs:537:14
```
or
```
thread 'tokio-runtime-worker-0' panicked at 'called `Result::unwrap()` on an `Err` value: Error("invalid value: integer `-1492471`, expected u64", line: 1, column: 76)', client/src/wallet/wallet.rs:537:14
```

Usually, this error happens when there is an unconfirmed balance in the wallet, but it is not the only situation in which it happens.

### 9. Deposit to State entity

Convert some value to statecoin.

```
cargo run --bin cli -- wallet deposit -a 500000 
```

This command returns:

* `State Chain ID`: Represents the statecoin
* `Funding Txid`: The 2-of-2 multisig transaction between a wallet key and the state entity key
* `Backup Transaction hex`: Transaction that returns funds to the wallet

### 10. Generate State entity Address

```bash
cargo run --bin cli -- wallet se-addr 
```

This command generates a statechain address to receive the statecoin created in the previous step.

### 11. Transfer Statecoin (Sender)

Choose a wallet to be the sender and run the following command:

```bash
cargo run --bin cli -- wallet transfer-sender -a <recipient-statechain-address> -i <sender-state-chain-id>
```

* `<recipient-statechain-address>` is the address generated in the previous step on the recipient's wallet.
* `<sender-state-chain-id>` is the statecoin id generated in step 9 in the sender's wallet.

The list of existing statechain ids can be obtained with the `cargo run --bin cli -- wallet -b` command in the sender's wallet.

This command returns a `Transfer Message` that needs to be sent to the recipient.

### 12. Transfer State Chain (Receiver)

In the recipient wallet, run the command:

```bash
cargo run --bin cli -- wallet transfer-receiver -m "<transfer-message>"
```

This command returns:

* `StateChain ID`: The id of the new statecoin.
* `Value`: Value of the new statecoin.
* `Locktime`: The `nLocktime` of the transaction.
* `Backup Transaction hex`: Transaction that returns funds to the sender

### 12. Swap State Chain

The swap operation is apparently not working due to timeout or "Backup Tx receiving address not found in this wallet!" error.

But the command to run it is:

```bash
cargo run --bin cli -- wallet swap -i <state-chain-id> -s <swap-size>
```

For this tutorial, this command can be run for each wallet, using 2 as the swap size.

To get some statechain id, `cargo run --bin cli -- wallet -b` can be used. If there are none, a new deposit needs be made, as described in step #9.

### 13. Withdraw from State entity

The statecoin can be withdrawn from State entity.

```bash
cargo run --bin cli -- wallet withdraw -i <state-chain-id>
```