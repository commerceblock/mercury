# Mercury Client

## Introduction
Mercury client is a bitcoin minimalist decentralized wallet CLI app with a client side
state chain implementation.

## Requirement
Mercury server is required to interact with the client, for instruction on how to run it see [here](../server/README.md).

## Installation
```bash
git clone https://github.com/commerceblock/mercury.git
cd mercury/client
cargo build --release
```

## Using the CLI
The wallet is currently exposed to a Mock Electrum server. The first 2 addresses generated have funds.

```bash
../target/release/cli --help            
```

```text
Command Line Interface for a minimalist decentralized crypto-currency wallet

USAGE:
    cli [FLAGS] [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
    -v               Sets the level of verbosity

SUBCOMMANDS:
    create-wallet    Create a new wallet
    help             Prints this message or the help of the given subcommand(s)
    wallet           Operation on wallet
```

## Wallet creation (required)
```bash
../target/release/cli create-wallet
```


## Wallet operations
```bash
../target/release/cli wallet --help
```

```text
Operation on wallet

USAGE:
    cli wallet [FLAGS] [SUBCOMMAND]

FLAGS:
    -a               Generate a new address
    -u               List unspent transactions (tx hash)
    -b               Total balance
    -V, --version    Prints version information
    -h, --help       Prints help information

SUBCOMMANDS:
    help    Prints this message or the help of the given subcommand(s)
    send    Send a transaction
```
### Get a derived/new address (HD)
```bash
../target/release/cli wallet -a
```

* Output:
```text
Network: [regtest]

Address: [bcrt1qq0znj64a5zukv7yew52zjzmdndch3r0vxu8668]
```

### Get total balance
```bash
../target/release/cli wallet -b
```

* Output:
```text
Network: [regtest]

Address:					Confirmed:	Unconfirmed:
bcrt1qsuqsurhgfduhqw6ejquw54482sqpkfc22gytyh	100000		0

State Chain ID:					Confirmed:	Unconfirmed:
1b4cc310-458d-40e8-8a1b-b91c2cc67397		100		0
```

### Get list unspent
```bash
../target/release/cli wallet -u
```

* Output:
```text
Network: [regtest]

Unspent tx hashes:
e0a97cb38e7e73617ef75a57eaf2841eb06833407c0eae08029bd04ea7e6115a
40bf39ffdf4322e4d30ed783feec5bd9eb2804b81f23ebd5e24ea2aa2365a326
]
```

### Deposit to State entity
```bash
../target/release/cli wallet deposit -a [SATOSHI_AMOUNT]
```

* Example:
```bash
../target/release/cli wallet deposit -a 100
```

* Output:
```text
Network: [regtest]

Deposited 100 satoshi's.
Shared Key ID: 9f197560-cc8a-4abd-8377-247e6208544e
State Chain ID: c7c57bc7-db45-474f-86f6-109205eb6b99
```

* Explorer:
https://www.blocktrail.com/tBTC/tx/44545bf81fc8aebcde855c2e33a5f83a17a93f76164330e1ee9e366e8e039444
