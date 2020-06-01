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
    help             Prints this message or the help of the given subcommand(s)
    create-wallet    Create a new wallet
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
    -a               Generate a new BTC address
    -b               Total balance
    -u               List unspent transactions (tx hash)
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

### Withdraw from State entity
```bash
../target/release/cli wallet withdraw -k [SHARED_KEY_ID]
```

* Example:
```bash
../target/release/cli wallet withdraw -k b7b56103-0d25-48c4-8ca7-66c235e30124
```

* Output:
```text
Network: [regtest],
Withdrawn 9000 satoshi's.
From State Chain ID: a3f8f121-7ae0-4be0-9793-101476fd141e

Withdraw Transaction hex: 02000000000101f712bceee061d....
```

### Generate State entity Address
```bash
../target/release/cli wallet se-addr -t [FUNDING_TXID]
```

* Example:
```bash
../target/release/cli wallet se-addr -t e0a97cb38e7e73617ef75a57eaf2841eb06833407c0eae08029bd04ea7e6115a
```

* Output:
```text
Network: [regtest],

New State Entity address:
"{\"backup_tx_addr\":\"bcrt1qjh4cs26aur7uct8fjavmrzqgxxdkpgjusanarx\",\"proof_key\":\"02851ad2219901fc72ea97b4d21e803c625a339f07da8c7069ea33ddd0125da84f\"}"
```

### Transfer State Chain (Sender)
```bash
../target/release/cli wallet transfer-sender -a [FUNDING_TXID]
```

* Example:
```bash
../target/release/cli wallet transfer-sender -a "{\"backup_tx_addr\":\"bcrt1qjh4cs26aur7uct8fjavmrzqgxxdkpgjusanarx\",\"proof_key\":\"02851ad2219901fc72ea97b4d21e803c625a339f07da8c7069ea33ddd0125da84f\"}" -k 665d2d2c-6c3b-4384-a410-15e8a48b7dc5
```

* Output:
```text
Transfer initiated for Shared Key ID: 665d2d2c-6c3b-4384-a410-15e8a48b7dc5.

Transfer message: "{\"shared_key_id\":\"665d2d2c-6c3b-4384-a410-15e8a48b7dc5\",\"t1\":\"221d6675ddcff3b623027d9a70771629a3e10fda1bed594fa022e61a35d1edb4\",\"state_chain_sig\":{\"purpose\":\"TRANSFER\",\"data\":\"02851ad2219901fc72ea97b4d21e803c625a339f07da8c7069ea33ddd0125da84f\",\"sig\":\"3045022100c0823ccc9d8954ac5e6947a523bef1c110bc01a1a0f725ed7ddc94bfcf7c27ac02206ff8121c57a6646f3fe5e9f2eb737c2907f63666cee0d5986ad044d010bcd699\"},\"state_chain_id\":\"03dadad7-91b9-45b5-9f17-5cd945565121\",\"backup_tx_psm\":{\"BackUpTx\":{\"protocol\":\"Deposit\",\"spending_addr\":\"bcrt1qyxaad6plw90z94njaclvfat38qzfc6e3acut7j\",\"input\":\"de812f33c8fa5cc2455f8cafcbbf62b7d32114cad57418886d5421c75f01d350:0\",\"address\":\"bcrt1qx9cs0t7u7gr4w0fh8rrsfm4l367hjuurdpw2pg\",\"amount\":10000,\"proof_key\":\"039afb8b85ba5c1b6664df7e68d4d79ea194e7022c76f0f9f3dadc3f94d8c79211\"}},\"rec_addr\":{\"backup_tx_addr\":\"bcrt1qjh4cs26aur7uct8fjavmrzqgxxdkpgjusanarx\",\"proof_key\":\"02851ad2219901fc72ea97b4d21e803c625a339f07da8c7069ea33ddd0125da84f\"}}"
```

### Transfer State Chain (Receiver)
```bash
../target/release/cli wallet transfer-receiver -m [TRANSFER_MESAGE]
```

* Example:
```bash
../target/release/cli wallet transfer-receiver -m "{\"shared_key_id\":\"665d2d2c-6c3b-4384-a410-15e8a48b7dc5\",\"t1\":\"221d6675ddcff3b623027d9a70771629a3e10fda1bed594fa022e61a35d1edb4\",\"state_chain_sig\":{\"purpose\":\"TRANSFER\",\"data\":\"02851ad2219901fc72ea97b4d21e803c625a339f07da8c7069ea33ddd0125da84f\",\"sig\":\"3045022100c0823ccc9d8954ac5e6947a523bef1c110bc01a1a0f725ed7ddc94bfcf7c27ac02206ff8121c57a6646f3fe5e9f2eb737c2907f63666cee0d5986ad044d010bcd699\"},\"state_chain_id\":\"03dadad7-91b9-45b5-9f17-5cd945565121\",\"backup_tx_psm\":{\"BackUpTx\":{\"protocol\":\"Deposit\",\"spending_addr\":\"bcrt1qyxaad6plw90z94njaclvfat38qzfc6e3acut7j\",\"input\":\"de812f33c8fa5cc2455f8cafcbbf62b7d32114cad57418886d5421c75f01d350:0\",\"address\":\"bcrt1qx9cs0t7u7gr4w0fh8rrsfm4l367hjuurdpw2pg\",\"amount\":10000,\"proof_key\":\"039afb8b85ba5c1b6664df7e68d4d79ea194e7022c76f0f9f3dadc3f94d8c79211\"}},\"rec_addr\":{\"backup_tx_addr\":\"bcrt1qjh4cs26aur7uct8fjavmrzqgxxdkpgjusanarx\",\"proof_key\":\"02851ad2219901fc72ea97b4d21e803c625a339f07da8c7069ea33ddd0125da84f\"}}"
```

* Output:
```text
Network: [regtest],

Transfer complete for Shared Key ID: 5e288b67-9867-46e0-bbe4-49b9a4cf06a2.
```
