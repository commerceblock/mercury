# Mercury layer WASM client specification

The Mercury layer operates as a client/server application. The Mercury client is a rust application (compiled to web-assmeby) that connects to the *mercury server* and Electrum server via http (over the Tor network). 

### WASM framework structure

```
response = JSON response object

response['error'] : json response error field
```

## Wallet functions

#### setEndpoints

Set the mercury server and electrum server endpoints

**request:**
```
{
    merc_server: String, // Tor address of mercury server
    electrum_server: String,    // Tor address of electrum server
    electrum_type: String,   // electrum server type
}
```

*response*
```
Status::Ok
```

#### fromMnemonic

Create a new wallet from 12 word BIP39 seed phrase

**request:** 
```
{
    network: String, // mainnet, testnet or regtest
    mnemonic: String,    // 12 word seed phrase
    password: String, // encryption password
    wallet_name: String,   // wallet name
}
```

*response*
```
Status::Ok
```

#### recoverWallet

Recover wallet from 12 word BIP39 seed phrase

**request:** 
```
{
    network: String, // mainnet, testnet or regtest
    mnemonic: String,    // 12 word seed phrase
    password: String, // encryption password
    wallet_name: String,   // wallet name
}
```

*response*
```
Status::Ok
```

#### fromJSON

Create a new wallet from JSON

**request:** 
```
{
    wallet_name: {}
}
```

*response*
```
Status::Ok
```

#### listWallets

List all created wallets

**request:**

*response*
```
{
    wallets: [{wallet_name}] 
}
```

#### getWallet

Get JSON wallets

**request:**
```
{
    password: String, // encryption password
    wallet_name: String,   // wallet name
}
```

*response*
```
{
    wallet_name: {}
}
```

#### getFeeInfo

Get server fee info

**request:** 

*response*
```
{
    address: String, // Receive address for fee payments
    deposit: u64,    // basis points
    withdraw: u64,   // basis points
    interval: u32,   // locktime decrement interval in blocks
    initlock: u32,   // inital backup locktime
}
```

#### getSCAddress

Get SC address

**request:** 
```
{
    index: u64 // address index, 0 is new address
}
```

*response*
```
{
    address: String, // Receive address for fee payments
    index: u64 // address index
}
```

#### getNumAddress

Get number of SC address

**request:** 

*response*
```
{
    number: u64 // number of SC addresses
}
```

#### getInvoice

Get LN invoice for token

**request:** 
```
{
    amount: u64 // invoice amount
}
```

*response*
```
{
    bolt11: String, // Bolt11 invoice
    token_id: String // token ID
}
```

#### queryToken

Check token balance and status

**request:** 
```
{
    token_id: String // Token ID
}
```

*response*
```
{
    amount: u64 // remaining token_id balance
}
```

#### getActivityLog

Get activity log

**request:** 

*response*
```
{
    activity_log: {}
}
```

#### getStatecoinList

Get list of statecoins

**request:** 
```
{
    available: bool // all statecoins objects or only available coins
}
```

*response*
```
{
    statcoins: [statechain_id:user_id, status, value, txid:vout, locktime]
}
```

#### getStateCoin

Get statecoin object

**request:** 
```
{
    statechain_id: String // statecoin ID
}
```

*response*
```
{
    statcoin: {}
}
```

#### getExpiredCoins

Get statecoin object

**request:** 
```
{
    locktime: u64 // current blockheight
}
```

*response*
```
{
    statcoins: [{}]
}
```


#### depositInit

Deposit a statecoin

This generates a shared key taproot address

**request:** 
```
{
    amount: u64 // coin value
    token_id: String // token ID
}
```

*response*
```
{
    address: String // TR deposit address
    statechain_id: String
    user_id: String
}
```

#### depositCheck

Check if a coin has been deposited

**request:** 
```
{
    address: String // deposit address
}
```

*response*
```
{
    confirmations: u32 // number of confirmations (0 in mempool, -1 not seen)
}
```

#### depositConfirm

Finalize deposit

**request:** 
```
{
    statechain_id: String
    user_id: String
}
```

*response*
```
{
    backup_tx
}
```
