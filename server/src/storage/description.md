
## Schema: statechainentity
Accessible by Mercury Server. These tables store all data for 2P-ECDSA and State Chain functionality.

### User
User represents a user in a particular state chain session. The same client co-owning 2 distinct UTXOs with the state entity would have 2 unrelated User table entris.

| Name            | Type          | Required | Description                             |
|-----------------|---------------|----------|-----------------------------------------|
| id              | String (UUID) | true     | Primary Key                             |
| state_chain_id  | String (UUID) | false    | Foreign Key for StateChain table        |
| authentication  | undetermined  | true     | Can be string token for now             |
| proofkey        | String        | false    |                                         |
| s2              | EC Scalar     | false    | Required at transfer to create new User |
| sig_hash        | String (Hash) | false    | Required for any tx signing             |
| withdraw_sc_sig | StateChainSig | false    | Required for withdraw                   |
| tx_withdraw     | Transaction   | false    | Withdraw tx data                        |



### StateChain
A list of States in which each State signs for the next State.

| Name           | Type          | Required | Description |
|----------------|---------------|----------|-------------|
| state_chain_id | String (UUID) | true     | Primary Key |
| chain          | Vec(State)    | true     |             |
| amount         | u64           | true     |             |
| locked_until   | SystemTime    | true     | Time in the future before which this state chain cannot be acted upon |
| owner_id       | String (UUID) | true     | user_id of current owner  |



### TransferData
TransferData stores transfer data between transfer_sender and transfer_receiver.

| Name            | Type          | Required | Description |
|-----------------|---------------|----------|-------------|
| state_chain_id  | String (UUID) | true     | Primary Key |
| state_chain_sig | StateChainSig | true     |             |
| x1              | EC Scalar     | true     |             |



### TransferBatchData
TransferBatch stores list of StateChains involved in a batch transfer and their status in the potocol.
When all transfers in the batch are complete these transfers are finalized atomically.

| Name                  | Type                      | Required | Description                                                 |
|-----------------------|---------------------------|----------|-------------------------------------------------------------|
| id                    | String (UUID)             | true     | Primary Key                                                 |
| start_time            | SystemTime                | true     | Time batch transfer began                                   |
| state_chains          | HashMap(String, bool)     | true     | Mapping of state_chain_ids to completion status             |
| finalized_data        | Vec(TransferFinalizeData) | true     | Data for finalizing transfers                               |
| punished_state_chains | Vec(String)               | true     | If transfer batch fails these state_chain_ids were punished |
| finalized             | bool                      | true     |                                                             |


### Ecdsa
2P-ECDSA library data.

| Name              | Type   | Required | Description                  |
|-------------------|--------|----------|------------------------------|
| id                | UUID   | true     | Primary Key                  |
| keygenfirstmsg    | String | false    | Seriaized MPC library struct |
| commwitness       | String | false    | Seriaized MPC library struct |
| eckeypair         | String | false    | Seriaized MPC library struct |
| party2public      | String | false    | Seriaized MPC library struct |
| paillierkeypair   | String | false    | Seriaized MPC library struct |
| party1private     | String | false    | Seriaized MPC library struct |
| pdldecommit       | String | false    | Seriaized MPC library struct |
| alpha             | String | false    | Seriaized MPC library struct |
| party2pdlfirstmsg | String | false    | Seriaized MPC library struct |
| party1masterkey   | String | false    | Seriaized MPC library struct |
| epheckeypair      | String | false    | Seriaized MPC library struct |
| ephkeygenfirstmsg | String | false    | Seriaized MPC library struct |
| epheckeypair      | String | false    | Seriaized MPC library struct |
| epheckeypair      | String | false    | Seriaized MPC library struct |




## Schema: watcher
Accessible by Mercury Server and Watchers. Tables are replicated for redundency since they store the most recent back-up tx for each currently active state chain.

### BackUpTxs <a name="BackUpTxs"></a>
Storage of active Backup Txs.

| Name            | Type          | Required | Description     |
|-----------------|---------------|----------|-----------------|
| state_chain_id  | String (UUID) | true     | Composite Key   |
| tx_backup       | Transaction   | true     | Back up tx data |



# SQL

CREATE TABLE "statechainentity"."usersession" (
    "id" uuid NOT NULL,
    "statechainid" uuid,
    "authentication" varchar,
    "s2" varchar,
    "sighash" varchar,
    "withdrawscsig" varchar,
    "txwithdraw" varchar,
    "proofkey" varchar,
    "txbackup" varchar,
    PRIMARY KEY ("id")
);

CREATE TABLE "statechainentity"."ecdsa" (
    "id" uuid NOT NULL,
    "keygenfirstmsg" varchar,
    "commwitness" varchar,
    "eckeypair" varchar,
    "party2public" varchar,
    "paillierkeypair" varchar,
    "party1private" varchar,
    "pdldecommit" varchar,
    "alpha" varchar,
    "party2pdlfirstmsg" varchar,
    "party1masterkey" varchar,
    "pos" varchar,
    "epheckeypair" varchar,
    "ephkeygenfirstmsg" varchar,
    "complete" bool NOT NULL DEFAULT false,
    PRIMARY KEY ("id")
);

CREATE TABLE "statechainentity"."statechain" (
    "id" uuid NOT NULL,
    "chain" varchar,
    "amount" int8,
    "ownerid" uuid,
    "lockeduntil" timestamp,
    PRIMARY KEY ("id")
);

CREATE TABLE "statechainentity"."transfer" (
    "id" uuid NOT NULL,
    "statechainsig" varchar,
    "x1" varchar,
    PRIMARY KEY ("id")
);


CREATE TABLE "statechainentity"."transferbatch" (
    "id" uuid NOT NULL,
    "starttime" timestamp,
    "statechains" varchar,
    "finalizeddata" varchar,
    "punishedstatechains" varchar,
    "finalized" bool,
    PRIMARY KEY ("id")
);

CREATE TABLE "statechainentity"."root" (
    "id" BIGSERIAL,
    "value" varchar,
    "commitmentinfo" varchar,
    PRIMARY KEY ("id")
);

CREATE TABLE "watcher"."backuptxs" (
    "id" uuid NOT NULL,
    "txbackup" varchar,
    PRIMARY KEY ("id")
);
