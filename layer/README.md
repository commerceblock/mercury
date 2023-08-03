# Introduction

Mercury Layer is an implementation of a layer-2 statechain protocol that enables off-chain transfer and settlement of Bitcoin outputs that remain under the full custody of the owner at all times, while benefiting from instant and zero cost transactions. The ability to perform this transfer without requiring the confirmation (mining) of on-chain transactions has advantages in a variety of different applications. 

This documentation covers the description of the Mercury Layer architecture and protocol, the specification Mercury API and instructions for the deployment and operation of the separate components of the system. 

## Overview

An *unspent transaction outputs* (UTXO) is the fundamental object that defines value and ownership in a cryptocurrency such as Bitcoin. A UTXO is identified by a transaction ID (`TxID`) and output index number (`n`) and has two properties: 1. A value (in BTC) and 2. Spending conditions (defined in Script). The spending conditions can be arbitrarily complex (within the limits of the consensus rules), but is most commonly defined by a single public key and can only be spent by transaction signed with the corresponding public key. 

The simplest function of the Mercury layer system is to enable the transfer the ownership of individual UTXOs controlled by a single public key `P` from one party to another without an on-chain (Bitcoin) transaction (or change in the spending condition). The SE facilitates this change of ownership, but has no way to seize, confiscate or freeze the output. To enable this, the private key (`s`) for `P` (where `P = s.G`) is shared between the SE and the owner, such that neither party ever has knowledge of the full private key (which is `s = s1 + o1` where `s1` is the SE private key share, and `o1` is the owner key share) and so cooperation of the owner and SE is required to spend the UTXO. However, by sharing the secret key in this way, the SE can change its key share (`s1 -> s2`) so that it combines with a new owner key share (`o2`) with the cooperation of the original owner, but without changing the full key (i.e. `s1 + o1 = s2 + o2`) all without any party revealing their key shares or learning the full key. The exclusive control of the UTXO then passes to the new owner without an on-chain transaction, and the SE only needs to be trusted to follow the protocol and delete/overwrite the key share corresponding to the previous owner. 

This key update/transfer mechanism is additionally combined with a system of *backup* transactions which can be used to claim the value of the UTXO by the current owner in the case the SE does not cooperate or has disappeared. The backup transaction is cooperatively signed by the current owner and the SE at the point of transfer, paying to an address controlled by the new owner. To prevent a previous owner (i.e. not the current owner) from broadcasting their backup transaction and stealing the deposit, the `nLocktime` value of the transaction is set to a future specified block height. Each time the ownership of the UTXO is transferred, the `nLocktime` is decremented by a specified value, therefore enabling the current owner to claim the deposit before any of the previous owners.

The decrementing timelock backup mechanism limits the number of transfers that can be made within the lock-out time. The user is responsible for submitting backup transactions to the Bitcoin network at the correct time, and applications will do this automatically.

The life-cycle of a deposit into the statechain, transfer and withdrawal is summarised as follows:

1. The depositor (Owner 1) initiates a UTXO statechain with the SE by paying BTC to an address where Owner 1 and the SE each have private key shares, both of which are required to spend the UTXO. Additionally, the SE and the depositor can cooperate to sign a backup transaction spending the UTXO to a timelocked transaction spending to an address fully controlled by Owner 1 which can be confirmed after the `nLocktime` block height in case the SE stops cooperating.
3. Owner 1 can verifiably transfer ownership of the UTXO to a new party (Owner 2) via a key update procedure that overwrites the private key share of SE that invalidates the Owner 1 private key and *activates* the Owner 2 private key share. Additionally, the transfer incorporates the cooperative signing of a new backup transaction paying to an address controlled by Owner 2 which can be confirmed after a new `nLocktime` block height, which is shortened (by an accepted confirmation interval) from the previous owners backup transaction `nLocktime`.
5. This transfer can be repeated multiple times to new owners as required (up until the most recent recovery `nLocktime` reaches a lower limit determined by the current Bitcoin block height).
6. At any time the most recent owner and SE can cooperate to sign a transaction spending the UTXO to an address of the most recent owner's choice (i.e. withdrawal). 

##  Statechains

The essential function of the Mercury layer system is that it enables 'ownership' (and control) of a UTXO to be transferred between two parties (who don't need to trust each other) via the SE without an on-chain transaction. The SE only needs to be trusted to operate the protocol (and crucially not store any information about previous key shares) and then the transfer of ownership is completely secure, even if the SE was to later get compromised or hacked. At any time the SE can prove that they have the key share for the current owner (and only to the current owner). The current owner is required to sign a *statechain transaction* (`SCTx`) with an owner key to transfer ownership to a new owner (i.e. a new owner key). This means that any theft of the UTXO by the collusion of a corrupt SE and old owner can be independently and conclusively proven.

## Blinding

The Mercury layer server is *blind* - that is the server *does not* and *cannot* know anything that would enable it to identify the coin (UTXO) that it is co-signing for. This prevents any censorship and storage of any identifying data in the server - the server itself is not aware of bitcoin, and does not perform any verifcation of transactions. 

To achieve this the server cannot know or be able to derive in any way the following values:

- The TxID:vout of the statecoin UTXO
- The address (i.e. public key) of the UTXO
- Any signatures added to the bitcoin blockchain for the coin public key.

This means that the server cannot:

- Learn of the shared public key it is co-signing for.
- Learn of the final (unblinded) form of any signatures it co-generates.
- Verify ANY details of backup or withdrawal transactions (as this would reveal the statecoin TxID).

All verification of backup transaction locktime decrementing sequence must be performed client side (i.e. by the receiving wallet). This requires that the full statechain and sequence of backup transactions is sent from sender to receiver and verified for each transfer (this can be done via the server with the data encrypted with the receiver public key). 

The server is no longer able to perform an explicit proof-of-publication of the globally unique coin ownership (via the SMT of coin TxIDs), as it cannot know these. It can however perform a proof-of-publication of its public key shares for each coin it is co-signing (i.e. SX, where X = 1,2,3 ...). These key shares can be used by the current owner to calulate the full shared public key and verify that their ownership is unique.
The design changes required are then as follows:

### Blind two-party Schnorr signatures

Mercury layer will by default employ Schnorr signatures via Taproot addresses for statecoins. To enable a signature to be generated over a shared public key (by the two private key shares of the server and owner) a blinded variant of the Musig2 protocol is employed. In this variant, one of the co-signing parties (the server) does not learn of 1) The full shared public key or 2) The final signature generated. An ephemeral key commitment scheme is employed to ensure Wagner based attacks are not possible. 

### Client transaction verification

In the blinded mercury layer protocol, the server cannot verify what it signs, but can only state HOW MANY unique signatures it has generated for a specific shared key, and it will return this number when queried by a wallet. The wallet will then have to check that every single previous backup transaction signed has been correctly decremented, AND that the total number of value backup transactions it has verified matches the number of signatures the server has co-generated. This will then enable a receiving wallet to verify that no other valid transactions spending the statecoin output exist (given it trusts the server to return the correct number of signatures). 

When it comes to withdrawal, the server can no longer verify that any fee has been added to the withdrawal transaction, and the wallet can just create any transaction it wants to end the chain. In this case, any fee collected by the SE must be done separately to the statecoin deposit and withdrawal transactions (and be required on deposit, before the deposit address is generated).

### Keyshare publication

The server does not have access to the TxIDs of individual coins along with the user proof keys that it can publish. Instead, it takes each of the current public key shares for each coin in the system and publishes this list. This is then updated with each new coin or coin ownership change. This public key list is then commited to bitcoin via Mainstay for a proof-of-uniqueness. 

To verify the uniqueness of the ownership of the shared public key, the current owner then derives the full shared public key from this commitment and their or key share (P = o1.(s1.G)) and verifies it against the coin. 
