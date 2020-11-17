# DLC novation

The ownership of a position in a discreet log contract (DLC) can be transferred using this same basic mechanism, but with the key rotation and backup transactions applied to every output of the multiple Contract Execution Transactions (CETs) of the DLC. The essential protocol is summarised as follows:

Either, or both, of the counterparties in a specific DLC can utilise the SE for novation, and this requires no changes to the DLC protocol. In fact, if one counterparty is using an SE service for novation, the other counterparty does not even need to be aware of this or of any of the changes of ownership. In the following, we decribe the set-up for one counterparty using the service. 

## Initialisation

A user wants to initiate a DLC using the SE service for novation. The following steps are followed as part of the DLC creation process:

1. The first position owner (Owner 1) generates two private keys: `o1` (the UTXO private key share) and `b1` (the backup private key).
2. Owner 1 then calculates the corresponding public key of the share `O1` and sends it to the SE: `O1 = o1.G`
3. The SE then generates a private key: `s1` (the SE private key share), calculates the corresponding public key and sends it to Owner 1: `S1 = s1.G`
4. Both SE and Owner 1 then multiply the public keys they receive by their own private key shares to obtain the same shared public key `P` (which corresponds to a shared private key of `p = o1*s1`): `P = o1.(s1.G) = s1.(o1.G)`
5. Owner 1 and the DLC counterparty create the DLC funding transaction `Tx0` (with supplied inputs) to pay an amount `A` to a 2-of-2 multisig (one public key `P` and the other public key belonging to the counterpary's - `C`. This defines the opening UTXO (the outpoint). 
6. The Owner 1 and the counterparty cooperate to generate the full set of unsigned CETs following the DLC protocol [6]: `TxDLC[i]` where `i = 1,...,n`, after agreeing on an oracle public key `O`. The counterparty partially signs all of them (1-of-2) and sends them to Owner 1. 
7. Owner 1 and the SE then coorperate to partially sign (1-of-2) the full set of CETs with the shared key `P` with 2P ECDSA and sends them to the counterparty. 
8. The SE creates a series of *kick-off transactions* that spend from the outputs that pay to `P` from the full set of CETs (two for each CET):  `TxK[i,1]` and `TxK[i,2]` where `i = 1,...,n`. 
9. Owner 1 and the SE cooperatively sign each `TxK` via 2P ECDSA. Both parties save these transactions. 
10. Owner 1 genertes `b1` (the backup private key) and computes `B1 = b1.G`.
11. Owner 1 creates a series of *backup transactions* for each kick-off transaction that pays the `P` output of each `TxK` to `B1`, and sets the `nSequence` to the maximum relative locktime `t0` (according to BIP68): `Tx1[i,1]` and `Tx1[i,2]` where `i = 1,...,n`. These are sent to the SE. 
10. The SE recieves all `Tx1[i,1]` and `Tx1[i,2]` where `i = 1,...,n` and verifies the `nSequence` field of each one. Owner 1 and the SE then sign each `Tx1` with shared key (`P`) via 2P ECDSA, which Owner 1 then saves. 
10. Owner 1 then co-signs (with the couterparty) and broadcasts the deposit/opening transaction `Tx0`. Once the transaction is confirmed, the deposit is completed. 
11. The SE then adds the UTXO outpoint with `O1` to the *statechain* which is then attested to Bitcoin via the Mainstay protocol. 

## Transfer

Owner 1 wishes to transfer their position in the DLT to a new owner (Owner 2) (as a payment or as part of a complex trade). For this to proceed, the new owner must be aware of the public key that is used to authenticate the SE (`SE`). The new owner may require the current owner prove their unique ownership by signing a message with their key share (`O1`) as published on the statechain. The protocol then proceeds as follows:

Steps 1-14 in the transfer section above are followed to transfer the shared key. Then the following steps are followed:
1. The SE sends Owner 2 the full set of signed kick-off transactions `TxK[i,1]` and `TxK[i,2]` where `i = 1,...,n`. 
2. Owner 2 creates a series of *backup transactions* for each kick-off transaction that pays the `P` output of each `TxK` to `B2`, and sets the `nSequence` to the maximum relative locktime `t0 - c` (according to BIP68): `Tx2[i,1]` and `Tx2[i,2]` where `i = 1,...,n`. These are sent to the SE. 
10. The SE recieves all `Tx2[i,1]` and `Tx2[i,2]` where `i = 1,...,n` and verifies the `nSequence` field of each one. Owner 2 and the SE then sign each `Tx2` with shared key (`P`) via 2P ECDSA, which Owner 2 then saves. 
18. The SE then adds the UTXO outpoint with public key `O2` to the statechain which is then attested to Bitcoin via the Mainstay protocol. 

This can then be repeated to transfer the DLC position to each new owner. 

## DLC closure

Once the oracle publishes the signature at the expiration of the DLC, making one of the CETs valid (`TxCET[j]`) - one of the counterparties submit their valid transaction (OR they can cooperate the sign a separate transaction that pays directly to each party's wallet address - this would also require the cooperation of the SE for the current Owner to sign their part of the opening/deposit transaction). If a CET is broadcast (and confirmed), the SE and the current owner can then cooperate to 'withdraw' the output from the CET (or if the SE is not-responsive, then the current owner can submit the corresponding kick-off backup transaction `TxK[j,1]` and after the timelock `Tx2[j,1]` to claim the CET output). If the SE is unresponsive AND the counterparty broadcasts an invalid state, the kick-off backup transaction `TxK[j,2]` can be broadcast followed by the backup transaction `Tx2[j,2]` after the timelock. 