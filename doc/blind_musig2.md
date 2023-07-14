# Blinded two-party Musig2

Proposal for a an implimentation of the Musig2 Schnorr multisig protocol where there are 2 parties but where one of the co-signing parties does not learn of 1) The full shared public key or 2) The final signature generated. 

In the folllowing descrption, private keys (field elements) are denoted using lower case letters, and elliptic curve points as uppercase letters. `G` is the generator point and point multiplication denoted as `X = xG` and point addition as `A = G + G`. 

`H()` is a hash function. 

## Schnorr signature

In the standard Schnorr signature protocol, the signer generated a private key (field element) `x` and corresponding public key `X = xG`. 

To sign a message `m`, the signer generates an ephemeral key/nonce (field element) `r` and corresponding public point `R = rG`. 

Signer calculates `e = H(X||R||m)` and `s = e.x + r`. The signature is the pair `(R,s)`. 

## 2-Party Musig2

The 2-party Musig2 protocol works as follows:

Party 1 generates private key `x1` and public key `X1 = x1G`. Party 2 generates private key `x2` and public key `X2 = x2G`. The set of pubkeys is `L = {X1,X2}`. The key aggregation coefficient is `KeyAggCoef(L,X) = H(L,X)`. The shared (aggreagte) public key `X = a1X1 + a2X2` where `a1 = KeyAggCoef(L,X1)` and `a2 = KeyAggCoef(L,X2)`. 

To sign a message `m`, party 1 generates nonce `r1` and `R1 = r1G`. Party 2 generates nonce `r2` and `R2 = r2G`. These are aggreagted into `R = R1 + R2`. 

Party 1 then computes `c = H(X||R||m)` and `s1 = c.a1.x1 + r1`. 
Party 2 then computes `c = H(X||R||m)` and `s2 = c.a2.x2 + r2`. 

The final signature is then `(R,s1+s2)`. 

## Blinded 2-Party Musig2

To prevent party 1 from learning of either the full public key or final signature is trivial in this case, if party 1 doesn not need to independently compute and verify `c = H(X||R||m)` (as they are blinded from the message in any case). 

1) Key aggregation is performed only by party 2. Party 1 just sends `X1` to party 2. 
2) Nonce aggregation is performed only by party 2. Party 1 just sends `R1` to party 2. 
3) Party 2 computes `c = H(X||R||m)` and sends it to party 1 in order to compute `s1 = c.a1.x1 + r1`. 

Party 1 never learns the final value of `(R,s1+s2)` or `m`. 

## Key update

In order to update the server (party 1) keyshare when a statecoin is transferred between users, the key aggregation coefficient must be set to 1 for each key. The purpose of this coefficient in the Musig2 protocol is to prevent 'rouge key attacks' where one party can choose a public key derived from both their own secret key and the inverse of the other party's public key giving them the ability to unilaterally produce a valid signature over the aggregate key. However this can be prevented (as specified in the musig2 paper) by the party producing a proof of knowledge of the private key corresponding to their supplied public key. This can be provided simply in the form of a signature, which is produced in any case by signing the statechain state in the mercury protocol. 

When receiving a statecoin, in order to verify that the coin address (i.e. aggregate public key) is shared correctly between the previous owner and the server, the client must verify the following:

1) Retreive the CURRENT public key (share) from the server for this coin `X1`.
2) Retrieve the public key (share) of the sender `X2`.
3) Verify that `X1 + X2 = P` the address of the statecoin.
4) Verify that the sender has the private key used to generate `X2`: this is done by verifying the statechain signature over the reciver public key `X3` from `X2`. 

This proves that the address `P` was generated (aggregated) with the server and can only be signed with cooperation with the server, i.e. no previous owner can hold the full key. 

In order to update the key shares, the following protocl can be used:

1. Server (party 1) generates a random blinding nonce `b` and sends to client (party 2).
2. Client performs `transfer_sender` and adds their private key the nonce: `t1 = b + x2`
3. Client sends `t1` to the reciever as part of `transfer_msg_3` (encrypted with the receiver public key `X3 = x3G`).
4. Reciver client decrypts `t1` and then subtracts their private key `x3`: `t2 = b + x2 - x3`.
5. Reciver client sends `t2` to the server as part of `transfer_receiver`.
6. Server the updates the private key share `x1_2 = x1 + t2 - b = x1 + b + x2 - x3 -b = x1 + x2 - x3`

So now, `x1_2 + x3` (the aggregation of the new server key share with the new client key share) is equal to `x1 + x2` (the aggregation of the old server key share with the old client key share). 

7. The server deletes `x1`. 
