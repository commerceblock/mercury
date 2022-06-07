# Blinded Mercury

## Current protocol

The following describes the process for deposit, transfer and withdrawal in the current mercury implementation. 

Mercury employs the 2-of-2 MPC ECDSA protocol of Lindell has two parties (with private keys `a` and `b`) where the shared public key is `P = ab.G` and both parties cooperate to create a signature for `P` without revealing either `a` or `b`.

In addition, a public key encryption scheme is required for blinded private key information sent between parties. This is compatible with the EC keys used for signatures, and ECIES is used. The notation for the use of ECIES operations is as follows: `Enc(m,K)` denotes the encryption of message `m` with public key `K = k.G` and `Dec(m,k)` denotes the decryption of message `m` using private key `k`.

### Deposit

An owner wants to deposit an amount of BTC into the platform. The following steps are then completed:

1. The depositor (Owner 1) generates a private key: `o1` (the UTXO private key share).
2. Owner 1 then calculates the corresponding public key of the share `O1` and sends it to the SE: `O1 = o1.G`
3. The SE then generates a private key: `s1` (the SE private key share), calculates the corresponding public key and sends it to Owner 1: `S1 = s1.G`
4. Both SE and Owner 1 then multiply the public keys they receive by their own private key shares to obtain the same shared public key `P` (which corresponds to a shared private key of `p = o1*s1`): `P = o1.(s1.G) = s1.(o1.G)`

> The above key sharing scheme is the same as that used in the 2P ECDSA protocols. The key generation routines of these existing 2P ECDSA implementations can be used in place of the above steps (which include additional verification and proof steps).

7. Owner 1 then pays a specified value of bitcoin to an address derived from the shared public key (`P`) generating the statecoin UTXO (`Tx0`). 
8. Owner 1 then creates a *backup transaction* (`Tx1`) that pays the `P` output of `Tx0` to an address derived from `O1`, and sets the `nLocktime` to the initial future block height `h0` (where `h0 = cheight + hinit`, `cheight` is the current Bitcoin block height and `hinit` is the specified initial locktime).
9. SE receives `Tx1` and `C1` from Owner 1 and verifies the `nLocktime` field. Owner 1 and the SE then sign `Tx1` with shared key (`P`) via 2P ECDSA (see below), which Owner 1 then saves.
11. The SE then adds the public key `C1` to the leaf of the sparse merkle tree (SMT) at position TxID of `Tx0`. The root of the SMT is then attested to Bitcoin via the Mainstay protocol in slot `slot_id`. 

### Transfer

Owner 1 wishes to transfer the value of the deposit `A` to a new owner (Owner 2) (e.g. as part of a swap). The protocol then proceeds as follows:

1. The receiver (Owner 2) generates a private key `o2`. They then compute the corresponding public key `O2 = c2.G`.
2. `O2` then represents the Owner 2 encoded 'address' and is communicated to Owner 1 (directly or via a swap conductor) in order for them to 'send' the ownership.
3. Owner 1 then requests that the SE facilitate a transfer to Owner 2 (and that the new owner can be authenticated with `O2`).
4. SE generates a random key `x1` and encrypts it with the Owner 1 statechain public key: `Enc(x1,O1)`
5. `Enc(x1,C1)` is sent to Owner 1 who decrypts it with `o1` to learn `x1`: `Dec(x1,c1)`
6. Owner 1 then computes `o1*x1` and encrypts it with the Owner 2 statechain public key (from the address): `Enc(o1*x1,O2)`
7. Owner 1 creates a new *backup transaction* (`Tx2`) that pays the `P` output of `Tx0` to `O2`, and sets the `nLocktime` to the relative locktime `h0 - (n-1)*c` where `c` is the confirmation interval and `n` is the owner number (i.e. 2).
8. The SE receives `Tx2` and verifies the `nLocktime` field corresponds to `h0 - (n-1)*c`. Owner 1 and the SE then sign `Tx2` with shared key (`P`) via 2P ECDSA, which Owner 1 then saves. 

> The steps 3-8 only require interaction between the SE and owner 1, and can be performed at any time before the involvement of Owner 2 is required.

9. Owner 1 retrieves the UTXO statechain (ownership sequence) for `Tx0` and signs ownership to `O2` with private key `o1`: this is `SCTx1`
10. Owner 1 then sends Owner 2 a message containing the objects:
	a. `Tx2`
	b. `SCTx1`
	c. `Enc(o1*x1,C2)`

> At this point the Owner 1 has sent all the information required to complete the transfer to Owner 2 and is no longer involved in the protocol. Owner 2 verifies the correctness and validity of the four objects, and the payment is complete. Owner 1 can then complete the key update with the SE.

The SE key share update then proceeds as follows:

12. Owner 2 decrypts object d: `Dec(o1*x1,c2)` and then computes `o1*x1*o2_inv` where `o2_inv` is the modular inverse of the private key `o2`.
13. Owner 2 then encrypts `Enc(o1*x1*o2_inv,SE)`, signs it with `C2` and sends it to the SE along with `SCTx1` and `O2`.
14. The SE authenticates and decrypts this to learn `o1*x1*o2_inv`: `Dec(o1*x1*o2_inv,se)`
15. The SE then multiplies this product by `x1_inv*s1` (where `x1_inv` the modular inverse of `x1`) to compute `s2 = o1*o2_inv*s1`.
16. The SE then verifies that `s2.O2 = P` and deletes the key share `s1`. 

> `s2` and `o2` are now the private key shares of `P = s2*o2.G` which remains unchanged (i.e. `s2*o2 = s1*o1`), without anyone having learnt the full private key. Provided the SE deletes `s1`, then there is no way anyone but the current owner (with `o2`) can spend the output.

17. The SE sends Owner 2 `S2 = s2.G` who verifies that `o2.S2 = P`
18. The SE then adds the public key `O2` to the leaf of the SMT at position TxID of `Tx0`. The root of the SMT is then attested to Bitcoin via the Mainstay protocol in slot `slot_id`.

> The SE keeps a database of backup transactions for the users, and broadcasts them at the appropriate time in case the users are off-line.

### Withdrawal

The current owner of a deposit can at any time withdraw from the platform to either gain complete control of the shared key or broadcast a jointly signed transaction. The current owner can request that the SE cooperates in signing a transaction paying the UTXO to certain addresses specified by the owner. The SE includes a withdrawal fee for providing the service (`F`), which can be included in this transaction.

This would proceed as follows:

1. The current owner (e.g. Owner 2) creates a transaction `TxW` that spends `Tx0` to an address `W`.
2. The owner then requests that the SE cooperate to sign this transaction using the shared public key `P`.
3. The owner signs the current state concatenated with the string `WITHDRAWAL` with their key `O2` and sends it to the SE.
4. SE and the owner sign `TxW`. The SE must confirm that `TxW` pays to `W` (otherwise this will create a fraud proof).
3. The fully signed `TxW` is then broadcast and confirmed.
4. The SE commits the close string to the leaf of the SMT at position TxID of `Tx0`, to verifiably close the UTXO chain of ownership.

## Two-party ECDSA signing

Two mutually distrusting parties can share the key pair `x` and `Q` in a way that no one ever knows the full `x` and both parties need to cooperate in order to generate a valid signature over `Q`. For compatibility with the arithmetic of ECDSA (multiplication by modulo inversions), the optimum way to split the full private key is with multiplicative sharing, i.e. `x = x1x2` where `x1` and `x2` are the party 1 (`P1`) and party 2 (`P2`) shares respectively. In order to enable multiparty computation of the full signature, the Pailier encryption system is used to perform the homomorphic addition of terms to calculate `s`. 

### Distributed key generation

`P1` and `P2` can cooperate to generate a public key `P` corresponding to a shared private key `x` (that never comes into existence explicitly). This is performed as follows:

1. `P1` chooses a random key `s1 <- Zq` and computes `S1 = s1.G` and sends to `P2`
2. `P2` chooses a random key `o1 <- Zq` and computes `O1 = o1.G` and sends to `P1`
3. `P1` computes `P = s1.Q2` and `P2` computes `P = o1.Q1`

To remain secure under a malicious adversary assumption, each party must provide the other with a proof of knowledge of the discrete log of the point generated (using a Schnorr proof). 

In the protocol of Lindell [1], `P1` then generates a Pailier key pair `(pk,sk)` and then computes `ck = Enc_pk(x1)` which is the Pailier encryption of the `P1` private key share. In addition to this, `P1` also sends a zero-knowledge proof to `P2` that a value encrypted in
a given Paillier ciphertext is the discrete log of a given elliptic curve point. 

### Distributed two-party signing

When `P1` and `P2` agree to produce a signature on a known message `m`, the first step is to generate a shared ephemeral key `k` and corresponding point `R` (`k` must be a shared key as knowledge of `k` enables the full private key to be derived from the signature). This key generation is performed in the same way as the key generation above, resulting in `P1` possessing a secret `k1` and `P2` possessing `k2`, where `R = k1.R2 = k2.R1 = k1k2.G` and `r` (the x coordinate of `R`) known and agreed by both parties. 

Then `P2` computes `c1 = Enc_pk(k2^-1.H(m) mod q)` and `v = k2^-1.rx2 mod q` using the Paillier public key `pk` from `P1`. 

`P2` then performs a homomorphic scalar multiplication of `v` by `ck` to obtain `c2 = Enc_pk(k2^-1.rx2x1 mod q)`, and then Pailier homomorphic addition of `c1` and `c2` to obtian `c3 = Enc_pk(k2^-1.H(x) + k2^-1.rx2x1 mod q)`. This so-called 'almost signature' is then sent to `P1`. 

The party `P1` receives `c3` and can decrypt it using their Pailier secret key `sk` to give `t = Dec_sk(c3) = k2^-1.H(x) + k2^-1.rx2x1 mod q`. All that is now required is for `P1` to multiply this value by the inverse of their ephemeral key share `k1^-1` to complete the signature. 

`s = k1^-1.k2^-1.H(x) + k1^-1.k2^-1.rx2x1 mod q = k^-1.H(x) + k^-1.rx mod q`

`P1` then verifies the full signature `(r,s)` against the agreed message `m` and shared public key `Q`, and if verified then releases it to `P2`. 

## Blinding considerations

The aim of 'blinding' the mercury server is to make it so that the server does not and *cannot* know anything that would enable it to identify the coin that it is co-signing for. This prevents any censorship and maintenance of any lists in the server. 

To achieve this the server cannot know or be able to derive in any way the following values: 

1. The TxID:vout of the statecoin UTXO
2. The address (i.e. public key) of the UTXO
3. Any signatures added to the bitcoin blockchain for the coin public key. 

This means that the server cannot:

1. Learn of the shared public key it is co-signing for. 
2. Learn of the final (unblinded) form of any signatures it co-generates. 
3. Verify ANY details of backup or withdrawal transactions (as this would reveal the statecoin TxID). 

These requirements lead to two fundamental changes to the mercury protocol:

1. The 2P-ECDSA keygen and signing must be blinded to the shared pubkey and signatures (for `P1`). 
2. All verification of backup transaction locktime decrementing sequence must be performed client side (i.e. by the receiving wallet). This neccessitates that the full statechain and sequence of backup transactions is sent from sender to receiver and verified for each transfer. (this can be done via the server with the data encrypted with the receiver public key). 
3. The server is no longer able to perform a proof-of-publication of the globally unique coin ownership (via the SMT of coin IDs). 

The design changes required are then as follows:

### Blinded Two-party ECDSA 

The principle of a *fully* blind two-party ECDSA, is that one party (i.e. `P1`) has a share of the full private key, as above, and can cooperate with `P2` to generate a signature for the shared public key `P`, however this is done without `P1` learning any information about the message being signed (`m`) OR any information about the final valid signature `(r,s)` itself (since in Bitcoin, even if `P1` has no information on the message, they can search the public blockchain and find it if they know the final signature). 

Blinding the server from the value of `O1` can be done in the distributed keygen by just not sending it to the server for verification - this is superfluous in the mercury trust setup in any case - the wallet performs all verification. 

Blinding the message `m` from `P1` in the above protocol is trivial: `H(m)` is added to the encrypted signature by `P2`, and `P1` verifies the final signature against `m` after completing it. If `P1` agrees to not know or care about the message `m`, then they simply send the final signature directly to `P2` to verify, without checking it themselves (because they can't as they don't know `m`). 

Blinding the final signature itself from `P1` is somewhat more involved, but is still fairly straightforward. A property of the above protocol to note is that, as with the message `m`, the value `r` is added to the Pailier encrypted expression only by `P2` and so there is no requirement for `P1` to have knowledge of `r`. To prevent `P1` from computing `r`, `P2` can simply not send `P1` the value `R2 = k2.G` after generating `k2` (`P2` still needs to recieve `R1 = k1.G` from `P1` to compute `r`). 

To prevent `P1` from learning the final value of `s`, even after finalising the computation of it, the plaintext Pailier encrypted 'almost signature' (`c3`) can be blinded with a blinding key/nonce via a a homomorphic scalar multiplication from `P2` before it is sent to `P1`. `P1` can then finalise the (blinded) `s` value by multiplying with `k1^-1` before returning it to `P2` who can then unblind it to get the final signature (`P1` having learnt nothing about the final `s` value). 

With these modifications, the signing protocol for a fully blinded `P1` then proceeds as follows:

1. `P1` chooses a random ephemeral key share `k1 <- Zq` and computes `R1 = k1.G` and sends to `P2`
2. `P2` chooses a random ephemeral key share `x2 <- Zq` and computes `R = k2.R1`
3. `P2` then determines `r` (the x component of `R` mod q). 
4. `P2` generate a random blinding key `b <- Zq`
5. `P2` chooses `m` and computes `c1 = Enc_pk(k2^-1.H(m) mod q)` and `v = k2^-1.rx2 mod q` using the Paillier public key `pk` from `P1`. 
6. `P2` then performs a homomorphic scalar multiplication of `v` by `ck` to obtain `c2 = Enc_pk(k2^-1.rx2x1 mod q)`, and then Pailier homomorphic addition of `c1` and `c2` to obtaidistrubuten `c3 = Enc_pk(k2^-1.H(x) + k2^-1.rx2x1 mod q)`.  
7. `P2` then performs a homomorphic scalar multiplication of `c3` by `b` to obtain `c4 = Enc_pk(k2^-1.H(x).b + k2^-1.rx2x1.b mod q)` and sends to `P1`. 
8. `P1` decrypts `c4` using their Pailier secret key `sk` to give `t = Dec_sk(c4) = k2^-1.H(x).b + k2^-1.rx2x1.b mod q`. 
9. `P1` multiplies `t` by the inverse of their ephemeral key share `k1^-1` to compute the blinded `s` value: `s_b = k^-1.H(x).b + k^-1.rx.b mod q` and sends to `P2`. 
10. `P2` then unblinds `s_b` to obtain the final signature `s = s_b.b^-1`
11. `P2` verifies `(r,s)` against the message `m` and the shared public key `Q`. 

#### Assumptions

The two-party ECDSA in it's fully blinded form breaks several security assumptions since it is not possible for the `P1` to perform certain verifications, however this is not an issue if `P1` adds constraints to signing operations - specifically `P1` enforces a rule that they will only perform a single co-signing for a given generated private key (as required for a statechain entity), therefore preventing `P2` from being able to learn anything about either `x1` or `k1` from a single request. 

### Wallet tx verification

The central rule of locktime based statechains is that the server ensures that the current owner has the closest locktime backup transaction, and that no other transactions have been co-signed outside of the strictly decrementing sequence. Therefore the server would have to verify the tx details of locktime of everything it co-signed. 

In the blinded protocol, the server cannot verify what it signs, but can only HOW MANY unique signatures it has generated for a specific shared key, and it will return this number when queried by a wallet. The wallet will then have to check that every single previous backup transaction signed has been correctly decremented, AND that the total number of value backup transactions it has verified matches the number of signatures the server has co-generated. This will then enable a receiving wallet to verify that no other valid transactions spending the statecoin output exist (given it trusts the server to return the correct number of signatures). 

When it comes to withdrawal, the server can no longer verify that any fee has been added to the withdrawal transaction, and the wallet can just create any transaction it wants to end the chain. In this case, any fee collected by the SE must be done separately to the statecoin transactions (and can be required on deposit, before the keygen process is enabled). 
