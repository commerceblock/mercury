# Blinded Two-Party ECDSA Signing

Two-party ECDSA protocols enable two mutually distrusting parties to both securely generate a shared private and public key pair, and generate a valid ECDSA signature on a mutually agreed message without either party learning any information about the other parties key share or the full private key. We propose a method based on the Lindell [1] protocol to enable one of the two parties to participate in the signature generation in a completely blinded way, such that they learn nothing about either the message being signed or the final valid signature itself. 

## ECDSA signing

The standard ECDSA operates as follows. A signatory has a private key `x` and corresponding public key `Q` which is the elliptic curve point `Q = x.G` where `G` is the generator point of an elliptic curve group of order `q` and `.` denotes elliptic curve point multiplication (upper case letters are points, lower case letters are scalars). The signatory signs message `m`, and `H()` is the SHA256 hash function. 

1. Choose a random ephemeral key `k <- Zq`
2. Compute `R = k.G`
3. Compute `r = r_x mod q` where `R = (r_x,r_y)`
4. Compute `s = k^-1(H(m) + rx) mod q`
5. Output the signature `(r,s)`

The value `k^-1` is the modular inverse of the key `k`. A critical feature of the standard ECDSA is that the key `k` must be kept secret and deleted after signing (i.e. not used to generate a second signature). Revealing `k` or re-using it to sign a second message allows anyone to discover the private key `x`. 

## Two-party ECDSA signing

Two mutually distrusting parties can share the key pair `x` and `Q` in a way that no one ever knows the full `x` and both parties need to cooperate in order to generate a valid signature over `Q`. For compatibility with the arithmetic of ECDSA (multiplication by modulo inversions), the optimum way to split the full private key is with multiplicative sharing, i.e. `x = x1x2` where `x1` and `x2` are the party 1 (`P1`) and party 2 (`P2`) shares respectively. In order to enable multiparty computation of the full signature, the Pailier encryption system is used to perform the homomorphic addition of terms to calculate `s`. 

### Distributed key generation

`P1` and `P2` can cooperate to generate a public key `Q` corresponding to a shared private key `x` (that never comes into existence explicitly). This is performed as follows:

1. `P1` chooses a random key `x1 <- Zq` and computes `Q1 = x1.G` and sends to `P2`
2. `P2` chooses a random key `x2 <- Zq` and computes `Q2 = x2.G` and sends to `P1`
3. `P1` computes `Q = x1.Q2` and `P2` computes `Q = x2.Q1`

To remain secure under a malicious adversary assumption, each party must provide the other with a proof of knowledge of the discrete log of the point generated (using a Schnorr proof). 

In the protocol of Lindell [1], `P1` then generates a Pailier key pair `(pk,sk)` and then computes `ck = Enc_pk(x1)` which is the Pailier encryption of the `P1` private key share. In addition to this, `P1` also sends a zero-knowledge proof to `P2` that a value encrypted in
a given Paillier ciphertext is the discrete log of a given elliptic curve point. 

### Distributed two-party signing

When `P1` and `P2` agree to produce a signature on a known message `m`, the first step is to generate a shared ephemeral key `k` and corresponding point `R` (`k` must be a shared key as knowledge of `k` enables the full private key to be derived from the signature). This key generation is performed in the same way as the key generation above, resulting in `P1` possessing a secret `k1` and `P2` possessing `k2`, where `R = k1.R2 = k2.R1 = k1k2.G` and `r` (the x coordinate of `R`) known and agreed by both parties. 

Then `P2` computes `c1 = Enc_pk(k2^-1.H(m) mod q)` and `v = k2^-1.rx2 mod q` using the Paillier public key `pk` from `P1`. 

`P2` then performs a homomorphic scalar multiplication of `v` by `ck` to obtain `c2 = Enc_pk(k2^-1.rx2x1 mod q)`, and then Pailier homomorphic addition of `c1` and `c2` to obtian `c3 = Enc_pk(k2^-1.H(x) + k2^-1.rx2x1 mod q)`. This so-called 'almost signature' is then sent to `P1`. 

The party `P1` recieves `c3` and can decrypt it using their Pailier secret key `sk` to give `t = Dec_sk(c3) = k2^-1.H(x) + k2^-1.rx2x1 mod q`. All that is now required is for `P1` to multiply this value by the inverse of their ephemeral key share `k1^-1` to complete the signature. 

`s = k1^-1.k2^-1.H(x) + k1^-1.k2^-1.rx2x1 mod q = k^-1.H(x) + k^-1.rx mod q`

`P1` then verifies the full signature `(r,s)` against the agreed message `m` and shared public key `Q`, and if verified then releases it to `P2`. 

## Blinded Two-party ECDSA signing

The principle of a *fully* blind two-party ECDSA (for the purposes of a Bitcoin transaction co-signing server), is that one party (i.e. `P1`) has a share of the full private key, as above, and can cooperate with `P2` to generate a signature for the shared public key `Q`, however this is done without `P1` learning any information about the message being signed (`m`) OR any information about the final valid signature `(r,s)` itself (since in Bitcoin, even if `P1` has no information on the message, they can search the public blockchain and find it if they know the final signature).  

Blinding the message `m` from `P1` in the above protocol is trivial: `H(m)` is added to the encrypted signature by `P2`, and `P1` verifies the final signature against `m` after completing it. If `P1` agrees to not know or care about the message `m`, then they simply send the final signature directly to `P2` to verify, without checking it themselves (because they can't as they don't know `m`). 

Blinding the final signature itself from `P1` is somewhat more involved, but is still fairly straightforward. A property of the above protocol to note is that, as with the message `m`, the value `r` is added to the Pailier encrypted expression only by `P2` and so there is no requirement for `P1` to have knowledge of `r`. To prevent `P1` from computing `r`, `P2` can simply not send `P1` the value `R2 = k2.G` after generating `k2` (`P2` still needs to recieve `R1 = k1.G` from `P1` to compute `r`). 

To prevent `P1` from learning the final value of `s`, even after finalising the computation of it, the plaintext Pailier encrypted 'almost signature' (`c3`) can be blinded with a blinding key/nonce via a a homomorphic scalar multiplication from `P2` before it is sent to `P1`. `P1` can then finalise the (blinded) `s` value by multiplying with `k1^-1` before returning it to `P2` who can then unblind it to get the final signature (`P1` having learnt nothing about the final `s` value). 

With these modifications, the signing protocol for a fully blinded `P1` then proceeds as follows:

1. `P1` chooses a random ephemeral key share `k1 <- Zq` and computes `R1 = k1.G` and sends to `P2`
2. `P2` chooses a random ephemeral key share `x2 <- Zq` and computes `R = k2.R1`
3. `P2` then determines `r` (the x component of `R` mod q). 
4. `P2` generate a random blinding key `b <- Zq`
5. `P2` chooses `m` and computes `c1 = Enc_pk(k2^-1.H(m) mod q)` and `v = k2^-1.rx2 mod q` using the Paillier public key `pk` from `P1`. 
6. `P2` then performs a homomorphic scalar multiplication of `v` by `ck` to obtain `c2 = Enc_pk(k2^-1.rx2x1 mod q)`, and then Pailier homomorphic addition of `c1` and `c2` to obtian `c3 = Enc_pk(k2^-1.H(x) + k2^-1.rx2x1 mod q)`.  
7. `P2` then performs a homomorphic scalar multiplication of `c3` by `b` to obtain `c4 = Enc_pk(k2^-1.H(x).b + k2^-1.rx2x1.b mod q)` and sends to `P1`. 
8. `P1` decrypts `c4` using their Pailier secret key `sk` to give `t = Dec_sk(c4) = k2^-1.H(x).b + k2^-1.rx2x1.b mod q`. 
9. `P1` multiplies `t` by the inverse of their ephemeral key share `k1^-1` to compute the blinded `s` value: `s_b = k^-1.H(x).b + k^-1.rx.b mod q` and sends to `P2`. 
10. `P2` then unblinds `s_b` to obtain the final signature `s = s_b.b^-1`
11. `P2` verifies `(r,s)` against the message `m` and the shared public key `Q`. 

### Assumptions

The two-party ECDSA in it's fully blinded form breaks several security assumptions since it is not possible for the `P1` to perform certain verifications, however this is not an issue if `P1` adds constraints to signing operations - specifically `P1` enforces a rule that they will only perform a single co-signing for a given generated private key (as required for a statechain entity), therefore preventing `P2` from being able to learn anything about either `x1` or `k1` from a single request. 

