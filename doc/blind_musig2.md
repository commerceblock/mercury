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
