# Swap

To perform a transfer the receiver provides a StateChain Entity Address (SCE-Address) to the sender. A StateChain transfer is implemented as two functions: The sender calls `transfer_sender()` to perform their half of the protocol and the receiver calls `transfer_receiver()` to perform their half and thus complete the transfer.

A swap is an atomic batch of StateChain transfers - either all transfers in a batch are successful or none of them are. A swap should be between StateChains of the same value. A swap can be between 2 participants where StateChains are simply swapped between the 2, or between n participants where each StateChains is transferred to an address of another participant in the swap.

A public StateChain Entity API is available displaying swap progress information. StateChains that are involved in the swap are listed and their completion status displayed. A StateChain in a swap can be `incomplete`, `complete` or `validated` depending on how far along into the transfer process the StateChain is. Users of the system can query this API to identify StateChains that have recently failed and avoid swapping with these participants in the future if they wish.

## Conductor

This document outlines a protocol for organising a swap round. We call this software the Conductor. Its jobs include:

- Decide on a set of parameters for a swap
- Choose suitable participants
- Blindly assign an SCE-Address for each participant to transfer to
- Implement a blame mechanism to protect against Denial of Service attacks

The protocol is made up of 4 phases as outlined below.

### Phase 0

First a Conductor gathers some participants for their swap proposal. There are two options for how this could work:

1) **Public Bulletin Board**: Participants advertise their desire to swap some BTC amount with some minimum swap size (number of participants) on a public bulletin board. The Conductor finds a set of suitable adverts and initiates the protocol. Any wallet can act as a Conductor here since all adverts are seen by everyone.

2) **Individual Conductor APIs**: Participants alert a Conductor they trust of their desire to swap some amount with some minimum swap size. Conductors decide on group sizes and initiates the protocol. This method may be useful for organising swaps with many participants by having consistent times for swaps of certain amounts, e.g. a swap for 1 BTC UTXOs at 8am, 1.5 BTC at 9am, etc..


### Phase 1 - Initiate

1) Conductor creates a `swap_token` containing parameters for the swap it is about to propose. Participants will sign this token as a form of commitment to the swap. The token is also included in their transfer to signal that this transfer is a part of this batch.

| Token Parameter | Description |
| :---            | :----  |  
| batch_id        | Unique identifier for the swap   |
| amount          | BTC amount that each UTXO must be  |
| time_out        | Lifetime of swap - if reached then swap is cancelled and no transfers are finalized |
| statechain_ids | List of all StateChains involved  |

2) Conductor sends each participant the `swap_token`. If a participant is happy with the swap parameters then they return an SCE-Address and produce a signature over the `swap_token` with the proof key that currently owns the state chain they are transferring in the swap.

The phase is complete when all have responded. If a time-out is reached then cancel and start from the top excluding those who did not respond. Little work has been done so far so this is not a DoS risk.

### Phase 2 - Create and distribute blinded tokens

Conductor creates and distributes a single-use blinded token per participant.


### Phase 3 - Participants produce an SCE-Address and perform transfer-sender

1) Participants create a fresh anonymous network identity and contact Conductor asking for another participants' SCE-Address. Conductor responds with an SE-Address and considers the blinded token 'spent'.
2) Participants carry out `transfer_sender()` with their given SCE-Address and mark the transfer as part of a swap by providing the `swap_token`. The StateChain involved is labelled `complete`
3) Participants signal validation of transfers sent **to** them by performing `transfer_receiver()`. This is to ensure that the transfer is successful and ready to be finalized. The StateChain is then labelled `validated`.
In step 3 participants provide a blinded commitment `Comm(statechain_id, nonce)` to the StateChain that they transferred in step 2 which may be revealed for blame assignment in the final phase.

### Phase 4 - End or blame assignment

The protocol is now complete for honest and live participants. If all transfers are completed before `swap_token.time_out` time has passed since the first `transfer_sender` is performed then the swap is considered complete and all transfers are finalized.

On the other hand if `swap_token.time_out` time passes before all transfers are complete then all transfers are rewound and no state chains involved in the swap have been transferred. The Conductor can now publish the list of signatures which signal the participants' commitment to the batch transfer. This can be included in the SCE public API so that all clients can access a list of those StateChains that have caused recent failures. Participants that completed their transfers can reveal the `nonce` to the their `Comm(statechain_id, nonce)` and thus prove which StateChain they own and should not take any responsibility for the failure.  

## Assigning blame at failure

After failure it is useful to know which StateChains failed to complete their transfer. Each StateChain in the swap is marked `incomplete`, `complete` or `validated`. There is also a list of `statechain_ids` that were committed to during successful `transfer_receiver()` calls. Below details how we can assign blame from this information:

`incomplete` - StateChain is clearly responsible for failing to perform `transfer_sender()`.

`complete`/`validated` - StateChain performed `transfer_sender()`. If this StateChain's ID is present in the list of revealed commitments then we know they successfully performed `transfer_receiver()` and thus completed their parts of the protocol successfully, whereas if it is not present then we know that a StateChain failed to perform `transfer_receiver()` and so can be assigned blame. 

## Malicious key-share tampering

In order to prevent DoS attacks, statechains which fail (or repeatedly fail) to complete the transfer as part of a swap must be blacklisted by the conductor. This will make any sustained DoS economically prohibitive, as BTC outputs will be locked up (from participating in swaps) each time a swap fails to complete. The issue with the nature of the transfer process with Mercury, is that the sender can send an incorrect or tampered blinded key share (`t1 = x1o1`) to the reciever preventing them from completing the `transfer_receiver()` step. In this case, the sender is to blame, but the reciver is unable to complete their step. Alternatively, the receiver (who is also the sender of another statechain) may be an attacker and could tamper with the key share (`t1/t2`) value, also preventing the `transfer_receiver()` from completing. In this case, it is not immediately possible to determine whether it was the sender of the receiver who tampered/modified the blinded key share. 

The blinded key share (`t1`) is sent from the sender to the reciever via the StateChain entity, however it must be encrypted with the reciever public key (proof key) when passing via the SE, since the statechain entity can determine the full output private key (`s1o1`) if they learn `t1 = x1o1` (since they know `x1` and `s1`). Therefore, to correctly assign blame for the failure of `transfer_receiver()` due to a tampered `t1/t2`, the StateChain entity must verify that the encrypted blinded-keyshare is valid (or invalid). 

This can be achieved via the public points of the intermediate key share values and a compact zero-knowledge proof that the encrypted value is equal to the private key corresponding to a known public point. 

The additional protocol proceeds as follows:

1. The sender computes `t1 = x1o1` after reciving `x1` from the StateChain entity from `transfer_sender()`. 
2. The sender computes the EC point corresponding to `t1`: `T1 = t1.G`. 
3. The sender encrypts `t1` with the reciver proof key `C2` using an ECIES algorithm:

a. Sender generates ephemeral key `y` and `Y = y.G`
b. Sender derives symetric key `k = H([y.C2]_x)` where `[y.C2]_x` is the x-coordinate of `y.C2`
c. Sender encrypts `t1`: `c = E(k;t1)` where `E` is a symmetric algorithm. 
d. Sender outputs `Y` and `c`

4. The sender then computes a non-interactive proof of the following statement: "The value `c` is an encryption of a value `t1` (with a key `k` that is derived from `c2.Y` where `c2` is the private key of public point `C2`), which the multiplier of the public point `T1`" without revealing `c2`, `k`, `y` or `t1`. Writen as a function:

```cpp
bool verify(c,Y,C2,T1,k,c2,t1,y) {
	if(T1 == t1.G && C2 == c2.G && Y = Y.G && k = H([y.C2]_x) && c = E(k;t1)) {
		return true;
	} else {
		return false;
	}
}
```

This non-interactive proof is denoted `P`. 

5. The sender then sends `c`, `Y`, `T1` and `P` to the reciever via the StateChain entity. 
6. The StateChain entity then verifies the proof `P` against the given values `c`, `Y`, `T1` and also verifies that `T1 = x1.O1` where `O1 = o1.G`. 

If the verification passes, then the values `c` and `Y` are forwarded to the reciever (along with the other transfer objects) and any failure will be the result of the reciever manipulating the recieved value of `t1`. If the verification fails, then this is proof that the sender has tampered with the value of `t1` and their output should be blacklisted. 

The proof `P` can be generated and verified using the generalised zkSNARK system as implemented in `libsnark`. 
