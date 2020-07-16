# Swap
To perform a transfer the receiver provides a StateChain Entity Address (SCE-Address) to the sender. A StateChain transfer is implemented as two functions: The sender calls `transfer_sender()` to performs their half of the protocol and the receiver calls `transfer_receiver()` to perform their half and thus complete the transfer.

A swap is an atomic batch of StateChain transfers - either all transfers in a batch are successful or none of them are. A swap should be between StateChains of the same value. A swap can be between 2 participants where StateChains are simply swapped between the 2, or between 1000 participants where each StateChains is transferred to an address of another participant in the swap.

A public StateChain Entity API is available displaying swap progress information. StateChains that are involved in the swap are listed and their completion status displayed. A StateChain in a swap can be `incomplete`, `complete` or `validated` depending on how far along into the transfer process the StateChain is. Users of the system can query this API to identify StateChains that have recently failed and avoid swapping with these participants in the future if they wish.

## Coordinator
This document outlines a protocol for organising a swap round. We call this software the Coordinator. Its jobs include:

- Decide on a set of parameters for a swap
- Choose suitable participants
- Pass messages between participants
- Implement a blame mechanism to protect against Denial of Service attacks


### Phase 0
First a Coordinator needs to gather some participants for their swap proposal. There are two options for how this could work:

1) **Public Bulletin Board**: Participants advertise their desire to swap some amount with some minimum anonymity set on a public bulletin board. The Coordinator finds a set of suitable adverts and initiates the protocol. Any wallet can act as a Coordinator here since all adverts are seen by everyone.

2) **Individual Coordinator APIs**: Participants alert a Coordinator they trust of their desire to swap some amount with some minimum anonymity set. Coordinators decide on group sizes and initiates the protocol. This method may be useful for organising swaps with many participants by having consistent times for swaps of certain amounts, e.g. a swap for 1 BTC UTXOs at 8am, 1.5 BTC at 9am, etc..


### Phase 1 - Initiate
1) Coordinator creates a `swap_token` containing parameters for the swap it is about to propose. Participants will sign this token as a form of commitment to the swap. The token is also included in their transfer to signal that this transfer is a part of this batch.

| Token Parameter       | Description |
| :---            | :----  |  
| batch_id        | Unique identifier for the swap   |
| amount          | BTC amount that each UTXO must be  |
| time_out        | Lifetime of swap - if reached then swap is cancelled and no transfers are finalized |
| state_chain_ids | List of all StateChains involved  |

2) Coordinator sends each participant the `swap_token`. If a participant is happy with the swap parameters then they return an SCE-Address and produce a signature over the `swap_token` with the proof key that currently owns the state chain they are transferring in the swap.

The phase is complete when all have responded. If a time-out is reached then cancel and start from the top excluding those who did not respond. Little work has been done so far so this is not a DoS risk.

### Phase 2 - Create and distribute blinded tokens
Coordinator creates and distributes a single-use blinded token per participant.


### Phase 3 - Participants produce an SCE-Address and perform transfer-sender
1) Participants create a fresh anonymous network identity and contact Coordinator asking for another participants' SCE-Address. Coordinator responds with an SE-Address and considers the blinded token 'spent'.
2) Participants carry out `transfer_sender()` with their given SCE-Address and mark the transfer as part of a swap by providing the `swap_token`. The StateChain involved is labelled `complete`
3) Participants signal validation of transfers sent **to** them by performing `transfer_receiver()`. This is to ensure that the transfer is successful and ready to be finalized. The StateChain is then labelled `validated`.
In step 3 participants provide a blinded commitment `Comm(state_chain_id, nonce)` to the StateChain that they transferred in step 2 which may be revealed for blame assignment in the final phase.


### Phase 4 - End or blame assignment
The protocol is now complete for honest and live participants. If all transfers are completed before `swap_token.time_out` time has passed since the first `transfer_sender` is performed then the swap is considered complete and all transfers are finalized.

On the other hand if `swap_token.time_out` time passes before all transfers are complete then all transfers are rewound and no state chains involved in the swap have been transferred. The coordinator can now publish the list of signatures which signal the participants' commitment to the batch transfer. This can be included in the SCE public API so that all clients can access a list of those StateChains that have caused recent failures. Participants that completed their transfers can reveal the `nonce` to the their `Comm(state_chain_id, nonce)` and thus prove which StateChain they own and should not take any responsibility for the failure.  

## Assigning blame at failure
After failure it is useful to know which StateChains failed to complete their transfer. Each StateChain in the swap is marked `incomplete`, `complete` or `validated`. There is also a list of `state_chain_ids` that were committed to during successful `transfer_receiver()` calls. Below details how we can assign blame from this information:

`incomplete` - StateChain is clearly responsible for failing to perform `transfer_sender()`.

`complete`/`validated` - StateChain performed `transfer_sender()`. If this StateChain's ID is present in the list of revealed commitments then we know they successfully performed `transfer_receiver()` and thus completed their parts of the protocol successfully, whereas if it is not present then we know that a StateChain failed to perform `transfer_receiver()` and should be assigned blame.  
