//! Conductor
//!
//! Conductor swap protocol trait and implementation. Full protocol descritpion can be found in Conductor Trait.

use super::super::Result;

extern crate shared_lib;
use shared_lib::structs::*;

use rocket::State;
use rocket_contrib::json::Json;
use uuid::Uuid;
use crate::server::StateChainEntity;

/// Conductor protocol trait. Comments explain client and server side of swap protocol.
pub trait Conductor {
    /// API: Poll Conductor to check for status of registered utxo.
    fn poll_utxo(&self, state_chain_id: Uuid) -> Result<()>;

    /// API: Poll Conductor to check for status of swap.
    fn poll_swap(&self, batch_id: Uuid) -> Result<()>;

    /// API: Phase 0:
    ///     - Alert Conductor of desire to take part in a swap. Provide StateChainSig to prove
    ///         ownership of StateChain
    fn register_utxo(&self, register_utxo_msg: RegisterUtxo) -> Result<()>;

    // Phase 1: Conductor waits until there is a large enough pool of registered UTXOs of the same size, when
    // such a pool is found Conductor generates a SwapToken and marks each UTXO as "in phase 0 of swap with id: x".
    // When a participant calls poll_utxo they see that their UTXO is involved in a swap and receive the
    // SwapToken. They now move on to phase 1.

    /// API: Phase 1:
    ///    - Participants signal agreement to Swap parameters by signing the SwapToken and
    ///         providing a fresh SCE_Address
    fn swap_first_message(&self, swap_msg1: SwapMsg1) -> Result<()>;

    // Phase 2: Iff all participants have successfuly carried out Phase 1 then Conductor generates a blinded token
    // for each participant and marks each UTXO as "in phase 1 of swap with id: x". Upon polling the
    // participants receive 1 blinded token each.

    /// API: Phase 3:
    ///    - Participants create a new Tor identity and "spend" their blinded token to receive one
    //         of the SCEAddress' input in phase 1.
    fn swap_second_message(&self, swap_msg2: SwapMsg2) -> Result<SCEAddress>;

    // Phase 3: Participants carry out transfer_sender() and signal that this transfer is a part of
    // swap with id: x. Participants carry out corresponding transfer_receiver() and provide their
    // commitment Comm(state_chain_id, nonce), to be used later as proof of completeing the protocol
    // if the swap fails.

    // Phase 4: The protocol is now complete for honest and live participants. If all transfers are
    // completed before swap_token.time_out time has passed since the first transfer_sender() is performed
    // then the swap is considered complete and all transfers are finalized.
    //
    // On the other hand if swap_token.time_out time passes before all transfers are complete then all
    // transfers are rewound and no state chains involved in the swap have been transferred.
    // The coordinator can now publish the list of signatures which signal the participants' commitment
    // to the batch transfer. This can be included in the SCE public API so that all clients can access a
    // list of those StateChains that have caused recent failures. Participants that completed their
    // transfers can reveal the nonce to the their Comm(state_chain_id, nonce) and thus prove which
    // StateChain they own and should not take any responsibility for the failure.
}

/// Struct defines a Swap. This is signed by each participant as agreement to take part in the swap.
#[allow(dead_code)]
pub struct SwapToken {
    id: Uuid,
    amount: u64,
    time_out: u64,
    state_chain_ids: Vec<Uuid>,
}

impl Conductor for StateChainEntity {
    fn poll_utxo(&self, _state_chain_id: Uuid) -> Result<()> {
        todo!()
    }
    fn poll_swap(&self, _batch_id: Uuid) -> Result<()> {
        todo!()
    }
    fn register_utxo(&self, _register_utxo_msg: RegisterUtxo) -> Result<()> {
        todo!()
    }
    fn swap_first_message(&self, _swap_msg1: SwapMsg1) -> Result<()> {
        todo!()
    }
    fn swap_second_message(&self, _swap_msg2: SwapMsg2) -> Result<SCEAddress> {
        todo!()
    }
}

#[post("/swap/poll/utxo", format = "json", data = "<state_chain_id>")]
pub fn poll_utxo(
    sc_entity: State<StateChainEntity>,
    state_chain_id: Json<Uuid>,
) -> Result<Json<()>> {
    match sc_entity.poll_utxo(state_chain_id.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/swap/poll/swap", format = "json", data = "<batch_id>")]
pub fn poll_swap(sc_entity: State<StateChainEntity>, batch_id: Json<Uuid>) -> Result<Json<()>> {
    match sc_entity.poll_swap(batch_id.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/swap/register-utxo", format = "json", data = "<register_utxo_msg>")]
pub fn register_utxo(
    sc_entity: State<StateChainEntity>,
    register_utxo_msg: Json<RegisterUtxo>,
) -> Result<Json<()>> {
    match sc_entity.register_utxo(register_utxo_msg.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/swap/first", format = "json", data = "<swap_msg1>")]
pub fn swap_first_message(
    sc_entity: State<StateChainEntity>,
    swap_msg1: Json<SwapMsg1>,
) -> Result<Json<()>> {
    match sc_entity.swap_first_message(swap_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/swap/second", format = "json", data = "<swap_msg2>")]
pub fn swap_second_message(
    sc_entity: State<StateChainEntity>,
    swap_msg2: Json<SwapMsg2>,
) -> Result<Json<(SCEAddress)>> {
    match sc_entity.swap_second_message(swap_msg2.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}
