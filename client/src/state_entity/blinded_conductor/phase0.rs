use shared_lib::structs::{SwapID, StatechainID};
use uuid::Uuid;

use super::super::super::Result;

use crate::{ClientShim, utilities::requests};

pub fn swap_poll_utxo(client_shim: &ClientShim, statechain_id: &Uuid) -> Result<SwapID> {
    requests::postb(
        &client_shim,
        &String::from("swap/poll/utxo"),
        &StatechainID { id: *statechain_id },
    )
}