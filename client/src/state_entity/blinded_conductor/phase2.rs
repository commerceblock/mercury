use shared_lib::{blinded_token::{BlindedSpendSignature, BSTRequestorData}, swap_data::{BSTMsg, SwapMsg2}, structs::SCEAddress};
use uuid::Uuid;

use super::super::super::Result;

use crate::{ClientShim, utilities::requests, wallet::wallet::Wallet};

pub fn swap_get_blinded_spend_signature(
    client_shim: &ClientShim,
    swap_id: &Uuid,
    statechain_id: &Uuid,
) -> Result<BlindedSpendSignature> {
    requests::postb(
        &client_shim,
        &String::from("swap/blinded-spend-signature"),
        &BSTMsg {
            swap_id: swap_id.to_owned().to_string(),
            statechain_id: statechain_id.to_owned().to_string(),
        },
    )
}

pub fn swap_second_message(
    wallet: &Wallet,
    swap_id: &Uuid,
    my_bst_data: &BSTRequestorData,
    blinded_spend_signature: &BlindedSpendSignature,
) -> Result<SCEAddress> {
    let s = my_bst_data.unblind_signature(blinded_spend_signature.to_owned());
    let bst = my_bst_data.make_blind_spend_token(s);

    requests::postb(
        &wallet.conductor_shim,
        &String::from("swap/second"),
        &SwapMsg2 {
            swap_id: swap_id.to_owned(),
            blinded_spend_token: bst,
        },
    )
}