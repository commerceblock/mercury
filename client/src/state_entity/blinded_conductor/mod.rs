pub mod swap_init;

use uuid::Uuid;

use super::super::Result;

use crate::{wallet::wallet::Wallet, error::CError};

pub fn do_swap(
    mut wallet: &mut Wallet,
    statechain_id: &Uuid,
    swap_size: &u64,
    with_tor: bool,
) -> Result<()> {

    if with_tor & (!wallet.client_shim.has_tor()  |! wallet.conductor_shim.has_tor()){
        return Err(CError::SwapError("tor not enabled".to_string()));
    }

    // step 1
    swap_init::swap_register_utxo(&wallet, &statechain_id, &swap_size)?;


    Ok(())

}