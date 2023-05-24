use bitcoin::Transaction;
use uuid::Uuid;
use crate::{error::CError, wallet::wallet::ElectrumxBox};

use super::super::Result;

pub fn verify_tx_backup_confirmed(electrumx_client: &mut ElectrumxBox, tx_backup: &Transaction ) -> Result<()> {

    // Get back up tx and proof key
    let txid = tx_backup.input[0].previous_output.txid.to_string();
    // let vout = tx_backup.input[0].previous_output.vout as usize;

    match electrumx_client.instance.get_transaction_conf_status(txid.clone(), false) {
        Ok(res) => {
            // Check for tx confs. If none after 10*(block time) then return error.
            if res.confirmations.is_none() {
                return Err(CError::Generic(String::from(
                    "Funding Transaction not confirmed.",
                )));
            }
            else if res.confirmations.unwrap() <  1 { // self.config.required_confirmation {
                return Err(CError::Generic(String::from(
                    "Funding Transaction insufficient confirmations.",
                )));
            }
        }
        Err(_) => {
            return Err(CError::Generic(String::from(
                "Funding Transaction not found.",
            )));
        }
    }

    Ok(())
}