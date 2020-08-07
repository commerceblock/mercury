//! StateEntity Deposit
//!
//! StateEntity Deposit trait and implementation for StateChainEntity.

use super::super::Result;
extern crate shared_lib;
use crate::error::SEError;
use crate::server::StateChainEntity;
use shared_lib::{state_chain::*, structs::*, util::FEE};

use rocket::State;
use rocket_contrib::json::Json;
use uuid::Uuid;
use crate::storage::Storage;
use crate::Database;
use mockall::predicate::*;
use mockall::*;

#[automock]
/// StateChain Deposit protocol trait
pub trait Deposit {
    /// API: Initiliase deposit protocol:
    ///     - Generate and return shared wallet ID
    ///     - Can do auth or other DoS mitigation here
    fn deposit_init(&self, deposit_msg1: DepositMsg1) -> Result<Uuid>;

    /// API: Complete deposit protocol:
    ///     - Wait for confirmation of funding tx in blockchain
    ///     - Create StateChain DB object
    ///     - Update sparse merkle tree with new StateChain entry
    fn deposit_confirm(
        &self,
        deposit_msg2: DepositMsg2,
    ) -> Result<Uuid>;
}

impl Deposit for StateChainEntity {
    fn deposit_init(&self, deposit_msg1: DepositMsg1) -> Result<Uuid> {
        // Generate shared wallet ID (user ID)
        let user_id = Uuid::new_v4();

        // if Verification/PoW/authoriation failed {
        //      warn!("Failed authorisation.")
        //      Err(SEError::AuthError)
        //  }

        // Create DB entry for newly generated ID signalling that user has passed some
        // verification. For now use ID as 'password' to interact with state entity
        self.database.create_user_session(&user_id, &deposit_msg1.auth,
            &deposit_msg1.proof_key)?;

        info!(
            "DEPOSIT: Protocol initiated. User ID generated: {}",
            user_id
        );
        debug!(
            "DEPOSIT: User ID: {} corresponding Proof key: {}",
            user_id,
            deposit_msg1.proof_key.to_owned()
        );

        Ok(user_id)
    }

    fn deposit_confirm(
        &self,
        deposit_msg2: DepositMsg2,
    ) -> Result<Uuid> {
        // let shared_key_id = deposit_msg2.shared_key_id.clone();
        let user_id = deposit_msg2.shared_key_id;

        // Get back up tx and proof key
        let (tx_backup, proof_key) = self.database.get_backup_transaction_and_proof_key(user_id)?;

        // Ensure backup tx exists is signed
        if tx_backup.input[0].witness.len() == 0 {
            return Err(SEError::Generic(String::from(
                "Signed Back up transaction not found.",
            )));
        }

        // Wait for funding tx existence in blockchain and confs
        self.verify_tx_confirmed(&tx_backup.input[0].previous_output.txid.to_string(), self)?;

        // Create state chain DB object
        let state_chain_id = Uuid::new_v4();
        let amount = (tx_backup.output.last().unwrap().value + FEE) as i64;
        let state_chain = StateChain::new(proof_key.clone());

        // Insert into StateChain table
        self.database.create_statechain(&state_chain_id, &user_id, &state_chain, &amount)?;

        // Insert into BackupTx table
        self.database.create_backup_transaction(&state_chain_id, &tx_backup)?;

        info!(
            "DEPOSIT: State Chain created. ID: {} For user ID: {}",
            state_chain_id, user_id
        );

        // Update sparse merkle tree with new StateChain entry
        let (new_root, current_root) = self.update_smt(
            &tx_backup
                .input
                .get(0)
                .unwrap()
                .previous_output
                .txid
                .to_string(),
                &proof_key,
        )?;

        info!(
            "DEPOSIT: Included in sparse merkle tree. State Chain ID: {}",
            state_chain_id
        );
        debug!(
            "DEPOSIT: State Chain ID: {}. New root: {:?}. Previous root: {:?}.",
            state_chain_id, new_root, current_root
        );

        // Update UserSession with StateChain's ID
        self.database.update_statechain_id(&user_id, &state_chain_id)?;
        Ok(state_chain_id)
    }
}

#[post("/deposit/init", format = "json", data = "<deposit_msg1>")]
pub fn deposit_init(
    sc_entity: State<StateChainEntity>,
    deposit_msg1: Json<DepositMsg1>,
) -> Result<Json<Uuid>> {
    match sc_entity.deposit_init(deposit_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/deposit/confirm", format = "json", data = "<deposit_msg2>")]
pub fn deposit_confirm(
    sc_entity: State<StateChainEntity>,
    deposit_msg2: Json<DepositMsg2>,
) -> Result<Json<Uuid>> {
    match sc_entity.deposit_confirm(deposit_msg2.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use shared_lib::Root;
    use std::str::FromStr;
    use bitcoin::{consensus, Transaction, util::misc::hex_bytes};

    fn test_deposit_init() {
        let user_id = Uuid::from_str("001203c9-93f0-46f9-abda-0678c891b2d3").unwrap();
        let proof_key = String::from("65aab40995d3ed5d03a0567b04819ff12641b84c17f5e9d5dd075571e183469c8f");

        // db.expect_create_user_session()
        // .returning(|_| Ok(user_id));

        // server.deposit_init(DepositMsg1{
        //     auth: String::from("auth"),
        //     proof_key
        // } )
    }

    fn test_deposit_confirm() {
        let user_id = Uuid::from_str("001203c9-93f0-46f9-abda-0678c891b2d3").unwrap();
        let proof_key = String::from("65aab40995d3ed5d03a0567b04819ff12641b84c17f5e9d5dd075571e183469c8f");

        let tx_backup: Transaction =
            consensus::deserialize(&hex_bytes(& "{\"version\":2,\"lock_time\":0,\"input\":[{\"previous_output\":\"faaaa0920fbaefae9c98a57cdace0deffa96cc64a651851bdd167f397117397c:0\",\"script_sig\":\"\",\"sequence\":4294967295,\"witness\":[[48,68,2,32,45,42,91,77,252,143,55,65,154,96,191,149,204,131,88,79,80,161,231,209,234,229,217,100,28,99,48,148,136,194,204,98,2,32,90,111,183,68,74,24,75,120,179,80,20,183,60,198,127,106,102,64,37,193,174,226,199,118,237,35,96,236,45,94,203,49,1],[2,242,131,110,175,215,21,123,219,179,199,144,85,14,163,42,19,197,97,249,41,130,243,139,15,17,51,185,147,228,100,122,213]]}],\"output\":[{\"value\":9000,\"script_pubkey\":\"00148fc32525487d2cb7323c960bdfb0a5ee6a364738\"}]}").unwrap()).unwrap();

        let current_root = Root::from_random();

        // db.expect_get_backup_transaction_and_proof_key(user_id)
        // .returning(|_| (tx_backup, proof_key));

        // db.expect_create_statechain()
        //     .returning(|_| Ok(());

        // db.expect_create_backup_transaction()
        //     .returning(|_| Ok(());

        // server.expect_update_smt()
        //     .returning(|_| (None, current_root));

        // db.expect_update_statechain_id()
        //     .returning(|_| Ok(());


        // server.deposit_confirm(DepositMsg2{
        //     shared_key_id: user_id
        // } )

    }
}
