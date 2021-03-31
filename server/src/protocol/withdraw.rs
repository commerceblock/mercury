//! StateEntity Withdraw
//!
//! StateEntity Withdraw protocol trait and implementation for StateChainEntity.

pub use super::super::Result;
extern crate shared_lib;
use crate::structs::StateChainOwner;
use crate::server::WITHDRAWALS_COUNT;
use shared_lib::{state_chain::*, structs::*};

use rocket::State;
use rocket_contrib::json::Json;

use crate::error::SEError;
use crate::Database;
use crate::{server::StateChainEntity, storage::Storage};
use cfg_if::cfg_if;
use uuid::Uuid;
use rocket_okapi::openapi;

cfg_if! {
    if #[cfg(any(test,feature="mockdb"))]{
        use crate::MockDatabase;
        use monotree::database::MemoryDB;
        type SCE = StateChainEntity::<MockDatabase, MemoryDB>;
    } else {
        use crate::PGDatabase;
        type SCE = StateChainEntity::<PGDatabase, PGDatabase>;
    }
}

/// StateChain Withdraw protocol trait
pub trait Withdraw {
    fn verify_statechain_sig(
        &self,
        statechain_id: &Uuid,
        statechain_sig: &StateChainSig,
        user_id: Option<Uuid>,
    ) -> Result<StateChainOwner>;

    /// User request withdraw:
    ///     - Check StateChainSig validity
    ///     - Mark user as authorised to withdraw
    fn withdraw_init(&self, withdraw_msg1: WithdrawMsg1) -> Result<()>;

    /// Finish withdrawal:
    ///     - Ensure withdraw tx has been signed
    ///     - Update UserSession, StateChain and Sparse merkle tree
    ///     - Return withdraw tx signature
    fn withdraw_confirm(&self, withdraw_msg2: WithdrawMsg2) -> Result<Vec<Vec<Vec<u8>>>>;
}

impl Withdraw for SCE {
    //Returns the statechain owner id if the signature is correct
    fn verify_statechain_sig(
        &self,
        statechain_id: &Uuid,
        statechain_sig: &StateChainSig,
        user_id: Option<Uuid>,
    ) -> Result<StateChainOwner> {
        // Get statechain owner
        let sco = self.database.get_statechain_owner(*statechain_id)?;
        //If a user id is supplied then check it,
        //and check that the statechain is unlocked
        match user_id {
            Some(id) => {
                // Check if locked
                is_locked(sco.locked_until)?;
                // check if owned by caller
                if sco.owner_id != id {
                    return Err(SEError::Generic(format!(
                        "State Chain not owned by User ID: {}.",
                        statechain_id
                    )));
                }
                ()
            }
            None => (),
        };

        // Verify StateChainSig
        let prev_proof_key = sco.chain.get_tip()?.data;
        statechain_sig.verify(&prev_proof_key)?;
        Ok(sco)
    }

    fn withdraw_init(&self, withdraw_msg1: WithdrawMsg1) -> Result<()> {
//        for (user_id, statechain_sig) in  
            //(withdraw_msg1.shared_key_ids, withdraw_msg1.statechain_sigs)
        for (user_id, statechain_sig) in 
            withdraw_msg1.shared_key_ids.iter().zip(withdraw_msg1.statechain_sigs.iter())
        {
            self.check_user_auth(&user_id)?;

            info!("WITHDRAW: Init. Shared Key ID: {}", user_id);

            let statechain_id = self.database.get_statechain_id(*user_id)?;

            self.verify_statechain_sig(
                &statechain_id,
                &statechain_sig,
                Some(*user_id),
            )?;

        // Mark UserSession as authorised for withdrawal

        self.database
            .update_withdraw_sc_sig(&user_id, statechain_sig.clone())?;

        info!(
            "WITHDRAW: Authorised. Shared Key ID: {}. State Chain: {}",
            user_id, statechain_id
        );
        }

        Ok(())
    }

    fn withdraw_confirm(&self, withdraw_msg2: WithdrawMsg2) -> Result<Vec<Vec<Vec<u8>>>> {
        let mut result = Vec::<Vec::<Vec::<u8>>>::new();
        
        for (i, user_id) in withdraw_msg2.shared_key_ids.iter().enumerate() {

            info!("WITHDRAW: Confirm. Shared Key ID: {}", user_id.to_string());

            // Get withdraw data - Checking that withdraw tx and statechain signature exists
            let wcd = self.database.get_withdraw_confirm_data(user_id.to_owned())?;

            // Ensure withdraw tx has been signed. i,e, that prepare-sign-tx has been completed.
            if wcd.tx_withdraw.input[i].witness.len() == 0 {
                return Err(SEError::Generic(String::from(
                   "Signed Back up transaction not found.",
                )));
            }

            // Get statechain and update with final StateChainSig
            let mut state_chain: StateChain = self.database.get_statechain(wcd.statechain_id)?;

            state_chain.add(wcd.withdraw_sc_sig.to_owned())?;

            self.database
                .update_statechain_amount(&wcd.statechain_id, state_chain, 0)?;

            // Remove statechain_id from user session to signal end of session
            self.database.remove_statechain_id(&user_id)?;

            //increment withdrawals metric
            WITHDRAWALS_COUNT.inc();

            // Update sparse merkle tree
            let (prev_root, new_root) = self.update_smt(
                &wcd.tx_withdraw
                    .input
                    .get(0)
                    .unwrap()
                    .previous_output
                    .txid
                    .to_string(),
                &withdraw_msg2.address,
            )?;

            //remove backup tx from the backup db
            self.database.remove_backup_tx(&wcd.statechain_id)?;

            info!(
                "WITHDRAW: Address included in sparse merkle tree. State Chain ID: {}",
                wcd.statechain_id
            );
            debug!(
                "WITHDRAW: State Chain ID: {}. New root: {:?}. Previous root: {:?}.",
                wcd.statechain_id, &new_root, &prev_root
            );

            info!(
                "WITHDRAW: Complete. Shared Key ID: {}. State Chain: {}",
                user_id.to_string(),
                wcd.statechain_id
            );

            result.push(wcd.tx_withdraw.input[0].clone().witness);
        };

        Ok(result)
    }
}

#[openapi]
/// # Initiate the withdrawal process: provide signed statechain
#[post("/withdraw/init", format = "json", data = "<withdraw_msg1>")]
pub fn withdraw_init(sc_entity: State<SCE>, withdraw_msg1: Json<WithdrawMsg1>) -> Result<Json<()>> {
    match sc_entity.withdraw_init(withdraw_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Complete the withdrawal process: confirm withdrawal transaction
#[post("/withdraw/confirm", format = "json", data = "<withdraw_msg2>")]
pub fn withdraw_confirm(
    sc_entity: State<SCE>,
    withdraw_msg2: Json<WithdrawMsg2>,
) -> Result<Json<Vec<Vec<Vec<u8>>>>> {
    match sc_entity.withdraw_confirm(withdraw_msg2.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockDatabase;
    use crate::{
        error::DBErrorType,
        protocol::util::{
            mocks,
            tests::{test_sc_entity, BACKUP_TX_NOT_SIGNED, BACKUP_TX_SIGNED},
        },
        structs::{StateChainOwner, WithdrawConfirmData},
    };
    use chrono::{Duration, Utc};
    use mockall::predicate;
    use std::str::FromStr;
    use uuid::Uuid;

    // Data from a run of transfer protocol.
    static WITHDRAW_MSG_1: &str = "{\"shared_key_ids\":[\"ad8cb891-ce91-447d-9192-bd105f3de602\"],\"statechain_sigs\":[{\"purpose\":\"WITHDRAW\",\"data\":\"bcrt1qt3jh638mmuzmh92jz8c4wj392p9gj2erf2zut8\",\"sig\":\"304402201abaa7f64b50e8a75ca840a2be6317b501e3b5b5abd057465c165c9b872799f4022000d8e36734857237cab323c7244dd5249295b51905b43bf4e93396b58317d872\"}]}";
    static STATE_CHAIN_ID: &str = "2b41ff74-510d-4fe7-90a6-714a26a137da";
    static STATE_CHAIN: &str = "{\"chain\":[{\"data\":\"026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e\",\"next_state\":null}]}";
    static STATE_CHAIN_SIG: &str = "{\"purpose\":\"WITHDRAW\",\"data\":\"bcrt1qt3jh638mmuzmh92jz8c4wj392p9gj2erf2zut8\",\"sig\":\"304402201abaa7f64b50e8a75ca840a2be6317b501e3b5b5abd057465c165c9b872799f4022000d8e36734857237cab323c7244dd5249295b51905b43bf4e93396b58317d872\"}";

    #[test]
    fn itegration_test_withdraw_init() {
        let withdraw_msg_1 = serde_json::from_str::<WithdrawMsg1>(WITHDRAW_MSG_1).unwrap();
        let shared_key_id = withdraw_msg_1.shared_key_ids[0];
        let statechain_id = Uuid::from_str(STATE_CHAIN_ID).unwrap();

        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_get_user_auth()
            .returning(move |_| Ok(shared_key_id));
        db.expect_get_statechain_id()
            .with(predicate::eq(shared_key_id))
            .returning(move |_| Ok(statechain_id));
        // shared_key_id does not own a state chain (use state chain id as shared key id to test)
        db.expect_get_statechain_id()
            .with(predicate::eq(statechain_id))
            .returning(move |_| {
                Err(SEError::DBError(
                    DBErrorType::NoDataForID,
                    statechain_id.to_string(),
                ))
            });
        db.expect_get_statechain_owner() // sc locked
            .with(predicate::eq(statechain_id))
            .times(1)
            .returning(move |_| {
                Ok(StateChainOwner {
                    locked_until: Utc::now().naive_utc() + Duration::seconds(5),
                    owner_id: shared_key_id,
                    chain: serde_json::from_str::<StateChain>(STATE_CHAIN).unwrap(),
                })
            });
        db.expect_get_statechain_owner()
            .with(predicate::eq(statechain_id))
            .returning(move |_| {
                Ok(StateChainOwner {
                    locked_until: Utc::now().naive_utc(),
                    owner_id: shared_key_id,
                    chain: serde_json::from_str::<StateChain>(STATE_CHAIN).unwrap(),
                })
            });
        db.expect_update_withdraw_sc_sig().returning(|_, _| Ok(()));

        let sc_entity = test_sc_entity(db);

        // user does not own State Chain
        let mut msg_1_wrong_shared_key = withdraw_msg_1.clone();
        msg_1_wrong_shared_key.shared_key_ids[0] = statechain_id;
        match sc_entity.withdraw_init(msg_1_wrong_shared_key.clone()) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("DB Error: No data for identifier.")),
        }
        // Sc locked
        match sc_entity.withdraw_init(withdraw_msg_1.clone()) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e
                .to_string()
                .contains("SharedLibError Error: Error: State Chain locked for 1 minutes.")),
        }

        // Expect successful run
        assert!(sc_entity.withdraw_init(withdraw_msg_1.clone()).is_ok());
    }

    #[test]
    fn itegration_test_withdraw_confirm() {
        let withdraw_msg_1 = serde_json::from_str::<WithdrawMsg1>(WITHDRAW_MSG_1).unwrap();
        let shared_key_ids = withdraw_msg_1.shared_key_ids;
        let withdraw_msg_2 = WithdrawMsg2 {
            shared_key_ids: shared_key_ids.clone(),
            address: "bcrt1qt3jh638mmuzmh92jz8c4wj392p9gj2erf2zut8".to_string(),
        };
        let statechain_id = Uuid::from_str(STATE_CHAIN_ID).unwrap();

        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_get_user_auth()
            .returning(move |_| Ok(shared_key_ids[0]));
        db.expect_get_withdraw_confirm_data()
            .times(1)
            .returning(move |_| {
                Ok(WithdrawConfirmData {
                    tx_withdraw: serde_json::from_str(&BACKUP_TX_NOT_SIGNED).unwrap(), // any tx is fine here
                    withdraw_sc_sig: serde_json::from_str::<StateChainSig>(
                        &STATE_CHAIN_SIG.to_string(),
                    )
                    .unwrap(),
                    statechain_id,
                })
            });
        db.expect_get_withdraw_confirm_data().returning(move |_| {
            Ok(WithdrawConfirmData {
                tx_withdraw: serde_json::from_str(&BACKUP_TX_SIGNED).unwrap(), // any tx is fine here
                withdraw_sc_sig: serde_json::from_str::<StateChainSig>(
                    &STATE_CHAIN_SIG.to_string(),
                )
                .unwrap(),
                statechain_id,
            })
        });
        db.expect_get_statechain()
            .returning(move |_| Ok(serde_json::from_str::<StateChain>(STATE_CHAIN).unwrap()));
        db.expect_update_statechain_amount()
            .returning(|_, _, _| Ok(()));
        db.expect_remove_statechain_id().returning(|_| Ok(()));
        db.expect_root_get_current_id().returning(|| Ok(1 as i64));
        db.expect_get_root().returning(|_| Ok(None));
        db.expect_root_update().returning(|_| Ok(1));
        db.expect_remove_backup_tx().returning(|_| Ok(()));

        let sc_entity = test_sc_entity(db);
        let _m = mocks::ms::post_commitment().create(); //Mainstay post commitment mock

        // Ensure backup tx has been signed
        match sc_entity.withdraw_confirm(withdraw_msg_2.clone()) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e
                .to_string()
                .contains("Signed Back up transaction not found.")),
        }

        // Expect successful run
        assert!(sc_entity.withdraw_confirm(withdraw_msg_2.clone()).is_ok());
    }
}
