//! StateEntity Withdraw
//!
//! StateEntity Withdraw protocol trait and implementation for StateChainEntity.

pub use super::super::Result;
extern crate shared_lib;
use crate::structs::StateChainOwner;
use shared_lib::{state_chain::*, structs::*};

use rocket::State;
use rocket_contrib::json::Json;

use crate::error::SEError;
use crate::Database;
use crate::{server::StateChainEntity, storage::Storage};
use cfg_if::cfg_if;
use uuid::Uuid;

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
    fn withdraw_confirm(&self, withdraw_msg2: WithdrawMsg2) -> Result<Vec<Vec<u8>>>;
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
        let user_id = withdraw_msg1.shared_key_id;
        self.check_user_auth(&user_id)?;

        info!("WITHDRAW: Init. Shared Key ID: {}", user_id);

        let state_chain_id = self.database.get_statechain_id(user_id)?;

        self.verify_statechain_sig(
            &state_chain_id,
            &withdraw_msg1.state_chain_sig,
            Some(user_id),
        )?;

        // Mark UserSession as authorised for withdrawal

        self.database
            .update_withdraw_sc_sig(&user_id, withdraw_msg1.state_chain_sig)?;

        info!(
            "WITHDRAW: Authorised. Shared Key ID: {}. State Chain: {}",
            user_id, state_chain_id
        );

        Ok(())
    }

    fn withdraw_confirm(&self, withdraw_msg2: WithdrawMsg2) -> Result<Vec<Vec<u8>>> {
        let user_id = withdraw_msg2.shared_key_id;
        info!("WITHDRAW: Confirm. Shared Key ID: {}", user_id.to_string());

        // Get withdraw data - Checking that withdraw tx and statechain signature exists
        let wcd = self.database.get_withdraw_confirm_data(user_id)?;

        // Ensure withdraw tx has been signed. i,e, that prepare-sign-tx has been completed.
        if wcd.tx_withdraw.input[0].witness.len() == 0 {
            return Err(SEError::Generic(String::from(
                "Signed Back up transaction not found.",
            )));
        }

        // Get statechain and update with final StateChainSig
        let mut state_chain: StateChain = self.database.get_statechain(wcd.state_chain_id)?;

        state_chain.add(wcd.withdraw_sc_sig.to_owned())?;

        self.database
            .update_statechain_amount(&wcd.state_chain_id, state_chain, 0)?;

        // Remove state_chain_id from user session to signal end of session
        self.database.remove_statechain_id(&user_id)?;

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

        info!(
            "WITHDRAW: Address included in sparse merkle tree. State Chain ID: {}",
            wcd.state_chain_id
        );
        debug!(
            "WITHDRAW: State Chain ID: {}. New root: {:?}. Previous root: {:?}.",
            wcd.state_chain_id, &new_root, &prev_root
        );

        info!(
            "WITHDRAW: Complete. Shared Key ID: {}. State Chain: {}",
            user_id.to_string(),
            wcd.state_chain_id
        );

        Ok(wcd.tx_withdraw.input[0].clone().witness)
    }
}

#[post("/withdraw/init", format = "json", data = "<withdraw_msg1>")]
pub fn withdraw_init(sc_entity: State<SCE>, withdraw_msg1: Json<WithdrawMsg1>) -> Result<Json<()>> {
    match sc_entity.withdraw_init(withdraw_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/withdraw/confirm", format = "json", data = "<withdraw_msg2>")]
pub fn withdraw_confirm(
    sc_entity: State<SCE>,
    withdraw_msg2: Json<WithdrawMsg2>,
) -> Result<Json<Vec<Vec<u8>>>> {
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
    static WITHDRAW_MSG_1: &str = "{\"shared_key_id\":\"ad8cb891-ce91-447d-9192-bd105f3de602\",\"state_chain_sig\":{\"purpose\":\"WITHDRAW\",\"data\":\"bcrt1qt3jh638mmuzmh92jz8c4wj392p9gj2erf2zut8\",\"sig\":\"3045022100cf280f1b03616d3ab27c485de7fa3931af4f9f0f515811eb6b145d68a47e248d022035931ad9779867fcaf04349bddff7ce30d56b8e001494c9fe3d095ef9eb1f773\"}}";
    static STATE_CHAIN_ID: &str = "2b41ff74-510d-4fe7-90a6-714a26a137da";
    static STATE_CHAIN: &str = "{\"chain\":[{\"data\":\"026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e\",\"next_state\":null}]}";
    static STATE_CHAIN_SIG: &str = "{\"purpose\":\"WITHDRAW\",\"data\":\"bcrt1qt3jh638mmuzmh92jz8c4wj392p9gj2erf2zut8\",\"sig\":\"3045022100cf280f1b03616d3ab27c485de7fa3931af4f9f0f515811eb6b145d68a47e248d022035931ad9779867fcaf04349bddff7ce30d56b8e001494c9fe3d095ef9eb1f773\"}";

    #[test]
    fn itegration_test_withdraw_init() {
        let withdraw_msg_1 = serde_json::from_str::<WithdrawMsg1>(WITHDRAW_MSG_1).unwrap();
        let shared_key_id = withdraw_msg_1.shared_key_id;
        let state_chain_id = Uuid::from_str(STATE_CHAIN_ID).unwrap();

        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_get_user_auth()
            .returning(move |_| Ok(shared_key_id));
        db.expect_get_statechain_id()
            .with(predicate::eq(shared_key_id))
            .returning(move |_| Ok(state_chain_id));
        // shared_key_id does not own a state chain (use state chain id as shared key id to test)
        db.expect_get_statechain_id()
            .with(predicate::eq(state_chain_id))
            .returning(move |_| {
                Err(SEError::DBError(
                    DBErrorType::NoDataForID,
                    state_chain_id.to_string(),
                ))
            });
        db.expect_get_statechain_owner() // sc locked
            .with(predicate::eq(state_chain_id))
            .times(1)
            .returning(move |_| {
                Ok(StateChainOwner {
                    locked_until: Utc::now().naive_utc() + Duration::seconds(5),
                    owner_id: shared_key_id,
                    chain: serde_json::from_str::<StateChain>(STATE_CHAIN).unwrap(),
                })
            });
        db.expect_get_statechain_owner()
            .with(predicate::eq(state_chain_id))
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
        msg_1_wrong_shared_key.shared_key_id = state_chain_id;
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
        let shared_key_id = withdraw_msg_1.shared_key_id;
        let withdraw_msg_2 = WithdrawMsg2 {
            shared_key_id,
            address: "bcrt1qt3jh638mmuzmh92jz8c4wj392p9gj2erf2zut8".to_string(),
        };
        let state_chain_id = Uuid::from_str(STATE_CHAIN_ID).unwrap();

        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_get_user_auth()
            .returning(move |_| Ok(shared_key_id));
        db.expect_get_withdraw_confirm_data()
            .times(1)
            .returning(move |_| {
                Ok(WithdrawConfirmData {
                    tx_withdraw: serde_json::from_str(&BACKUP_TX_NOT_SIGNED).unwrap(), // any tx is fine here
                    withdraw_sc_sig: serde_json::from_str::<StateChainSig>(
                        &STATE_CHAIN_SIG.to_string(),
                    )
                    .unwrap(),
                    state_chain_id,
                })
            });
        db.expect_get_withdraw_confirm_data().returning(move |_| {
            Ok(WithdrawConfirmData {
                tx_withdraw: serde_json::from_str(&BACKUP_TX_SIGNED).unwrap(), // any tx is fine here
                withdraw_sc_sig: serde_json::from_str::<StateChainSig>(
                    &STATE_CHAIN_SIG.to_string(),
                )
                .unwrap(),
                state_chain_id,
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
