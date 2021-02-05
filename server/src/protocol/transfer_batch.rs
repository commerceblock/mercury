//! StateEntity Batch Transfer
//!
//! StateEntity Batch Transfer protocol trait and implementation. API is used by Conductor and
//! swap partipants to organise swaps.

pub use super::super::Result;
use super::transfer::Transfer;

extern crate shared_lib;
use crate::error::SEError;
use crate::{server::StateChainEntity, Database};
use shared_lib::{commitment::verify_commitment, state_chain::*, structs::*};

use rocket_okapi::openapi;
use cfg_if::cfg_if;
use chrono::{NaiveDateTime, Utc};
use rocket::State;
use rocket_contrib::json::Json;
use std::str::FromStr;
use uuid::Uuid;

//Generics cannot be used in Rocket State, therefore we define the concrete
//type of StateChainEntity here
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

/// StateChain BatchTransfer protocol trait
pub trait BatchTransfer {
    /// API: Request setup of a batch transfer.
    ///     - Verify all signatures
    ///     - Create TransferBatchData DB object
    fn transfer_batch_init(&self, transfer_batch_init_msg: TransferBatchInitMsg) -> Result<()>;

    /// Finalize all transfers in a batch if all are complete and validated.
    fn finalize_batch(&self, batch_id: Uuid) -> Result<()>;

    /// API: Reveal a nonce for a corresponding Transfer commitment.
    fn transfer_reveal_nonce(&self, transfer_reveal_nonce: TransferRevealNonce) -> Result<()>;
}

impl BatchTransfer for SCE {
    fn transfer_batch_init(&self, transfer_batch_init_msg: TransferBatchInitMsg) -> Result<()> {
        let batch_id = transfer_batch_init_msg.id.clone();
        info!("TRANSFER_BATCH_INIT: ID: {}", batch_id);

        if self.database.has_transfer_batch_id(batch_id) {
            return Err(SEError::Generic(format!(
                "Batch transfer with ID {} already exists.",
                batch_id.to_string()
            )));
        }

        // Ensure sigs purpose is for batch transfer
        for sig in &transfer_batch_init_msg.signatures {
            if !sig.purpose.contains("TRANSFER_BATCH") {
                return Err(SEError::Generic(String::from(
                    "Signture's purpose is not valid for batch transfer.",
                )));
            }
        }

        let mut state_chains = vec![];
        for sig in transfer_batch_init_msg.signatures.clone() {
            // Ensure sig is for same batch as others
            if &sig.clone().purpose[15..] != batch_id.to_string() {
                return Err(SEError::Generic(String::from(
                    "Batch id is not identical for all signtures.",
                )));
            }

            let statechain_id = Uuid::from_str(&sig.data).unwrap();
            let sco = self.database.get_statechain_owner(statechain_id)?;

            // Verify sigs
            let proof_key = sco.chain.get_tip()?.data;
            sig.verify(&proof_key)?;

            // Ensure state chains are all available
            is_locked(sco.locked_until)?;

            // Add to TransferBatchData object
            state_chains.push(statechain_id);
        }

        // Create new TransferBatchData and add to DB
        self.database
            .create_transfer_batch_data(&batch_id, state_chains)?;

        info!("TRANSFER_BATCH_INIT: Batch ID {} initiated.", batch_id);
        debug!(
            "TRANSFER_BATCH_INIT: Batch ID {}. Signatures: {:?}.",
            batch_id, transfer_batch_init_msg.signatures
        );

        Ok(())
    }

    fn finalize_batch(&self, batch_id: Uuid) -> Result<()> {
        info!("TRANSFER_FINALIZE_BATCH: ID: {}", batch_id);

        let fbd = self.database.get_finalize_batch_data(batch_id)?;


        for finalized_data in fbd.finalized_data_vec.clone() {
            self.transfer_finalize(&finalized_data)?;
        }

        self.database
            .update_transfer_batch_finalized(&batch_id, &true)?;

        Ok(())
    }

    fn transfer_reveal_nonce(&self, transfer_reveal_nonce: TransferRevealNonce) -> Result<()> {
        let batch_id = transfer_reveal_nonce.batch_id;
        let statechain_id = transfer_reveal_nonce.statechain_id;
        info!(
            "TRANSFER_REVEAL_NONCE: Batch ID: {}. State Chain ID: {}",
            batch_id, statechain_id
        );

        let tbd = self.database.get_transfer_batch_data(batch_id)?;

        if tbd.state_chains.get(&statechain_id).is_none() {
            return Err(SEError::Generic(String::from(
                "State chain ID not in this batch.",
            )));
        }

        if tbd.finalized {
            return Err(SEError::Generic(String::from(
                "Transfer Batch completed successfully.",
            )));
        }

        if !transfer_batch_is_ended(tbd.start_time, self.config.batch_lifetime as i64) {
            return Err(SEError::Generic(String::from("Transfer Batch still live.")));
        }

        verify_commitment(
            &transfer_reveal_nonce.hash,
            &statechain_id.to_string(),
            &transfer_reveal_nonce.nonce,
        )?;

        // If state chain completed + commitment revealed then punishment can be removed from state chain
        match self.database.get_sc_finalize_batch_data(&statechain_id){
            Ok(v) => {
                //Check the data relatesd to this batch transfer
                match v.batch_data {
                    Some(bd) => {
                        if bd.id == batch_id{
                            self.database
                                .update_locked_until(&statechain_id, &get_time_now())?;
                            info!(
                                "TRANSFER_REVEAL_NONCE: State Chain unlocked. ID: {}",
                                statechain_id
                            );

                            // remove from transfer batch punished list
                            let mut new_punished = tbd.punished_state_chains.clone();
                            new_punished.retain(|x| x != &statechain_id);
                            self.database.update_punished(&batch_id, new_punished)?;
                        }
                    },
                    None => (),
                }
            },
            Err(_) => (),
        }

        Ok(())
    }
}

/// Check if Transfer Batch is out of time
pub fn transfer_batch_is_ended(start_time: NaiveDateTime, batch_lifetime: i64) -> bool {
    let current_time = Utc::now().naive_utc().timestamp();
    if current_time - start_time.timestamp() > batch_lifetime {
        return true;
    }
    false
}

#[openapi]
/// # Initiate the batch transfer protocol: provide statechain signatures
#[post(
    "/transfer/batch/init",
    format = "json",
    data = "<transfer_batch_init_msg>"
)]
pub fn transfer_batch_init(
    sc_entity: State<SCE>,
    transfer_batch_init_msg: Json<TransferBatchInitMsg>,
) -> Result<Json<()>> {
    match sc_entity.transfer_batch_init(transfer_batch_init_msg.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Complete Batch transfer: reveal transfer nonce
#[post(
    "/transfer/batch/reveal",
    format = "json",
    data = "<transfer_reveal_nonce>"
)]
pub fn transfer_reveal_nonce(
    sc_entity: State<SCE>,
    transfer_reveal_nonce: Json<TransferRevealNonce>,
) -> Result<Json<()>> {
    match sc_entity.transfer_reveal_nonce(transfer_reveal_nonce.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockDatabase;
    use crate::{
        protocol::{transfer::TransferFinalizeData, util::tests::test_sc_entity},
        structs::{StateChainOwner, TransferBatchData, TransferFinalizeBatchData},
    };
    use chrono::{Duration, Utc};
    use mockall::predicate;
    use shared_lib::commitment::make_commitment;
    use std::str::FromStr;
    use uuid::Uuid;
    use shared_lib::state_chain::State as SCState;
    use std::collections::{HashMap, HashSet};
    use crate::error::DBErrorType;

    // Useful data structs for transfer batch protocol.
    /// Batch id and Signatures for statechains to take part in batch-transfer
    static TRANSFER_BATCH_INIT: &str = "{\"id\":\"1304280d-60f3-443e-892e-9fd41ecb1b4f\",\"signatures\":[{\"purpose\":\"TRANSFER_BATCH:1304280d-60f3-443e-892e-9fd41ecb1b4f\",\"data\":\"06b7d64d-e88e-4de1-b596-0ee11c84f244\",\"sig\":\"3045022100fced97e99ad2700ee4ece2c398cd4092d73c09d2241ab438d63a9ab9d97abcdc02205c93d76d4692a4b396e1affe31adbc2a23af9859c7180644c1fb9a74fe3b5a01\"},
    {\"purpose\":\"TRANSFER_BATCH:1304280d-60f3-443e-892e-9fd41ecb1b4f\",\"data\":\"92753256-2efa-43c1-8486-8c0f107bbeb9\",\"sig\":\"3045022100e21391ea17151d30357287607b08e0b18631bd177f1c0fc1b8b6eaef1320e2e6022018df26119cb8ee914a39f7c181ccc40842cdcf6f4a4514087031adf4386e41e9\"},
    {\"purpose\":\"TRANSFER_BATCH:1304280d-60f3-443e-892e-9fd41ecb1b4f\",\"data\":\"217a001c-e2e3-441b-9a4e-59980591ddf0\",\"sig\":\"3045022100d72a6b8e0833a37c2b7ea3ce3a23fef529aaeb473be70373c900ab1d6ec394f9022009fbcfdb37b675f4013c65cb3a51e248cc70d0e37965abec5111f0ae8109652e\"}]}";
    /// Mapping of statechain_ids -> proof keys for above list of sigatures
    static SIG_PROOF_KEYS: &str = "{\"06b7d64d-e88e-4de1-b596-0ee11c84f244\":\"026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e\",\"92753256-2efa-43c1-8486-8c0f107bbeb9\":\"022d7ea3d286541ed593e0158e315d73908646abcfa46aa56c12229a2910cce48c\",\"217a001c-e2e3-441b-9a4e-59980591ddf0\":\"039afb8b85ba5c1b6664df7e68d4d79ea194e7022c76f0f9f3dadc3f94d8c79211\"}";
    /// Signs for incorrect batch id
    static STATE_CHAIN_SIG_ONE_WRONG_BATCH_ID: &str = "{\"purpose\":\"TRANSFER_BATCH:5d15c863-2ee3-46e2-935b-3f8702155fb6\",\"data\":\"ff33831e-f458-4a14-997c-abc460d1fe87\",\"sig\":\"30440220601a56ede4f2980e4b66d3b07a58b44dd5831b0ae300aa38de521147d74b49cc0220284923cd22b10c8edbf81535b53ab974757e875a39bc59bad84b3a01cf022e52\"}";
    /// Signs for "TRANSFER" instead of "TRANSFER-BATCH"
    static STATE_CHAIN_SIG_ONE_SIGN_REG_TRANSFER: &str = "{\"purpose\":\"TRANSFER\",\"data\":\"proof key dummy\",\"sig\":\"3045022100f31f1189d871c098bf954c1783ca1f89b4c6314c1cd59cf4ca3080a4e6f15104022040687c3d9335438ec9fec5fc125b5514fe323c98d1d70509de6e2f7c829d2948\"}";

    static TRANSFER_FINALIZE_DATA: &str = "{\"new_shared_key_id\":\"45ee47fb-9361-42f3-a0a9-7d48c9b55afb\",\"statechain_id\":\"5c960c7a-de59-40ac-a207-021afa57ca32\",\"statechain_sig\":{\"purpose\":\"TRANSFER\",\"data\":\"03b1237dfd274027c29699bab2af88974ee266670861c4bb882f1f2a132f725be1\",\"sig\":\"3045022100c442cba10460732f473bf6d665b9f6b10a032395ecd2f75ab582137952d8e49c02206007005217bf21c321723a736fb854f09d51e1efeacb11dee663b766e1a5c305\"},\"s2\":\"1608b4f8fa8555bce037817c3608b107e4448c38e933007daf607596be9ad27\",\"new_tx_backup_hex\":\"0200000000010161cd0e9151b4ecbf1fc2b69a3aecce6ea3a677584c3114c34621573d8d529e4f0000000000ffffffff01384a00000000000016001427baa80ce9ce30ef1ef5f20a76ffc3a1a85be3d102483045022100fb7f1b15d6962a7e462541284be2cd81ea0f44c7bb9e23da1efe217b440ce17902205a569f29d1590b96ec5852784226f7ba6375b907adcf853bd052ccfab112df9d0121034f14136fdbe82daa4f7e6c27f2e2ad30a74616f141680ecde534b77010e4917500000000\",\"batch_data\":{\"id\":\"b0bcdab8-917c-46af-aaa2-d9060ff98575\",\"commitment\":\"8228048f45f148675a2f1e5d2e65b9a15c50a7b3f905e9b19f10c6ee67218861\"}}";

    #[test]
    fn test_transfer_batch_init() {
        let transfer_batch_init_msg =
            serde_json::from_str::<TransferBatchInitMsg>(TRANSFER_BATCH_INIT).unwrap();
        let batch_id = transfer_batch_init_msg.id;
        let already_active_batch_id =
            Uuid::from_str(&"deadb33f-1725-445e-9e08-0d15865cc844").unwrap();

        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_has_transfer_batch_id()
            .with(predicate::eq(already_active_batch_id))
            .returning(|_| true);
        db.expect_has_transfer_batch_id()
            .with(predicate::eq(batch_id))
            .returning(|_| false);
        db.expect_create_transfer_batch_data()
            .returning(|_, _| Ok(()));

        for (id, proof_key) in serde_json::from_str::<HashMap<&str, &str>>(SIG_PROOF_KEYS)
            .unwrap()
            .into_iter()
        {
            db.expect_get_statechain_owner()
                .with(predicate::eq(Uuid::from_str(id).unwrap()))
                .returning(move |_| {
                    Ok(StateChainOwner {
                        locked_until: Utc::now().naive_utc(), // do not test for locked statechains here since
                        owner_id: already_active_batch_id, // it has been done in deposit, transfer and withdraw tests.
                        chain: StateChain::new(proof_key.to_string()),
                    })
                });
        }
        db.expect_create_transfer_batch_data()
            .returning(|_, _| Ok(()));

        let sc_entity = test_sc_entity(db);

        // Try batch id already exists
        let mut init_msg_batch_id_already_exists = transfer_batch_init_msg.clone();
        init_msg_batch_id_already_exists.id = already_active_batch_id;
        match sc_entity.transfer_batch_init(init_msg_batch_id_already_exists) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("already exists.")),
        }

        // one sig signs for incorrect batch_id
        let mut init_msg_sigs_one_wrong_batch_id = transfer_batch_init_msg.clone();
        *init_msg_sigs_one_wrong_batch_id
            .signatures
            .get_mut(2)
            .unwrap() =
            serde_json::from_str::<StateChainSig>(&STATE_CHAIN_SIG_ONE_WRONG_BATCH_ID.to_string())
                .unwrap();
        match sc_entity.transfer_batch_init(init_msg_sigs_one_wrong_batch_id) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e
                .to_string()
                .contains("Batch id is not identical for all signtures.")),
        }

        // one sig signs for "TRANSFER" instead of "TRANSFER-BATCH"
        let mut init_msg_sigs_one_sign_for_regular_transfer = transfer_batch_init_msg.clone();
        *init_msg_sigs_one_sign_for_regular_transfer
            .signatures
            .get_mut(0)
            .unwrap() = serde_json::from_str::<StateChainSig>(
            &STATE_CHAIN_SIG_ONE_SIGN_REG_TRANSFER.to_string(),
        )
        .unwrap();
        match sc_entity.transfer_batch_init(init_msg_sigs_one_sign_for_regular_transfer) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e
                .to_string()
                .contains(" purpose is not valid for batch transfer.")),
        }

        // Expect successful run
        assert!(sc_entity
            .transfer_batch_init(transfer_batch_init_msg)
            .is_ok());
    }

    #[test]
    #[ignore]
    fn test_finalize_batch() {
        let batch_id = serde_json::from_str::<TransferBatchInitMsg>(TRANSFER_BATCH_INIT)
            .unwrap()
            .id;

        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));

        let tfd : TransferFinalizeData = serde_json::from_str(TRANSFER_FINALIZE_DATA).unwrap();

        let finalized_data_vec  = vec![tfd];
        let mut statechain_ids = vec![];
        for item in finalized_data_vec.clone() {
            statechain_ids.push(item.statechain_id.clone());
        }

        // simply test for state_chains.len() != finalized_data.len()
        db.expect_get_finalize_batch_data().times(1).returning(move |_| {
            Ok(TransferFinalizeBatchData {
                finalized_data_vec: finalized_data_vec.clone(),
                start_time: Utc::now().naive_utc(),
            })
        });

        for (id, proof_key) in serde_json::from_str::<HashMap<&str, &str>>(SIG_PROOF_KEYS)
        .unwrap()
        .into_iter(){
            let mut chain = Vec::<SCState>::new();
            println!("id, proof key: {}, {}", id.to_string(), proof_key.to_string());
            chain.push(SCState {
                data: proof_key.to_string(),
                next_state: None,
            });

            let statechain = StateChain {
                chain: chain.clone(),
            };

            db.expect_get_statechain()
                .returning(move |_| (Ok(statechain.clone())));
        }

        db.expect_update_statechain_owner()
        .returning(|_, _, _| Ok(()));

        let sc_entity = test_sc_entity(db);

        match sc_entity.finalize_batch(batch_id) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e
                .to_string()
                .contains("Error: secp: signature failed verification"), e.to_string()),
        }
    }

    #[test]
    fn test_transfer_reveal_nonce() {
        let transfer_finalize_data: TransferFinalizeData =
            serde_json::from_str(TRANSFER_FINALIZE_DATA).unwrap();
        let batch_id = transfer_finalize_data.batch_data.unwrap().id;
        let statechain_id = transfer_finalize_data.statechain_id;

        let mut transfer_batch_data = TransferBatchData {
            state_chains: HashSet::new(),
            punished_state_chains: vec![],
            start_time: Utc::now().naive_utc(),
            finalized: false,
        };

        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        // state chain id not involved in batch
        db.expect_get_transfer_batch_data().times(1).returning(|_| {
            Ok(TransferBatchData {
                state_chains: HashSet::new(),
                punished_state_chains: vec![],
                start_time: Utc::now().naive_utc(),
                finalized: false,
            })
        });
        let mut state_chains = HashSet::new();
        state_chains.insert(statechain_id);
        transfer_batch_data.state_chains = state_chains;
        // Batch completed successfully - no need to reveal nonce.
        transfer_batch_data.finalized = true;
        db.expect_get_transfer_batch_data()
            .times(1)
            .returning(move |_| {
                Ok(TransferBatchData {
                    state_chains: {
                        let mut state_chains = HashSet::new();
                        state_chains.insert(statechain_id);
                        state_chains
                    },
                    punished_state_chains: vec![],
                    start_time: Utc::now().naive_utc(),
                    finalized: true,
                })
            });
        transfer_batch_data.finalized = false;
        db.expect_get_transfer_batch_data()
            .times(1)
            .returning(move |_| {
                Ok(TransferBatchData {
                    state_chains: {
                        let mut state_chains = HashSet::new();
                        state_chains.insert(statechain_id);
                        state_chains
                    },
                    punished_state_chains: vec![],
                    start_time: Utc::now().naive_utc(),
                    finalized: false,
                })
            });
        db.expect_get_transfer_batch_data().returning(move |_| {
            Ok(TransferBatchData {
                state_chains: {
                    let mut state_chains = HashSet::new();
                    state_chains.insert(statechain_id);
                    state_chains
                },
                punished_state_chains: vec![],
                start_time: Utc::now().naive_utc() - Duration::seconds(9999), // ensure batch lifetime has passed,
                finalized: false,
            })
        });

        db.expect_update_locked_until().returning(|_, _| Ok(()));
        db.expect_update_punished().returning(|_, _| Ok(()));
        db.expect_get_sc_finalize_batch_data().returning(|_|
            Err(SEError::DBError(
                DBErrorType::NoDataForID, "no data".to_string())));

        let sc_entity = test_sc_entity(db);

        let (commitment, nonce) = make_commitment(&statechain_id.to_string());
        let transfer_reveal_nonce = TransferRevealNonce {
            batch_id,
            hash: commitment,
            statechain_id,
            nonce,
        };

        // State Chain is not involved in this batch-transfer
        match sc_entity.transfer_reveal_nonce(transfer_reveal_nonce.clone()) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("State chain ID not in this batch.")),
        }

        // Transfer batch completed successfully - no need to reveal nonce.
        match sc_entity.transfer_reveal_nonce(transfer_reveal_nonce.clone()) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e
                .to_string()
                .contains("Transfer Batch completed successfully.")),
        }

        // Transfer batch is still live - no need to reveal nonce yet.
        match sc_entity.transfer_reveal_nonce(transfer_reveal_nonce.clone()) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("Transfer Batch still live.")),
        }

        // Invalid nonce for commitment
        let mut transfer_reveal_nonce_incorrect_nonce = transfer_reveal_nonce.clone();
        transfer_reveal_nonce_incorrect_nonce.nonce = [0; 32];
        match sc_entity.transfer_reveal_nonce(transfer_reveal_nonce_incorrect_nonce) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e
                .to_string()
                .contains("Error: Commitment verification failed.")),
        }

        // Expect successful run
        assert!(sc_entity
            .transfer_reveal_nonce(transfer_reveal_nonce)
            .is_ok());
    }

    #[test]
    fn test_transfer_batch_is_ended() {
        assert_eq!(
            transfer_batch_is_ended(Utc::now().naive_utc() - Duration::seconds(2), 1),
            true
        );
        assert_eq!(
            transfer_batch_is_ended(Utc::now().naive_utc() - Duration::seconds(1), 2),
            false
        );
        assert_eq!(
            transfer_batch_is_ended(Utc::now().naive_utc() - Duration::seconds(1), 1),
            false
        );
    }
}
