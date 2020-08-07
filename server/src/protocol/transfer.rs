//! StateEntity Transfer
//!
//! StateEntity Transfer protocol trait and implementation.

pub use super::super::Result;
extern crate shared_lib;
use super::transfer_batch::transfer_batch_is_ended;
use shared_lib::{state_chain::*, structs::*};

use crate::error::SEError;
use crate::Database;
use crate::{server::StateChainEntity, storage::Storage};

use bitcoin::Transaction;
use cfg_if::cfg_if;
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    {BigInt, FE, GE},
};
use rocket::State;
use rocket_contrib::json::Json;
use std::str::FromStr;
use uuid::Uuid;

cfg_if! {
    if #[cfg(test)]{
        use crate::MockDatabase as DB;
        type SCE = StateChainEntity::<DB>;
    } else {
        use crate::PGDatabase as DB;
        type SCE = StateChainEntity::<DB>;
    }
}

/// Struct holds data when transfer is complete but not yet finalized
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferFinalizeData {
    pub new_shared_key_id: Uuid,
    pub state_chain_id: Uuid,
    pub state_chain_sig: StateChainSig,
    pub s2: FE,
    pub new_tx_backup: Transaction,
    pub batch_data: Option<BatchData>,
}

/// StateChain Transfer protocol trait
pub trait Transfer {
    /// API: Initiliase transfer protocol:
    ///     - Authorisation of Owner and DoS protection
    ///     - Validate transfer parameters
    ///     - Store transfer parameters
    fn transfer_sender(&self, transfer_msg1: TransferMsg1) -> Result<TransferMsg2>;

    /// API: Transfer shared wallet to new Owner:
    ///     - Check new Owner's state chain is correct
    ///     - Perform 2P-ECDSA key rotation
    ///     - Return new public shared key S2
    fn transfer_receiver(&self, transfer_msg4: TransferMsg4) -> Result<TransferMsg5>;

    /// Update DB and SMT after successful transfer.
    /// This function is called immediately in the regular transfer case or after confirmation of atomic
    /// transfers completion in the batch transfer case.
    fn transfer_finalize(&self, finalized_data: &TransferFinalizeData) -> Result<()>;
}

impl Transfer for SCE {
    fn transfer_sender(&self, transfer_msg1: TransferMsg1) -> Result<TransferMsg2> {
        let user_id = transfer_msg1.shared_key_id;
        self.check_user_auth(&user_id)?;

        info!("TRANSFER: Sender Side. Shared Key ID: {}", user_id);

        // Get state_chain id
        let state_chain_id = self.database.get_statechain_id(user_id)?;

        // Check if transfer has already been completed (but not finalized)
        if self.database.transfer_is_completed(state_chain_id) {
            return Err(SEError::Generic(String::from(
                "Transfer already completed. Waiting for finalize.",
            )));
        }

        // Check if state chain is owned by user and not locked
        let sco = self.database.get_statechain_owner(state_chain_id)?;

        is_locked(sco.locked_until)?;
        if sco.owner_id != user_id {
            return Err(SEError::Generic(format!(
                "State Chain not owned by User ID: {}.",
                user_id
            )));
        }

        // Generate x1
        let x1: FE = ECScalar::new_random();

        self.database
            .create_transfer(&state_chain_id, &transfer_msg1.state_chain_sig, &x1)?;

        info!(
            "TRANSFER: Sender side complete. Previous shared key ID: {}. State Chain ID: {}",
            user_id.to_string(),
            state_chain_id
        );
        debug!("TRANSFER: Sender side complete. State Chain ID: {}. State Chain Signature: {:?}. x1: {:?}.", state_chain_id, transfer_msg1.state_chain_sig, x1);

        // TODO encrypt x1 with Senders proof key

        Ok(TransferMsg2 { x1 })
    }

    fn transfer_receiver(&self, transfer_msg4: TransferMsg4) -> Result<TransferMsg5> {
        let user_id = transfer_msg4.shared_key_id;
        let state_chain_id = transfer_msg4.state_chain_id;

        info!("TRANSFER: Receiver side. Shared Key ID: {}", user_id);

        // Get Transfer Data for state_chain_id
        let td = self.database.get_transfer_data(state_chain_id)?;

        // Ensure state_chain_sigs are the same
        if td.state_chain_sig != transfer_msg4.state_chain_sig.to_owned() {
            return Err(SEError::Generic(format!(
                "State chain siganture provided does not match state chain at id {}",
                state_chain_id
            )));
        }

        let kp = self.database.get_ecdsa_keypair(user_id)?;

        // TODO: decrypt t2

        // let x1 = transfer_data.x1;
        let t2 = transfer_msg4.t2;
        let s1 = kp.party_1_private.get_private_key();

        // Note:
        //  s2 = o1*o2_inv*s1
        //  t2 = o1*x1*o2_inv
        let s2 = t2 * (td.x1.invert()) * s1;

        // Check s2 is valid for Lindell protocol (s2<q/3)
        let sk_bigint = s2.to_big_int();
        let q_third = FE::q();
        if sk_bigint >= q_third.div_floor(&BigInt::from(3)) {
            return Err(SEError::Generic(format!("Invalid o2, try again.")));
        }

        let g: GE = ECPoint::generator();
        let s2_pub: GE = g * s2;

        let p1_pub = kp.party_2_public * s1;
        let p2_pub = transfer_msg4.o2_pub * s2;

        // Check P1 = o1_pub*s1 === p2 = o2_pub*s2
        if p1_pub != p2_pub {
            error!("TRANSFER: Protocol failed. P1 != P2.");
            return Err(SEError::Generic(String::from(
                "Transfer protocol error: P1 != P2",
            )));
        }

        // Create user ID for new UserSession (receiver of transfer)
        let new_shared_key_id = Uuid::new_v4();

        let finalized_data = TransferFinalizeData {
            new_shared_key_id: new_shared_key_id.clone(),
            state_chain_id: state_chain_id.clone(),
            state_chain_sig: td.state_chain_sig,
            s2,
            new_tx_backup: transfer_msg4.tx_backup.clone(),
            batch_data: transfer_msg4.batch_data.clone(),
        };

        // If batch transfer then mark StateChain as complete and store finalized data in TransferBatch table.
        // This is so the transfers can be finalized when all transfers in the batch are complete.
        if transfer_msg4.batch_data.is_some() {
            let batch_id = transfer_msg4.batch_data.clone().unwrap().id;
            info!(
                "TRANSFER: Transfer as part of batch {}. State Chain ID: {}",
                batch_id, state_chain_id
            );
            // Get TransferBatch data
            let mut tbd = self.database.get_finalize_batch_data(batch_id)?;

            // Ensure batch transfer is still active
            if transfer_batch_is_ended(tbd.start_time, self.config.batch_lifetime as i64) {
                return Err(SEError::Generic(String::from(
                    "Transfer batch ended. Too late to complete transfer.",
                )));
            }

            tbd.state_chains.insert(state_chain_id.clone(), true);
            tbd.finalized_data_vec.push(finalized_data.clone());

            self.database.update_finalize_batch_data(
                &batch_id,
                tbd.state_chains,
                tbd.finalized_data_vec,
            )?;

        // If not batch then finalize transfer now
        } else {
            // Update DB and SMT with new transfer data
            self.transfer_finalize(&finalized_data)?;
        }

        info!(
            "TRANSFER: Receiver side complete. State Chain ID: {}",
            new_shared_key_id
        );
        debug!("TRANSFER: Receiver side complete. State Chain ID: {}. New Shared Key ID: {}. Finalized data: {:?}",state_chain_id,state_chain_id,finalized_data);

        Ok(TransferMsg5 {
            new_shared_key_id,
            s2_pub,
        })
    }

    /// Update DB and SMT after successful transfer.
    /// This function is called immediately in the regular transfer case or after confirmation of atomic
    /// transfers completion in the batch transfer case.
    fn transfer_finalize(&self, finalized_data: &TransferFinalizeData) -> Result<()> {
        let state_chain_id = finalized_data.state_chain_id;

        info!("TRANSFER_FINALIZE: State Chain ID: {}", state_chain_id);

        // Update state chain
        let mut state_chain: StateChain = self.database.get_statechain(state_chain_id)?;

        state_chain.add(finalized_data.state_chain_sig.to_owned())?;

        let new_user_id = finalized_data.new_shared_key_id;

        self.database.update_statechain_owner(
            &state_chain_id,
            state_chain.clone(),
            &new_user_id,
        )?;

        // Create new UserSession to allow new owner to generate shared wallet

        self.database.transfer_init_user_session(
            &new_user_id,
            &state_chain_id,
            finalized_data.to_owned(),
        )?;

        self.database
            .update_backup_tx(&state_chain_id, finalized_data.new_tx_backup.to_owned())?;

        info!(
            "TRANSFER: Finalized. New shared key ID: {}. State Chain ID: {}",
            finalized_data.new_shared_key_id, state_chain_id
        );

        // Update sparse merkle tree with new StateChain entry
        let (new_root, prev_root) = self.update_smt(
            &finalized_data
                .new_tx_backup
                .input
                .get(0)
                .unwrap()
                .previous_output
                .txid
                .to_string(),
            &state_chain
                .chain
                .last()
                .ok_or(SEError::Generic(String::from("StateChain empty")))?
                .data
                .clone(),
        )?;

        info!(
            "TRANSFER: Included in sparse merkle tree. State Chain ID: {}",
            state_chain_id
        );
        debug!(
            "TRANSFER: State Chain ID: {}. New root: {:?}. Previous root: {:?}.",
            state_chain_id, &new_root, &prev_root
        );

        // Remove TransferData for this transfer
        self.database.remove_transfer_data(&state_chain_id)?;

        Ok(())
    }
}

#[post("/transfer/sender", format = "json", data = "<transfer_msg1>")]
pub fn transfer_sender(
    sc_entity: State<SCE>,
    transfer_msg1: Json<TransferMsg1>,
) -> Result<Json<TransferMsg2>> {
    match sc_entity.transfer_sender(transfer_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/transfer/receiver", format = "json", data = "<transfer_msg4>")]
pub fn transfer_receiver(
    sc_entity: State<SCE>,
    transfer_msg4: Json<TransferMsg4>,
) -> Result<Json<TransferMsg5>> {
    match sc_entity.transfer_receiver(transfer_msg4.into_inner()) {
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
            tests::{test_sc_entity, BACKUP_TX_NO_SIG, PARTY_1_PRIVATE, PARTY_2_PUBLIC},
        },
        structs::{ECDSAKeypair, StateChainOwner, TransferData, TransferFinalizeBatchData},
    };
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use chrono::{Duration, Utc};
    use mockall::predicate;
    use std::collections::HashMap;
    use std::str::FromStr;

    // Data from a run of transfer protocol.
    static TRANSFER_MSG_2: &str =
        "{\"x1\":\"3d9558a1a21cd6d2c327372b449189b329c1e868ae46181ff181822fb3526c8e\"}";
    static TRANSFER_MSG_2_INVALID_X1: &str =
        "{\"x1\":\"2d9558a1a21cd6d2c327372b449189b329c1e868ae46181ff181822fb3526c8e\"}";
    // static TRANSFER_MSG_3: &str = "{\"shared_key_id\":\"52cf3349-06d9-498f-beff-da51b50b581a\",\"t1\":\"35fedc73ab54d45054d32676809ffb03b9e36aaaef0679aae422e6e27946c88\",\"state_chain_sig\":{\"purpose\":\"TRANSFER\",\"data\":\"021e705788579c6aafcfcc8ca91b0556a2044e6c61dfb7fca5f90c40ed119349ec\",\"sig\":\"3045022100f7b81ca9d4b5408cb73732f3728ec9bf46fe1fe2d857385d6bbf1e287d2573dc02201b78041526727385f0f6d4d9c2a63edaf5a4b455448a976d19b2380854a40858\"},\"state_chain_id\":\"384d1061-3f34-43a4-812a-735d5477f77c\",\"tx_backup_psm\":{\"shared_key_id\":\"52cf3349-06d9-498f-beff-da51b50b581a\",\"protocol\":\"Transfer\",\"tx\":{\"version\":2,\"lock_time\":0,\"input\":[{\"previous_output\":\"3973b8a0f7a9bc1bb34fcd09163ea58392d80077a12f84dc2eb0e19b626d8a52:0\",\"script_sig\":\"\",\"sequence\":4294967295,\"witness\":[[48,69,2,33,0,146,130,43,53,130,148,74,180,114,245,76,62,137,126,97,30,101,14,228,180,212,63,51,127,206,42,219,34,53,27,152,56,2,32,22,42,154,192,8,253,71,35,148,75,68,242,98,115,30,117,175,178,156,36,85,15,156,64,131,36,100,122,125,179,189,16,1],[2,20,236,39,73,3,57,140,192,61,42,116,136,167,39,19,167,106,166,28,223,119,207,72,39,228,39,39,30,127,189,204,16]]}],\"output\":[{\"value\":9000,\"script_pubkey\":\"0014489f47c27f75c4b4a6c2149cfd851a1fd9892a7b\"}]},\"input_addrs\":[\"0214ec274903398cc03d2a7488a72713a76aa61cdf77cf4827e427271e7fbdcc10\"],\"input_amounts\":[10000],\"proof_key\":\"021e705788579c6aafcfcc8ca91b0556a2044e6c61dfb7fca5f90c40ed119349ec\"},\"rec_addr\":{\"tx_backup_addr\":\"bcrt1qfz050snlwhztffkzzjw0mpg6rlvcj2nmpaa28e\",\"proof_key\":\"021e705788579c6aafcfcc8ca91b0556a2044e6c61dfb7fca5f90c40ed119349ec\"}}";
    static TRANSFER_MSG_4: &str = "{\"shared_key_id\":\"52cf3349-06d9-498f-beff-da51b50b581a\",\"state_chain_id\":\"384d1061-3f34-43a4-812a-735d5477f77c\",\"t2\":\"3470325e44f669a8889e1f55a4f70606e58a6cc6fbea39a7c3133b88bc58e41b\",\"state_chain_sig\":{\"purpose\":\"TRANSFER\",\"data\":\"021e705788579c6aafcfcc8ca91b0556a2044e6c61dfb7fca5f90c40ed119349ec\",\"sig\":\"3045022100f7b81ca9d4b5408cb73732f3728ec9bf46fe1fe2d857385d6bbf1e287d2573dc02201b78041526727385f0f6d4d9c2a63edaf5a4b455448a976d19b2380854a40858\"},\"o2_pub\":{\"x\":\"bfe15b926e47845f535990e8971e698a460673dff4582465f237c571fea2db43\",\"y\":\"8c0202ee1655cbe4d3a4b181ce7a9bf9e1f85e533d845b1ee1820d9d97123b36\"},\"tx_backup\":{\"version\":2,\"lock_time\":0,\"input\":[{\"previous_output\":\"3973b8a0f7a9bc1bb34fcd09163ea58392d80077a12f84dc2eb0e19b626d8a52:0\",\"script_sig\":\"\",\"sequence\":4294967295,\"witness\":[[48,69,2,33,0,146,130,43,53,130,148,74,180,114,245,76,62,137,126,97,30,101,14,228,180,212,63,51,127,206,42,219,34,53,27,152,56,2,32,22,42,154,192,8,253,71,35,148,75,68,242,98,115,30,117,175,178,156,36,85,15,156,64,131,36,100,122,125,179,189,16,1],[2,20,236,39,73,3,57,140,192,61,42,116,136,167,39,19,167,106,166,28,223,119,207,72,39,228,39,39,30,127,189,204,16]]}],\"output\":[{\"value\":9000,\"script_pubkey\":\"0014489f47c27f75c4b4a6c2149cfd851a1fd9892a7b\"}]},\"batch_data\":null}";
    static STATE_CHAIN: &str = "{\"chain\":[{\"data\":\"026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e\",\"next_state\":null}]}";
    static FINALIZED_DATA: &str = "{\"new_shared_key_id\":\"c0c90555-badf-4317-a508-b3747777e652\",\"state_chain_id\":\"384d1061-3f34-43a4-812a-735d5477f77c\",\"state_chain_sig\":{\"purpose\":\"TRANSFER\",\"data\":\"021e705788579c6aafcfcc8ca91b0556a2044e6c61dfb7fca5f90c40ed119349ec\",\"sig\":\"3045022100f7b81ca9d4b5408cb73732f3728ec9bf46fe1fe2d857385d6bbf1e287d2573dc02201b78041526727385f0f6d4d9c2a63edaf5a4b455448a976d19b2380854a40858\"},\"s2\":\"14cd6a42ddc2f0e1bb1752d20e9d258d539d0e4e7ec33baf1b8196cad0206859\",\"new_tx_backup\":{\"version\":2,\"lock_time\":0,\"input\":[{\"previous_output\":\"3973b8a0f7a9bc1bb34fcd09163ea58392d80077a12f84dc2eb0e19b626d8a52:0\",\"script_sig\":\"\",\"sequence\":4294967295,\"witness\":[[48,69,2,33,0,146,130,43,53,130,148,74,180,114,245,76,62,137,126,97,30,101,14,228,180,212,63,51,127,206,42,219,34,53,27,152,56,2,32,22,42,154,192,8,253,71,35,148,75,68,242,98,115,30,117,175,178,156,36,85,15,156,64,131,36,100,122,125,179,189,16,1],[2,20,236,39,73,3,57,140,192,61,42,116,136,167,39,19,167,106,166,28,223,119,207,72,39,228,39,39,30,127,189,204,16]]}],\"output\":[{\"value\":9000,\"script_pubkey\":\"0014489f47c27f75c4b4a6c2149cfd851a1fd9892a7b\"}]},\"batch_data\":null}";

    #[test]
    fn itegration_test_transfer_sender() {
        let user_id = Uuid::from_str("203001c9-93f0-46f9-aaaa-0678c891b2d3").unwrap();
        let no_sc_user_id = Uuid::from_str("11111111-1111-46f9-aaaa-0678c891b2d3").unwrap();
        let state_chain_id = Uuid::from_str("001203c9-93f0-46f9-abda-0678c891b2d3").unwrap();
        let sender_proof_key_priv = SecretKey::from_slice(&[1; 32]).unwrap(); // Proof key priv part
        let sender_proof_key =
            PublicKey::from_secret_key(&Secp256k1::new(), &sender_proof_key_priv);
        let state_chain_sig: StateChainSig =
            serde_json::from_str::<TransferMsg4>(&TRANSFER_MSG_4.to_string())
                .unwrap()
                .state_chain_sig;

        let mut db = MockDatabase::new();
        db.expect_get_user_auth().returning(move |_| Ok(user_id));
        db.expect_get_statechain_id()
            .with(predicate::eq(user_id))
            .returning(move |_| Ok(state_chain_id));
        // userid does not own a state
        db.expect_get_statechain_id()
            .with(predicate::eq(no_sc_user_id))
            .returning(move |_| {
                Err(SEError::DBError(
                    DBErrorType::NoDataForID,
                    no_sc_user_id.to_string(),
                ))
            });
        db.expect_transfer_is_completed()
            .with(predicate::eq(state_chain_id))
            .returning(|_| false);
        db.expect_get_statechain_owner()
            .with(predicate::eq(state_chain_id))
            .returning(move |_| {
                Ok(StateChainOwner {
                    locked_until: Utc::now().naive_utc(),
                    owner_id: user_id,
                    chain: StateChain::new(sender_proof_key.to_string()),
                })
            });
        db.expect_create_transfer().returning(|_, _, _| Ok(()));

        let sc_entity = test_sc_entity(db);

        // user does not own State Chain
        match sc_entity.transfer_sender(TransferMsg1 {
            shared_key_id: no_sc_user_id,
            state_chain_sig: state_chain_sig.clone(),
        }) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("DB Error: No data for identifier.")),
        }

        assert!(sc_entity
            .transfer_sender(TransferMsg1 {
                shared_key_id: user_id,
                state_chain_sig
            })
            .is_ok());
    }

    #[test]
    fn itegration_test_transfer_receiver() {
        let transfer_msg_4 =
            serde_json::from_str::<TransferMsg4>(&TRANSFER_MSG_4.to_string()).unwrap();
        let shared_key_id = transfer_msg_4.shared_key_id;
        let state_chain_id = transfer_msg_4.state_chain_id;
        let s2 = serde_json::from_str::<TransferFinalizeData>(&FINALIZED_DATA.to_string())
            .unwrap()
            .s2;
        let x1 = serde_json::from_str::<TransferMsg2>(&TRANSFER_MSG_2.to_string())
            .unwrap()
            .x1;

        let mut db = MockDatabase::new();
        db.expect_get_user_auth()
            .returning(move |_| Ok(shared_key_id));
        db.expect_get_transfer_data()
            .with(predicate::eq(state_chain_id))
            .returning(move |_| {
                Ok(TransferData {
                    state_chain_id,
                    state_chain_sig: serde_json::from_str::<TransferMsg4>(
                        &TRANSFER_MSG_4.to_string(),
                    )
                    .unwrap()
                    .state_chain_sig,
                    x1,
                })
            });
        db.expect_get_ecdsa_keypair()
            .with(predicate::eq(shared_key_id))
            .returning(|_| {
                Ok(ECDSAKeypair {
                    party_1_private: serde_json::from_str(&PARTY_1_PRIVATE.to_string()).unwrap(),
                    party_2_public: serde_json::from_str(&PARTY_2_PUBLIC.to_string()).unwrap(),
                })
            });
        db.expect_get_statechain().returning(move |_| {
            Ok(serde_json::from_str::<StateChain>(&STATE_CHAIN.to_string()).unwrap())
        });
        db.expect_update_statechain_owner()
            .returning(|_, _, _| Ok(()));
        db.expect_transfer_init_user_session()
            .returning(|_, _, _| Ok(()));
        db.expect_update_backup_tx().returning(|_, _| Ok(()));
        db.expect_remove_transfer_data().returning(|_| Ok(()));
        db.expect_get_finalize_batch_data() // batch time up
            .times(1)
            .returning(move |_| {
                Ok(TransferFinalizeBatchData {
                    state_chains: HashMap::new(),
                    finalized_data_vec: vec![TransferFinalizeData {
                        new_shared_key_id: shared_key_id,
                        state_chain_id,
                        state_chain_sig: serde_json::from_str::<TransferMsg4>(
                            &TRANSFER_MSG_4.to_string(),
                        )
                        .unwrap()
                        .state_chain_sig,
                        s2: s2,
                        new_tx_backup: serde_json::from_str::<Transaction>(
                            &BACKUP_TX_NO_SIG.to_string(),
                        )
                        .unwrap(),
                        batch_data: Some(BatchData {
                            id: shared_key_id,
                            commitment: String::default(),
                        }),
                    }],
                    start_time: Utc::now().naive_utc() - Duration::seconds(999999),
                })
            });
        db.expect_get_finalize_batch_data().returning(move |_| {
            Ok(TransferFinalizeBatchData {
                state_chains: HashMap::new(),
                finalized_data_vec: vec![TransferFinalizeData {
                    new_shared_key_id: shared_key_id,
                    state_chain_id,
                    state_chain_sig: serde_json::from_str::<TransferMsg4>(
                        &TRANSFER_MSG_4.to_string(),
                    )
                    .unwrap()
                    .state_chain_sig,
                    s2: s2,
                    new_tx_backup: serde_json::from_str::<Transaction>(
                        &BACKUP_TX_NO_SIG.to_string(),
                    )
                    .unwrap(),
                    batch_data: Some(BatchData {
                        id: shared_key_id,
                        commitment: String::default(),
                    }),
                }],
                start_time: Utc::now().naive_utc(),
            })
        });
        db.expect_update_finalize_batch_data()
            .returning(|_, _, _| Ok(()));

        let sc_entity = test_sc_entity(db);
        //Mainstay post commitment mock
        let _m = mocks::ms::post_commitment().create();
        // Input data to transfer_receiver
        let mut transfer_msg_4 =
            serde_json::from_str::<TransferMsg4>(&TRANSFER_MSG_4.to_string()).unwrap();

        // Incorrect x1, t1 or t2 => t2 is incorrect
        let mut msg_4_incorrect_t2 = transfer_msg_4.clone();
        msg_4_incorrect_t2.t2 =
            serde_json::from_str::<TransferMsg2>(&TRANSFER_MSG_2_INVALID_X1.to_string())
                .unwrap()
                .x1;
        match sc_entity.transfer_receiver(msg_4_incorrect_t2) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("Transfer protocol error: P1 != P2")),
        }

        // StateChain incorreclty signed for
        let mut msg_4_incorrect_sc = transfer_msg_4.clone();
        msg_4_incorrect_sc.state_chain_sig.data =
            "deadb33f88579c6aafcfcc8ca91b0556a2044e6c61dfb7fca5f90c40ed119349ec".to_string();
        match sc_entity.transfer_receiver(msg_4_incorrect_sc) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e
                .to_string()
                .contains("Error: State chain siganture provided does not match state chain at")),
        }
        // Expected successful run
        assert!(sc_entity.transfer_receiver(transfer_msg_4.clone()).is_ok());

        // Test transfer involved in batch
        transfer_msg_4.batch_data = Some(BatchData {
            id: shared_key_id,
            commitment: String::default(),
        });

        // Batch lifetime passed
        match sc_entity.transfer_receiver(transfer_msg_4.clone()) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e
                .to_string()
                .contains("Error: Transfer batch ended. Too late to complete transfer.")),
        }
        // Expected successful batch transfer run
        assert!(sc_entity.transfer_receiver(transfer_msg_4).is_ok());
    }
}
