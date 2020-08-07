//! StateEntity Transfer
//!
//! StateEntity Transfer protocol trait and implementation.

pub use super::super::Result;
extern crate shared_lib;
use shared_lib::{state_chain::*, structs::*};
use super::transfer_batch::transfer_batch_is_ended;

use crate::error::SEError;
use crate::Database;
use crate::{server::StateChainEntity, storage::Storage};

use bitcoin::Transaction;
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    {BigInt, FE, GE},
};
use rocket::State;
use rocket_contrib::json::Json;
use uuid::Uuid;
use cfg_if::cfg_if;
use std::str::FromStr;

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
    fn transfer_sender(
        &self,
        transfer_msg1: TransferMsg1,
    ) -> Result<TransferMsg2>;

    /// API: Transfer shared wallet to new Owner:
    ///     - Check new Owner's state chain is correct
    ///     - Perform 2P-ECDSA key rotation
    ///     - Return new public shared key S2
    fn transfer_receiver(
        &self,
        transfer_msg4: TransferMsg4,
    ) -> Result<TransferMsg5>;

    /// Update DB and SMT after successful transfer.
    /// This function is called immediately in the regular transfer case or after confirmation of atomic
    /// transfers completion in the batch transfer case.
    fn transfer_finalize(
        &self,
        finalized_data: &TransferFinalizeData,
    ) -> Result<()>;
}

impl Transfer for SCE {
    fn transfer_sender(
        &self,
        transfer_msg1: TransferMsg1,
    ) -> Result<TransferMsg2> {
        let user_id = transfer_msg1.shared_key_id;
        self.check_user_auth(&user_id)?;

        info!("TRANSFER: Sender Side. Shared Key ID: {}", user_id);

        // Get state_chain id
        let state_chain_id = self.database.get_statechain_id(user_id)?;

        // Check if transfer has already been completed (but not finalized)
        if self.database.transfer_is_completed(state_chain_id){
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

        self.database.create_transfer(&state_chain_id, &transfer_msg1.state_chain_sig, &x1)?;

        info!(
            "TRANSFER: Sender side complete. Previous shared key ID: {}. State Chain ID: {}",
            user_id.to_string(),
            state_chain_id
        );
        debug!("TRANSFER: Sender side complete. State Chain ID: {}. State Chain Signature: {:?}. x1: {:?}.", state_chain_id, transfer_msg1.state_chain_sig, x1);

        // TODO encrypt x1 with Senders proof key

        Ok(TransferMsg2 { x1 })
    }

    fn transfer_receiver(
        &self,
        transfer_msg4: TransferMsg4,
    ) -> Result<TransferMsg5> {
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

            self.database.update_finalize_batch_data(&batch_id, tbd.state_chains,
                                                        tbd.finalized_data_vec)?;

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
    fn transfer_finalize(
        &self,
        finalized_data: &TransferFinalizeData,
    ) -> Result<()> {
        let state_chain_id = finalized_data.state_chain_id;

        info!("TRANSFER_FINALIZE: State Chain ID: {}", state_chain_id);

        // Update state chain
        let mut state_chain: StateChain = self.database.get_statechain(state_chain_id)?;

        state_chain.add(finalized_data.state_chain_sig.to_owned())?;


        let new_user_id = finalized_data.new_shared_key_id;

        self.database.update_statechain_owner(&state_chain_id,
            state_chain.clone(), &new_user_id)?;

        // Create new UserSession to allow new owner to generate shared wallet

        self.database.transfer_init_user_session(&new_user_id, &state_chain_id,
            finalized_data.to_owned())?;


        self.database.update_backup_tx(&state_chain_id, finalized_data.new_tx_backup.to_owned())?;


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
                .clone()
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
    use crate::{MockDatabase, PGDatabase};
    use crate::{protocol::{ecdsa::party_one::Party1Private, util::tests::{STATE_CHAIN_SIG, test_sc_entity, PARTY_1_PRIVATE, PARTY_2_PUBLIC, BACKUP_TX_NO_SIG}}, structs::{TransferData, StateChainOwner, ECDSAKeypair}, error::DBErrorType, storage::db};
    use std::str::FromStr;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use chrono::Utc;
    use mockall::predicate;

    #[test]
    fn itegration_test_transfer_sender() {
        let user_id = Uuid::from_str("203001c9-93f0-46f9-aaaa-0678c891b2d3").unwrap();
        let no_sc_user_id = Uuid::from_str("11111111-1111-46f9-aaaa-0678c891b2d3").unwrap();
        let state_chain_id = Uuid::from_str("001203c9-93f0-46f9-abda-0678c891b2d3").unwrap();
        let sender_proof_key_priv = SecretKey::from_slice(&[1; 32]).unwrap(); // Proof key priv part
        let sender_proof_key = PublicKey::from_secret_key(&Secp256k1::new(), &sender_proof_key_priv);
        let receiver_proof_key_priv = SecretKey::from_slice(&[2; 32]).unwrap(); // Proof key priv part
        let state_chain_sig: StateChainSig = serde_json::from_str(&STATE_CHAIN_SIG.to_string()).unwrap();

        let mut db = MockDatabase::new();
        db.expect_get_user_auth().returning(move |_| Ok(user_id));
        db.expect_get_statechain_id().with(predicate::eq(user_id)).returning(move |_| Ok(state_chain_id));
        // userid does nto own a state
        db.expect_get_statechain_id().with(predicate::eq(no_sc_user_id)).returning(move |_| Err(SEError::DBError(DBErrorType::NoDataForID, no_sc_user_id.to_string())));
        db.expect_transfer_is_completed().with(predicate::eq(state_chain_id)).returning(|_| false);
        db.expect_get_statechain_owner().with(predicate::eq(state_chain_id))
            .returning(move |_| Ok(StateChainOwner{
                    locked_until: Utc::now().naive_utc(),
                    owner_id: user_id,
                    chain: StateChain::new(sender_proof_key.to_string())
                }));
        db.expect_create_transfer().returning(|_,_,_| Ok(()));

        let sc_entity = test_sc_entity(db);

        // user does not own State Chain
        match sc_entity.transfer_sender(TransferMsg1{
            shared_key_id: no_sc_user_id,
            state_chain_sig: state_chain_sig.clone()
        }) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("DB Error: No data for identifier."))
        }

        assert!(sc_entity.transfer_sender(TransferMsg1{
            shared_key_id: user_id,
            state_chain_sig
        }).is_ok());
    }

    #[test]
    fn itegration_test_transfer_receiver() {
        let user_id = Uuid::from_str("203001c9-93f0-46f9-aaaa-0678c891b2d3").unwrap();
        let state_chain_id = Uuid::from_str("001203c9-93f0-46f9-abda-0678c891b2d3").unwrap();
        let x1: FE = ECScalar::new_random();
        let sender_proof_key_priv = SecretKey::from_slice(&[1; 32]).unwrap(); // Proof key priv part
        let sender_proof_key = PublicKey::from_secret_key(&Secp256k1::new(), &sender_proof_key_priv);
        let receiver_proof_key_priv = SecretKey::from_slice(&[2; 32]).unwrap(); // Proof key priv part
        let receiver_proof_key = PublicKey::from_secret_key(&Secp256k1::new(), &receiver_proof_key_priv);

        let state_chain = StateChain::new(sender_proof_key_priv.to_string());
        let state_chain_owner = StateChainOwner{
            locked_until: Utc::now().naive_utc(),
            owner_id: user_id,
            chain: state_chain
        };

        let backup_tx = serde_json::from_str(&BACKUP_TX_NO_SIG.to_string()).unwrap();

        let mut db = MockDatabase::new();
        db.expect_get_user_auth().returning(move |_| Ok(user_id));
        db.expect_get_transfer_data()
            .with(predicate::eq(state_chain_id))
            .returning(move |_| Ok(TransferData {
                state_chain_id,
                state_chain_sig: serde_json::from_str::<StateChainSig>(&STATE_CHAIN_SIG.to_string()).unwrap(),
                x1,
            }));
        db.expect_get_ecdsa_keypair()
            .with(predicate::eq(user_id))
            .returning(|_| Ok(ECDSAKeypair {
                party_1_private: serde_json::from_str(&PARTY_1_PRIVATE.to_string()).unwrap(),
                party_2_public: serde_json::from_str(&PARTY_2_PUBLIC.to_string()).unwrap()
            }));
        // db.expect_get_finalize_batch_data()
        //     .returning(|_| Ok(TransferFinalizeData {
        //         new_shared_key_id: user_id,
        //         o2: FE::zero(),
        //         s2_pub: GE::base_point2(),
        //         state_chain_data: StateChainDataAPI {
        //             amount: 1000 as u64,
        //             utxo: tx_backup.input.get(0).unwrap().previous_output,
        //             chain: state_chain.chain.chain,
        //         },
        //         proof_key: sender_proof_key,
        //         state_chain_id: state_chain_id,
        //         tx_backup_psm: PrepareSignTxMsg {
        //             state_chain_sig: serde_json::from_str::<StateChainSig>(&STATE_CHAIN_SIG.to_string()).unwrap(),
        //             s2: FE::zero(),
        //             new_tx_backup: backup_tx.clone(),
        //             batch_data: BatchData{id: user_id, commitment: String::default()},
        //         },
        //     }));

        let sc_entity = test_sc_entity(db);

        // Test regaular transfer (no batch)
        assert!(sc_entity.transfer_receiver(TransferMsg4 {
            shared_key_id: user_id,
            state_chain_id: state_chain_id,
            t2: FE::zero(),
            state_chain_sig: serde_json::from_str::<StateChainSig>(&STATE_CHAIN_SIG.to_string()).unwrap(),
            o2_pub: GE::base_point2(),
            tx_backup: backup_tx.clone(),
            batch_data: None,
        }).is_ok());

        // Test transfer involved in batch
        assert!(sc_entity.transfer_receiver(TransferMsg4 {
            shared_key_id: user_id,
            state_chain_id: state_chain_id,
            t2: FE::zero(),
            state_chain_sig: serde_json::from_str::<StateChainSig>(&STATE_CHAIN_SIG.to_string()).unwrap(),
            o2_pub: GE::base_point2(),
            tx_backup: backup_tx,
            batch_data: Some(BatchData{id: user_id, commitment: String::default()}),
        }).is_ok());
    }
}
