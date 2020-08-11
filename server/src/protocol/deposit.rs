//! StateEntity Deposit
//!
//! StateEntity Deposit trait and implementation for StateChainEntity.

pub use super::super::Result;
extern crate shared_lib;
use crate::error::SEError;
use crate::server::StateChainEntity;
use crate::storage::Storage;
use crate::Database;
use shared_lib::{state_chain::*, structs::*, util::FEE};

use bitcoin::PublicKey;
use cfg_if::cfg_if;
use rocket::State;
use rocket_contrib::json::Json;
use std::str::FromStr;
use uuid::Uuid;

//Generics cannot be used in Rocket State, therefore we define the concrete
//type of StateChainEntity here
cfg_if! {
    if #[cfg(any(test,feature="mockdb"))]{
        use crate::MockDatabase;
        type SCE = StateChainEntity::<MockDatabase>;
    } else {
        use crate::PGDatabase;
        type SCE = StateChainEntity::<PGDatabase>;
    }
}

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
    fn deposit_confirm(&self, deposit_msg2: DepositMsg2) -> Result<Uuid>;
}

impl Deposit for SCE {
    fn deposit_init(&self, deposit_msg1: DepositMsg1) -> Result<Uuid> {
        // Generate shared wallet ID (user ID)
        let user_id = Uuid::new_v4();

        // if Verification/PoW/authoriation failed {
        //      warn!("Failed authorisation.")
        //      Err(SEError::AuthError)
        //  }

        // Check proof key is valid public key
        if let Err(_) = PublicKey::from_str(&deposit_msg1.proof_key) {
            return Err(SEError::Generic(String::from(
                "Proof key not in correct format.",
            )));
        };

        // Create DB entry for newly generated ID signalling that user has passed some
        // verification. For now use ID as 'password' to interact with state entity
        self.database
            .create_user_session(&user_id, &deposit_msg1.auth, &deposit_msg1.proof_key)?;

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

    fn deposit_confirm(&self, deposit_msg2: DepositMsg2) -> Result<Uuid> {
        // let shared_key_id = deposit_msg2.shared_key_id.clone();
        let user_id = deposit_msg2.shared_key_id;
        self.check_user_auth(&user_id)?;

        // Get back up tx and proof key
        let (tx_backup, proof_key) = self
            .database
            .get_backup_transaction_and_proof_key(user_id)?;

        // Ensure backup tx exists and is signed
        if tx_backup.input[0].witness.len() == 0 {
            return Err(SEError::Generic(String::from(
                "Signed Back up transaction not found.",
            )));
        }

        // Wait for funding tx existence in blockchain and confs
        self.verify_tx_confirmed(&tx_backup.input[0].previous_output.txid.to_string())?;

        // Create state chain DB object
        let state_chain_id = Uuid::new_v4();
        let amount = (tx_backup.output.last().unwrap().value + FEE) as i64;
        let state_chain = StateChain::new(proof_key.clone());

        // Insert into StateChain table
        self.database
            .create_statechain(&state_chain_id, &user_id, &state_chain, &amount)?;

        // Insert into BackupTx table
        self.database
            .create_backup_transaction(&state_chain_id, &tx_backup)?;

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
        self.database
            .update_statechain_id(&user_id, &state_chain_id)?;

        Ok(state_chain_id)
    }
}

#[post("/deposit/init", format = "json", data = "<deposit_msg1>")]
pub fn deposit_init(sc_entity: State<SCE>, deposit_msg1: Json<DepositMsg1>) -> Result<Json<Uuid>> {
    match sc_entity.deposit_init(deposit_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/deposit/confirm", format = "json", data = "<deposit_msg2>")]
pub fn deposit_confirm(
    sc_entity: State<SCE>,
    deposit_msg2: Json<DepositMsg2>,
) -> Result<Json<Uuid>> {
    match sc_entity.deposit_confirm(deposit_msg2.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::protocol::util::{
        mocks,
        tests::{test_sc_entity, BACKUP_TX_NOT_SIGNED, BACKUP_TX_SIGNED},
    };
    use bitcoin::Transaction;
    use std::str::FromStr;

    #[test]
    fn integration_test_deposit_init() {
        let mut db = MockDatabase::new();
        db.expect_create_user_session().returning(|_, _, _| Ok(()));

        let sc_entity = test_sc_entity(db);

        // Invalid proof key
        match sc_entity.deposit_init(DepositMsg1 {
            auth: String::from("auth"),
            proof_key: String::from(""),
        }) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("Proof key not in correct format.")),
        }
        // Invalid proof key
        match sc_entity.deposit_init(DepositMsg1 {
            auth: String::from("auth"),
            proof_key: String::from(
                "65aab40995d3ed5d03a0567b04819ff12641b84c17f5e9d5dd075571e18346",
            ),
        }) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("Proof key not in correct format.")),
        }

        assert!(sc_entity
            .deposit_init(DepositMsg1 {
                auth: String::from("auth"),
                proof_key: String::from(
                    "026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e"
                )
            })
            .is_ok());
    }

    #[test]
    fn integration_test_deposit_confirm() {
        let user_id = Uuid::from_str("001203c9-93f0-46f9-abda-0678c891b2d3").unwrap();
        let proof_key =
            String::from("026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e");
        let tx_backup: Transaction = serde_json::from_str(&BACKUP_TX_NOT_SIGNED).unwrap();
        let tx_backup_signed = serde_json::from_str::<Transaction>(&BACKUP_TX_SIGNED).unwrap();

        let mut db = MockDatabase::new();
        db.expect_get_user_auth().returning(move |_| Ok(user_id));
        db.expect_root_get_current_id().returning(|| Ok(1 as i64));
        db.expect_get_root().returning(|_| Ok(None));
        db.expect_root_update().returning(|_| Ok(1));
        // First return unsigned back up tx
        db.expect_get_backup_transaction_and_proof_key()
            .times(1)
            .returning(move |_| Ok((tx_backup.clone(), "".to_string())));
        // Second time return signed back up tx
        db.expect_get_backup_transaction_and_proof_key()
            .returning(move |_| Ok((tx_backup_signed.clone(), proof_key.clone())));
        db.expect_create_statechain().returning(|_, _, _, _| Ok(()));
        db.expect_create_backup_transaction()
            .returning(|_, _| Ok(()));
        db.expect_update_statechain_id().returning(|_, _| Ok(()));

        let sc_entity = test_sc_entity(db);

        // Backup tx not signed error
        match sc_entity.deposit_confirm(DepositMsg2 {
            shared_key_id: user_id,
        }) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("Signed Back up transaction not found.")),
        }

        // Clean protocol run
        let _m = mocks::ms::post_commitment().create();         //Mainstay post commitment mock
        assert!(sc_entity
            .deposit_confirm(DepositMsg2 {
                shared_key_id: user_id
            })
            .is_ok());
    }
}
