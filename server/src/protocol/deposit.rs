//! StateEntity Deposit
//!
//! StateEntity Deposit trait and implementation for StateChainEntity.

pub use super::super::Result;
use crate::server::DEPOSITS_COUNT;
extern crate shared_lib;
use crate::error::{SEError,DBErrorType};
use crate::server::{StateChainEntity};
use crate::protocol::util::RateLimiter;
use crate::storage::Storage;
use crate::Database;
use shared_lib::{state_chain::*, structs::*, util::FEE};

use bitcoin::PublicKey;
use cfg_if::cfg_if;
use rocket::State;
use rocket_contrib::json::Json;
use std::str::FromStr;
use uuid::Uuid;
use rocket_okapi::openapi;
use rand::Rng;
use hex;

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

/// StateChain Deposit protocol trait
pub trait Deposit {
    /// API: Initiliase deposit protocol:
    ///     - Generate and return shared wallet ID
    ///     - Can do auth or other DoS mitigation here
    fn deposit_init(&self, deposit_msg1: DepositMsg1) -> Result<UserID>;

    /// API: Initiliase deposit protocol:
    ///     - Generate and return shared wallet ID
    ///     - Can do auth or other DoS mitigation here
    fn pod_deposit_init(&self, deposit_msg1: PODMsg1) -> Result<PODUserID>;

    /// API: Complete deposit protocol:
    ///     - Wait for confirmation of funding tx in blockchain
    ///     - Create StateChain DB object
    ///     - Update sparse merkle tree with new StateChain entry
    fn deposit_confirm(&self, deposit_msg2: DepositMsg2) -> Result<StatechainID>;
}

impl Deposit for SCE {
    fn deposit_init(&self, deposit_msg1: DepositMsg1) -> Result<UserID> {
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

        // Generate shared wallet ID (user ID)
        let user_id = Uuid::new_v4();

        // generate vdf challenge
        let mut rng = rand::thread_rng();
        let challenge_bytes = rng.gen::<[u8; 16]>();
        let challenge = hex::encode(challenge_bytes);

        // Create DB entry for newly generated ID signalling that user has passed some
        // verification. For now use ID as 'password' to interact with state entity
        // unsolved_vdf saved for verification at keygen first

        self.database
            .create_user_session_challenge(&user_id, &deposit_msg1.auth, &deposit_msg1.proof_key, &challenge, self.user_ids.clone(), None)?;

        info!(
            "DEPOSIT: Protocol initiated. User ID generated: {}",
            user_id
        );
        debug!(
            "DEPOSIT: User ID: {} corresponding Proof key: {}",
            user_id,
            deposit_msg1.proof_key.to_owned()
        );

        Ok(UserID {id: user_id, challenge: Some(challenge)})
    }

    fn pod_deposit_init(&self, pod_msg1: PODMsg1) -> Result<PODUserID> {

        // Check proof key is valid public key
        if let Err(_) = PublicKey::from_str(&pod_msg1.proof_key) {
            return Err(SEError::Generic(String::from(
                "Proof key not in correct format.",
            )));
        };


        let status = self.database.get_pay_on_demand_status(&pod_msg1.token_id)?;
        // Get token info

        if !status.confirmed{
            return Err(SEError::Generic(String::from(
                "Token payment not received",
            )));
        } 

        let deposit_amount = match pod_msg1.amount{
            Some(x) => x,
            None => u64::MIN
        };
        
        if deposit_amount == u64::MIN {
            return Err(SEError::Generic(String::from(
                "Invalid deposit amount",
            )));
        }
        
        if deposit_amount > status.amount{
            return Err(SEError::Generic(String::from(
                "Insufficent token credit to make deposit",
            )));
        }
        
        let token_value = status.amount - deposit_amount;
        // The remaining token value
        
        // Generate shared wallet ID (user ID)
        let user_id = Uuid::new_v4();


        // Create DB entry for newly generated ID signalling that user has passed some
        // verification. For now use ID as 'password' to interact with state entity
        // unsolved_vdf saved for verification at keygen first
        
        self.database
            .create_user_session(&user_id, &pod_msg1.auth, &pod_msg1.proof_key, self.user_ids.clone(), pod_msg1.amount)?;
        
        // Once DB entry created
        // Decrement token value
        self.database
            .set_pay_on_demand_amount( &pod_msg1.token_id, &token_value )?;


        info!(
            "DEPOSIT: Protocol initiated. User ID generated: {}",
            user_id
        );
        debug!(
            "DEPOSIT: User ID: {} corresponding Proof key: {}",
            user_id,
            pod_msg1.proof_key.to_owned()
        );

        Ok(PODUserID { id: user_id })
    }

    fn deposit_confirm(&self, deposit_msg2: DepositMsg2) -> Result<StatechainID> {
        // let shared_key_id = deposit_msg2.shared_key_id.clone();
        self.check_user_auth(&deposit_msg2.shared_key_id)?;
        let user_id = deposit_msg2.shared_key_id;

        // Get back up tx and proof key
        let (tx_backup, proof_key) = self
            .database
            .get_backup_transaction_and_proof_key(user_id)?;

        // Skip check if zero confs set
        if tx_backup.input[0].witness.len() == 0 {
            return Err(SEError::Generic(String::from(
                "Signed Back up transaction not found.",
            )));
        }

        let mut total = 0;
        for output in &tx_backup.output {
            total += output.value;
        }
        let amount = (total + FEE) as i64;

        let statechain_id: Uuid;

        // check if we already have a statechain with this user ID (in case of deposit RBF)
        match self.database.get_statechain_id(user_id.clone()) {
            Ok(res) => {
                statechain_id = res;
                self.database.update_backup_tx(&statechain_id, tx_backup.clone())?;
            },
            Err(e) => match e {
                SEError::DBErrorWC(DBErrorType::NoDataForID, _, _) => {
                    // Create state chain DB object
                    statechain_id = Uuid::new_v4();
                    let state_chain = StateChain::new(proof_key.clone());
                    // Insert into StateChain table
                    self.database.create_statechain(&statechain_id, &user_id, &state_chain, &amount)?;

                    // Insert into BackupTx table
                    self.database
                        .create_backup_transaction(&statechain_id, &tx_backup)?;                    
                    },

                _ => return Err(e),

            }
        }

        // set the shared public key
        let shared_pubkey = self.database.get_shared_pubkey(user_id.clone())?;
        self.database.set_shared_pubkey(statechain_id.clone(), &shared_pubkey.ok_or(SEError::Generic(String::from("Shared pubkey missing")))?)?;

        info!(
            "DEPOSIT: State Chain created. ID: {} For user ID: {}",
            statechain_id, user_id
        );

        // Update UserSession with StateChain's ID
        self.database
            .update_statechain_id(&user_id, &statechain_id)?;

        //increment fee metric
        DEPOSITS_COUNT.inc();

        // Update sparse merkle tree with new StateChain entry
        let (current_root, new_root) = self.update_smt(
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
            statechain_id
        );
        debug!(
            "DEPOSIT: State Chain ID: {}. New root: {:?}. Previous root: {:?}.",
            statechain_id, new_root, current_root
        );

        Ok(StatechainID {id: statechain_id})
    }
}

#[openapi]
/// # Initiate a statechain deposit and generate a shared key ID
#[post("/deposit/init", format = "json", data = "<deposit_msg1>")]
pub fn deposit_init(sc_entity: State<SCE>, deposit_msg1: Json<DepositMsg1>) -> Result<Json<UserID>> {
    sc_entity.check_rate_slow("deposit_init")?;
    match sc_entity.deposit_init(deposit_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Confirm the deposit process has completed and retreive the statechain ID
#[post("/deposit/confirm", format = "json", data = "<deposit_msg2>")]
pub fn deposit_confirm(
    sc_entity: State<SCE>,
    deposit_msg2: Json<DepositMsg2>,
) -> Result<Json<StatechainID>> {
    sc_entity.check_rate_fast("deposit_confirm")?;
    match sc_entity.deposit_confirm(deposit_msg2.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::storage::db;
    use crate::protocol::util::{
        mocks,
        tests::{test_sc_entity, BACKUP_TX_NOT_SIGNED, BACKUP_TX_SIGNED},
    };
    use bitcoin::Transaction;
    use std::str::FromStr;

    #[test]
    fn test_deposit_init() {
        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_create_user_session_challenge().returning(|_, _, _, _, _, _| Ok(()));

        let sc_entity = test_sc_entity(db, None, None, None, None);

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
    fn test_pod_deposit_init() {
        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_create_user_session().returning(|_, _, _, _, _ | Ok(()));
        
        // let mut confirmed_var = true;
        // let mut value_var = 0;

        let token_status = PODStatus {
            confirmed: true,
            amount: 0
        };

        // Token Spent Test 1
        db.expect_get_pay_on_demand_status()
            .times(1)
            .return_once( move |_| Ok(token_status));
        
        
        // MOCK Decrement Token
        db.expect_set_pay_on_demand_amount().returning(|_,_| Ok(()));


        let unconfirmed_token = PODStatus {
            confirmed: false,
            amount: 10000
        };


        // Token Not Confirmed Test 2
        db.expect_get_pay_on_demand_status()
            .times(1)
            .return_once( move |_| Ok(unconfirmed_token));
        
        
        // Insufficient token value for deposit

        let low_token = PODStatus {
            confirmed: true,
            amount: 10000
        };
        
        // Insufficient Token Funds for Deposit Test 3
        db.expect_get_pay_on_demand_status()
            .times(1)
            .return_once( move |_| Ok(low_token));
        
        let success_token = PODStatus{
            confirmed: true,
            amount: 20000
        };


        // Successful call Test 4
        db.expect_get_pay_on_demand_status()
            .times(1)
            .return_once( move |_| Ok(success_token));

        let sc_entity = test_sc_entity(db, None, None, None, None);

        // Token Already Spent Test 1
        match sc_entity.pod_deposit_init(PODMsg1 {
            auth: String::from("auth"),
            proof_key: String::from(
                "026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e"
            ),
            token_id: Uuid::new_v4(),
            amount: Some(10000),
        }) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("Insufficent token credit to make deposit")),
        }
        
        
        // Unconfirmed token ( token not paid for ) Test 2
        match sc_entity.pod_deposit_init(PODMsg1 {
            auth: String::from("auth"),
            proof_key: String::from(
                "026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e"
            ),
            token_id: Uuid::new_v4(),
            amount: Some(10000),
        }) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("Token payment not received")),
        }
        
        // Insufficient Token Funds for Deposit Test 3
        match sc_entity.pod_deposit_init(PODMsg1 {
            auth: String::from("auth"),
            proof_key: String::from(
                "026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e"
            ),
            token_id: Uuid::new_v4(),
            amount: Some(0),
        }) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("Invalid deposit amount")),
        }        
        
        
        //Successful call Test 4
        assert!(sc_entity
            .pod_deposit_init(PODMsg1 {
                auth: String::from("auth"),
                proof_key: String::from(
                    "026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e"
                ),
                token_id: Uuid::new_v4(),
                amount: Some(10000),
        })
        .is_ok());
    }

    #[test]
    fn test_deposit_confirm() {
        let user_id = Uuid::from_str("001203c9-93f0-46f9-abda-0678c891b2d3").unwrap();
        let proof_key =
            String::from("026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e");
        let tx_backup: Transaction = serde_json::from_str(&BACKUP_TX_NOT_SIGNED).unwrap();
        let tx_backup_signed = serde_json::from_str::<Transaction>(&BACKUP_TX_SIGNED).unwrap();

        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_get_user_auth()
           .returning(|_user_id| Ok(String::from("user_auth")));
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
        db.expect_get_shared_pubkey().returning(|_| Ok(Some("".to_string())));
        db.expect_set_shared_pubkey().returning(|_,_| Ok(()));
        db.expect_get_statechain_id().returning(move |_| {
                Err(SEError::DBErrorWC(
                    DBErrorType::NoDataForID,
                    user_id.clone().to_string(),db::Column::StateChainId))
            });

        let sc_entity = test_sc_entity(db, None, None, None, None);

        // Backup tx not signed error
        match sc_entity.deposit_confirm(DepositMsg2 {
            shared_key_id: user_id,
        }) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e
                .to_string()
                .contains("Signed Back up transaction not found."), "{}", e.to_string()),
        }

        // Clean protocol run
        let _m = mocks::ms::post_commitment().create(); //Mainstay post commitment mock
        assert!(sc_entity
            .deposit_confirm(DepositMsg2 {
                shared_key_id: user_id
            })
            .is_ok());
    }

    #[test]
    fn test_deposit_confirm_rbf() {
        let user_id = Uuid::from_str("001203c9-93f0-46f9-abda-0678c891b2d3").unwrap();
        let statechain_id = Uuid::from_str("11111111-93f0-46f9-abda-0678c891b2d3").unwrap();
        let proof_key =
            String::from("026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e");
        let tx_backup: Transaction = serde_json::from_str(&BACKUP_TX_NOT_SIGNED).unwrap();
        let tx_backup_signed = serde_json::from_str::<Transaction>(&BACKUP_TX_SIGNED).unwrap();

        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_get_user_auth()
           .returning(|_user_id| Ok(String::from("user_auth")));
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
        db.expect_get_shared_pubkey().returning(|_| Ok(Some("".to_string())));
        db.expect_set_shared_pubkey().returning(|_,_| Ok(()));
        db.expect_get_statechain_id().returning(move |_| Ok(statechain_id));
        db.expect_update_backup_tx().returning(|_,_| Ok(()));

        let sc_entity = test_sc_entity(db, None, None, None, None);

        // Backup tx not signed error
        match sc_entity.deposit_confirm(DepositMsg2 {
            shared_key_id: user_id,
        }) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e
                .to_string()
                .contains("Signed Back up transaction not found."), "{}", e.to_string()),
        }

        // Clean protocol run
        let _m = mocks::ms::post_commitment().create(); //Mainstay post commitment mock
        assert!(sc_entity
            .deposit_confirm(DepositMsg2 {
                shared_key_id: user_id
            })
            .is_ok());

        assert_eq!(sc_entity
            .deposit_confirm(DepositMsg2 {
                shared_key_id: user_id
            })
            .unwrap().id,statechain_id);
    }

    #[test]
    fn test_deposit_confirm_db_error() {
        let user_id = Uuid::from_str("001203c9-93f0-46f9-abda-0678c891b2d3").unwrap();
        let proof_key =
            String::from("026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e");
        let tx_backup: Transaction = serde_json::from_str(&BACKUP_TX_NOT_SIGNED).unwrap();
        let tx_backup_signed = serde_json::from_str::<Transaction>(&BACKUP_TX_SIGNED).unwrap();

        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_get_user_auth()
           .returning(|_user_id| Ok(String::from("user_auth")));
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
        db.expect_get_shared_pubkey().returning(|_| Ok(Some("".to_string())));
        db.expect_set_shared_pubkey().returning(|_,_| Ok(()));
        db.expect_get_statechain_id().returning(move |_| {
                Err(SEError::Generic(String::from(
                "Other error",)))
            });
        db.expect_update_backup_tx().returning(|_,_| Ok(()));

        let sc_entity = test_sc_entity(db, None, None, None, None);

        // Backup tx not signed error
        match sc_entity.deposit_confirm(DepositMsg2 {
            shared_key_id: user_id,
        }) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e
                .to_string()
                .contains("Signed Back up transaction not found."), "{}", e.to_string()),
        }

        // Clean protocol run
        let _m = mocks::ms::post_commitment().create(); //Mainstay post commitment mock

        match sc_entity.deposit_confirm(DepositMsg2 {
            shared_key_id: user_id,
        }) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e
                .to_string()
                .contains("Other error"), "{}", e.to_string()),
        }

    }
}
