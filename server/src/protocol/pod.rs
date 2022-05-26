//! StateEntity POD (pay on deposit)
//!
//! StateEntity POD trait and implementation for StateChainEntity.

pub use super::super::Result;
use crate::server::DEPOSITS_COUNT;
extern crate shared_lib;
use crate::error::{SEError,DBErrorType};
use crate::server::{StateChainEntity};
use crate::protocol::util::RateLimiter;
use crate::storage::db;
use crate::storage::Storage;
use crate::Database;
use shared_lib::{state_chain::*, structs::*, util::FEE};

use bitcoin::{PublicKey, Address};
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
pub trait POD {
    /// API: Initiliase pay-on-deposit:
    ///     - Generate and return a new pay on deposit token
    fn pod_token_init(&self, value: &u64) -> Result<PODToken>;

    /// API: Verify a POD token:
    ///     - Return the PODStatus struct for token_id
    fn pod_token_verify(&self, token_id: &Uuid) -> Result<PODStatus>;
}

impl POD for SCE {
    fn pod_token_init(&self, value: &u64) -> Result<PODToken> {
        let token_id = Uuid::new_v4();
        let lightning_invoice = get_lightning_invoice(&token_id, value)?;
        let btc_payment_address = get_btc_payment_address(&token_id, value)?;
        return PODToken {token_id, lightning_invoice, btc_payment_address, value.to_owned()}
    }

    fn pod_token_verify(token_id: &Uuid) -> Result<PODStatus>> {
        let mut pod_status = db.get_pod_status(token_id)?;
        if (!pod_status.confirmed && !pod_status.spent) {
            let pod_token: PODToken = db.get_pod_token(token_id)?;
            match query_lightning_payment(&pod_token.lightning_invoice)?{
                true => {
                    pod_status.confirmed = true;
                    db.set_pod_status(token_id, &pod_status)?;
                },
                false => {
                    match query_btc_payment(&pod_token.btc_payment_address, &pod_token.value)? {
                        true => {
                            pod_status.confirmed = true;
                            db.set_pod_status(token_id, &pod_status)?;
                        },
                        false => ()
                    }
                }
            };

        }
        Result<pod_status>
    }
}

#[openapi]
/// # Initialize a pay-on-demand token
#[get("/pod/token/init/<value>", format = "json")]
pub fn deposit_init(sc_entity: State<SCE>, value: u64) -> Result<Json<PODToken>> {
    sc_entity.check_rate_slow("pod_token_init")?;
    match sc_entity.pod_token_init(value.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Verify confirmed and spent status of pod token
#[get("/pod/token/verify/<pod_token_id>", format = "json")]
pub fn pod_token_verify(
    sc_entity: State<SCE>,
    pod_token_id: Uuid,
) -> Result<Json<PODStatus>> {
    sc_entity.check_rate_fast("pod_token_verify")?;
    match sc_entity.pod_token_verify(&pod_token_id) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

fn get_lightning_invoice(pod_token_id: &Uuid, value: &u64) -> Result<String> {
    unimplemented!()
}

fn get_btc_payment_address(pod_token_id: &Uuid, value: &u64) -> Result<Address> {
    unimplemented!()
}

fn query_lightning_payment(invoice: &string) -> Result<bool> {
    unimplemented!()
}

fn query_btc_payment(address: &Address, value: &u64) -> Result<bool> {
    unimplemented!()
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
    fn test_pod_token_init() {
        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_create_user_session().returning(|_, _, _, _, _| Ok(()));

        db.expect_

        let sc_entity = test_sc_entity(db, None, None, None, None);

        // Invalid value
        match sc_entity.pod_token_init()
    }

    fn test_pod_token_verify() {

    }
       
}
