//! StateEntity POD (pay on deposit)
//!
//! StateEntity POD trait and implementation for StateChainEntity.

pub use super::super::Result;
extern crate shared_lib;
use crate::error::SEError;
use crate::protocol::util::RateLimiter;
use crate::rpc::bitcoin_client_factory::BitcoinRpcApi;
use crate::server::StateChainEntity;
use crate::Database;
use shared_lib::structs::*;

use crate::rpc::bitcoin_client_factory::BitcoinClient;
use crate::rpc::lightning_client_factory::LightningClient;
use bitcoin::Address;
use bitcoin::Amount;
use cfg_if::cfg_if;
use rocket::State;
use rocket_contrib::json::Json;
use rocket_okapi::openapi;
use shared_lib::structs::Invoice;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use uuid::Uuid;
use std::str::FromStr;

//Generics cannot be used in Rocket State, therefore we define the concrete
//type of StateChainEntity here
cfg_if! {
    if #[cfg(any(test,feature="mockdb"))]{
        use crate::MockDatabase;
        use monotree::database::MemoryDB;
        type DB = MockDatabase;
        type SCE = StateChainEntity::<DB, MemoryDB>;

    } else {
        use crate::PGDatabase;
        type DB = PGDatabase;
        type SCE = StateChainEntity::<DB, DB>;
    }
}

/// StateChain Deposit protocol trait
pub trait POD {
    /// API: Initiliase pay-on-deposit:
    ///     - Generate and return a new pay on deposit token
    fn pod_token_init(
        &self,
        token_id: Uuid,
        value: &u64,
        lightning_client: Option<&LightningClient>,
        bitcoin_client: Option<&BitcoinClient>,
    ) -> Result<PODInfo>;

    /// API: Verify a POD token:
    ///     - Return the PODStatus struct for token_id
    fn pod_token_verify(
        &self,
        bitcoin_client: Option<&BitcoinClient>,
        lightning_client: Option<&LightningClient>,
        token_id: &Uuid,
    ) -> Result<PODStatus>;

    fn get_lightning_invoice(
        &self,
        lightning_client: Option<&LightningClient>,
        pod_token_id: &Uuid,
        value: &u64,
    ) -> Result<Invoice>;

    fn get_btc_payment_address(
        &self,
        bitcoin_client: Option<&BitcoinClient>,
        pod_token_id: &Uuid,
    ) -> Result<Address>;

    fn query_lightning_payment(
        &self,
        lightning_client: Option<&LightningClient>,
        id: &Uuid,
    ) -> Result<bool>;

    fn wait_lightning_invoices(&self) -> Result<()>;

    fn query_btc_payment(
        &self,
        bitcoin_client: Option<&BitcoinClient>,
        address: &Address,
        value: &u64,
    ) -> Result<bool>;

}

impl POD for SCE {
    fn pod_token_init(
        &self,
        token_id: Uuid,
        value: &u64,
        lightning_client: Option<&LightningClient>,
        bitcoin_client: Option<&BitcoinClient>,
    ) -> Result<PODInfo> {
        let lightning_invoice: Invoice = self
            .get_lightning_invoice(lightning_client, &token_id, value)?
            .into();
        let btc_payment_address = self.get_btc_payment_address(bitcoin_client, &token_id)?;
        let pod_info = PODInfo {
            token_id,
            lightning_invoice,
            btc_payment_address,
            value: value.to_owned(),
        };
        match self.database.init_pay_on_demand_info(&pod_info) {
            Ok(_) => Ok(pod_info),
            Err(e) => Err(SEError::Generic(format!(
                "Error setting POD info: {:?} - {}",
                &pod_info, &e
            ))),
        }
    }

    fn pod_token_verify(
        &self,
        bitcoin_client: Option<&BitcoinClient>,
        lightning_client: Option<Arc<Mutex<LightningClient>>>,
        token_id: &Uuid,
    ) -> Result<PODStatus> {
        let statuses = self.lightning_invoice_statuses.clone();
        let database = &self.database;

        fn confirm_payment(
            pod_info: &PODInfo,
            statuses: Arc<Mutex<HashMap<Uuid, LightningInvoiceStatus>>>,
            database: &DB,
        ) -> Result<PODStatus> {
            database.set_pay_on_demand_status(
                &pod_info.token_id,
                &PODStatus {
                    confirmed: true,
                    amount: pod_info.value,
                },
            )?;
            //Database updated as confirmed - lightning payment status no longer needed in memory
            let mut guard = statuses.as_ref().lock().unwrap();
            guard.remove(&pod_info.token_id);
            database.get_pay_on_demand_status(&pod_info.token_id)
        }

        let mut pod_status = self.database.get_pay_on_demand_status(token_id)?;
        if (!pod_status.confirmed) {
            let pod_info = &self.database.get_pay_on_demand_info(token_id)?;

            if self.query_btc_payment(
                bitcoin_client,
                &pod_info.btc_payment_address,
                &pod_info.value,
            )? {
                pod_status = confirm_payment(&pod_info, statuses, database)?
            }

            if self.query_lightning_payment(lightning_client, &token_id)? {
                pod_status = confirm_payment(&pod_info, statuses, database)?
            }

        }

        Ok(pod_status)
    }

    fn get_lightning_invoice(
        &self,
        lightning_client: Option<&LightningClient>,
        pod_token_id: &Uuid,
        value: &u64,
    ) -> Result<Invoice> {
        let id_str = &pod_token_id.to_string();
        Ok(lightning_client
            .unwrap_or(&self.lightning_client()?)
            .invoice(value * 1000, id_str, id_str, None)?
            .into())
    }

    fn get_btc_payment_address(
        &self,
        bitcoin_client: Option<&BitcoinClient>,
        pod_token_id: &Uuid,
    ) -> Result<Address> {
        let id_str = pod_token_id.to_string().clone();
        let result = bitcoin_client
            .unwrap_or(&self.bitcoin_client()?)
            .get_new_address(Some(&id_str), None)?
            .into();
        Ok(result)
    }

    fn query_lightning_payment(
        &self,
        lightning_client: Option<&LightningClient>,
        id: &Uuid,
    ) -> Result<bool> {









        
    }

    fn query_btc_payment(
        &self,
        bitcoin_client: Option<&BitcoinClient>,
        address: &Address,
        value: &u64,
    ) -> Result<bool> {
        let received: Amount = bitcoin_client
            .unwrap_or(&self.bitcoin_client()?)
            .get_received_by_address(&address, Some(1))?
            .into();
        Ok(received >= Amount::from_sat(value.to_owned()))
    }
}

#[openapi]
/// # Initialize a pay-on-demand token
#[get("/pod/token/init/<value>", format = "json")]
pub fn pod_token_init(sc_entity: State<SCE>, value: u64) -> Result<Json<PODInfo>> {
    sc_entity.check_rate_slow("pod_token_init")?;
    let token_id = Uuid::new_v4();
    match sc_entity.pod_token_init(token_id, &value, None, None) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Verify confirmed and spent status of pod token
#[get("/pod/token/verify/<pod_token_id>", format = "json")]
pub fn pod_token_verify(sc_entity: State<SCE>, pod_token_id: String) -> Result<Json<PODStatus>> {
    sc_entity.check_rate_fast("pod_token_verify")?;
    let id = Uuid::from_str(&pod_token_id)?.into();
    match sc_entity.pod_token_verify(None, None, &id) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::error::DBErrorType;
    use crate::protocol::util::tests::test_sc_entity;
    use crate::rpc::lightning_client_factory::mock_constants as ln_consts;
    use crate::rpc::bitcoin_client_factory::mock_constants as btc_consts;
    use clightningrpc::responses;

    fn get_invoice_amount() -> bitcoin::Amount {
        ln_consts::invoice_amount()
    }

    fn get_waiting(id: &str) -> responses::WaitInvoice {
        ln_consts::waiting(id)
    }

    fn get_paid(id: &str) -> responses::WaitInvoice {
        ln_consts::paid(id)
    }

    fn get_expired(id: &str) -> responses::WaitInvoice {
        let mut resp = get_waiting(id);
        resp.status = String::from("expired");
        let resp = resp;
        resp
    }

    fn get_lightning_invoice() -> Invoice {
        ln_consts::invoice()
    }

    fn get_invoice() -> Invoice {
        Invoice::from(get_lightning_invoice())
    }

    fn get_pod_info(token_id: Uuid) -> PODInfo {
        PODInfo {
            token_id,
            lightning_invoice: get_invoice(),
            btc_payment_address: btc_consts::address(),
            value: get_invoice_amount().as_sat(),
        }
    }

    fn get_test_sce() -> SCE {
        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().return_const(Ok(()));
        db.expect_create_user_session().return_const(Ok(()));
        test_sc_entity(db, None, None, None, None)
    }

    #[test]
    fn test_pod_token_init() {
        let token_id = Uuid::new_v4();
        let mut sce = get_test_sce();
        sce.database
            .expect_init_pay_on_demand_info()
            .return_const(Ok(()));
        let address = btc_consts::address();
        let address_clone = address.clone();
        let mut bc = sce.bitcoin_client().unwrap();
        bc.expect_get_new_address()
            .return_once(move |_, _| Ok(address_clone));
        let invoice = get_lightning_invoice();
        let mut lc = sce.lightning_client().unwrap();

        lc.expect_invoice()
            .return_once(move |_, _, _, _| Ok(invoice.clone()));
        let value = 1234;
        let info_expected = get_pod_info(token_id.clone());
        let info: PODInfo = sce
            .pod_token_init(token_id.clone(), &value, Some(&lc), Some(&bc))
            .unwrap();
        assert_eq!(&info.value, &value);
        assert_eq!(&info.btc_payment_address, &address);
        assert_eq!(&info, &info_expected);
    }

    #[test]
    fn test_get_btc_payment_address() {
        let sce = get_test_sce();
        let address = btc_consts::address();
        let address_clone = address.clone();
        let mut bc = sce.bitcoin_client().unwrap();
        bc.expect_get_new_address()
            .return_once(move |_, _| Ok(address_clone));
        let _address: Address = sce
            .get_btc_payment_address(Some(&bc), &Uuid::new_v4())
            .unwrap();
    }

    #[test]
    fn test_get_lightning_invoice() {
        let sce = get_test_sce();
        let invoice_expected = get_lightning_invoice();
        let invoice_expected_db: Invoice = invoice_expected.clone().into();
        let mut lc = sce.lightning_client().unwrap();
        lc.expect_invoice()
            .return_once(move |_, _, _, _| Ok(invoice_expected.clone()));
        let value = 123;
        let invoice: Invoice = sce
            .get_lightning_invoice(Some(&lc), &Uuid::new_v4(), &value)
            .unwrap()
            .into();
        assert_eq!(invoice, invoice_expected_db);
    }

    #[test]
    fn test_pod_token_verify_unknown() {
        let mut sce = get_test_sce();
        let id = Uuid::from_fields(0, 1, 2, &[0, 1, 2, 3, 4, 5, 6, 7]).unwrap();
        sce.database
            .expect_get_pay_on_demand_status()
            .return_once(move |&id_clone| {
                return Err(SEError::DBError(
                    DBErrorType::NoDataForID,
                    id_clone.to_string(),
                ));
            });
        let result = sce.pod_token_verify(None, None, &id);
        assert_eq!(
            result,
            Err(SEError::DBError(DBErrorType::NoDataForID, id.to_string()))
        );
    }

    #[test]
    fn test_pod_token_verify_waiting_lightning() {
        let mut sce = get_test_sce();
        let id = Uuid::from_fields(0, 1, 2, &[0, 1, 2, 3, 4, 5, 6, 7]).unwrap();
        sce.database
            .expect_get_pay_on_demand_status()
            .return_const(Ok(PODStatus {
                confirmed: false,
                amount: 0,
            }));
        sce.database
            .expect_get_pay_on_demand_info()
            .return_const(Ok(get_pod_info(id.clone())));
        let mut lc = sce.lightning_client().unwrap();
        lc.expect_waitinvoice()
            .returning(|id_str| Ok(get_waiting(id_str)));
        let lc_arc = Arc::new(Mutex::new(lc));
        let lc_guard = lc_arc.as_ref().lock().unwrap();
        drop(lc_guard);
        let mut bc = sce.bitcoin_client().unwrap();
        bc.expect_get_received_by_address()
            .returning(|_, _| Ok(bitcoin::Amount::from_sat(0)));
        let result = sce.pod_token_verify(Some(&bc), Some(Arc::clone(&lc_arc)), &id);
        assert_eq!(
            result,
            Ok(PODStatus {
                confirmed: false,
                amount: 0
            })
        );
        //Still unpaid on second call
        let result_2 = sce.pod_token_verify(Some(&bc), Some(lc_arc), &id);
        assert_eq!(
            result_2,
            Ok(PODStatus {
                confirmed: false,
                amount: 0
            })
        );
    }

    #[test]
    fn test_pod_token_verify_paid() {
        let mut sce = get_test_sce();
        let id = Uuid::from_fields(0, 1, 2, &[0, 1, 2, 3, 4, 5, 6, 7]).unwrap();
        sce.database
            .expect_get_pay_on_demand_status()
            .return_const(Ok(PODStatus {
                confirmed: true,
                amount: 100,
            }));
        let result = sce.pod_token_verify(None, None, &id);
        assert_eq!(
            result,
            Ok(PODStatus {
                confirmed: true,
                amount: 100
            })
        );
    }

    #[test]
    fn test_pod_token_verify_paid_lightning() {
        let mut sce = get_test_sce();
        let id = Uuid::from_fields(0, 1, 2, &[0, 1, 2, 3, 4, 5, 6, 7]).unwrap();

        let mut seq = mockall::Sequence::new();

        sce.database
            .expect_get_pay_on_demand_status()
            .times(1)
            .in_sequence(&mut seq)
            .return_const(Ok(PODStatus {
                confirmed: false,
                amount: 0,
            }));

        sce.database
            .expect_get_pay_on_demand_status()
            .times(1)
            .in_sequence(&mut seq)
            .return_const(Ok(PODStatus {
                confirmed: true,
                amount: 100,
            }));

        sce.database
            .expect_get_pay_on_demand_info()
            .return_const(Ok(get_pod_info(id.clone())));
        let mut lc = sce.lightning_client().unwrap();
        lc.expect_waitinvoice()
            .return_once(move |id_str| Ok(get_waiting(id_str)));
        lc.expect_waitinvoice()
            .return_once(move |id_str| Ok(get_paid(id_str)));
        let lc_arc = Arc::new(Mutex::new(lc));
        let mut bc = sce.bitcoin_client().unwrap();
        bc.expect_get_received_by_address()
            .returning(|_, _| Ok(bitcoin::Amount::from_sat(0)));
        let result = sce.pod_token_verify(Some(&bc), Some(Arc::clone(&lc_arc)), &id);
        assert_eq!(
            result,
            Ok(PODStatus {
                confirmed: false,
                amount: 0
            })
        );
        
        let result_2 = sce.pod_token_verify(Some(&bc), Some(lc_arc), &id);
        assert_eq!(
            result_2,
            Ok(PODStatus {
                confirmed: true,
                amount: 100
            })
        );
    }

    #[test]
    fn test_pod_token_verify_expired_lightning() {
        let mut sce = get_test_sce();
        let id = Uuid::from_fields(0, 1, 2, &[0, 1, 2, 3, 4, 5, 6, 7]).unwrap();
        sce.database
            .expect_get_pay_on_demand_status()
            .times(2)
            .return_const(Ok(PODStatus {
                confirmed: false,
                amount: 0,
            }));
        sce.database
            .expect_get_pay_on_demand_info()
            .return_const(Ok(get_pod_info(id.clone())));
        let mut lc = sce.lightning_client().unwrap();
        lc.expect_waitinvoice()
            .returning(|id_str| Ok(get_expired(id_str)));
        let lc_arc = Arc::new(Mutex::new(lc));

        let mut bc = sce.bitcoin_client().unwrap();
        bc.expect_get_received_by_address()
            .returning(|_, _| Ok(bitcoin::Amount::from_sat(0)));
        let result = sce.pod_token_verify(Some(&bc), Some(Arc::clone(&lc_arc)), &id);
        assert_eq!(
            result,
            Ok(PODStatus {
                confirmed: false,
                amount: 0
            })
        );
        let result_2 = sce.pod_token_verify(Some(&bc), Some(Arc::clone(&lc_arc)), &id);
        assert_eq!(
            result_2,
            Ok(PODStatus {
                confirmed: false,
                amount: 0
            })
        );
    }

    #[test]
    fn test_pod_token_verify_paid_btc() {
        let mut sce = get_test_sce();
        let id = Uuid::from_fields(0, 1, 2, &[0, 1, 2, 3, 4, 5, 6, 7]).unwrap();
        sce.database
            .expect_get_pay_on_demand_status()
            .times(2)
            .return_const(Ok(PODStatus {
                confirmed: false,
                amount: 0,
            }));
        sce.database
            .expect_get_pay_on_demand_status()
            .times(1)
            .return_const(Ok(PODStatus {
                confirmed: true,
                amount: 100,
            }));
        sce.database
            .expect_set_pay_on_demand_status()
            .times(1)
            .return_const(Ok(()));
        sce.database
            .expect_get_pay_on_demand_info()
            .return_const(Ok(get_pod_info(id.clone())));
        let mut lc = sce.lightning_client().unwrap();
        lc.expect_waitinvoice()
            .times(2)
            .returning(|id_str| Ok(get_waiting(id_str)));
        let lc_arc = Arc::new(Mutex::new(lc));
        
        let mut bc = sce.bitcoin_client().unwrap();
        //full amount paid - expect confirmed
        bc.expect_get_received_by_address()
            .times(1)
            .returning(|_, _| Ok(get_invoice_amount()));

        sce.pod_token_verify(Some(&bc), Some(Arc::clone(&lc_arc)), &id).unwrap();            
        let result = sce.pod_token_verify(Some(&bc), Some(Arc::clone(&lc_arc)), &id);
        assert_eq!(
            result,
            Ok(PODStatus {
                confirmed: true,
                amount: 100
            })
        );
    }

    #[test]
    fn test_pod_token_verify_unpaid_btc() {
        let mut sce = get_test_sce();
        let id = Uuid::from_fields(0, 1, 2, &[0, 1, 2, 3, 4, 5, 6, 7]).unwrap();
        sce.database
            .expect_get_pay_on_demand_status()
            .return_once(|_| {
                Ok(PODStatus {
                    confirmed: false,
                    amount: 0,
                })
            });
        sce.database
            .expect_get_pay_on_demand_info()
            .return_const(Ok(get_pod_info(id.clone())));
        let lc = Arc::new(Mutex::new(sce.lightning_client().unwrap()));
        let mut lc_guard = lc.as_ref().lock().unwrap();
        lc_guard
            .expect_waitinvoice()
            .times(1)
            .returning(|id_str| Ok(get_waiting(id_str)));
        drop(lc_guard);
        let mut bc = sce.bitcoin_client().unwrap();
        //Less than full amount paid - expect not confirmed
        bc.expect_get_received_by_address()
            .return_once(|_, _| Ok(get_invoice_amount() - bitcoin::Amount::from_sat(1)));
        let result = sce.pod_token_verify(Some(&bc), Some(Arc::clone(&lc)), &id);
        assert_eq!(
            result,
            Ok(PODStatus {
                confirmed: false,
                amount: 0
            })
        );
    }
}
