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
use crate::rpc::bitcoin_client_factory::BitcoinRpcApi;
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
use bitcoincore_rpc::Error;
use bitcoin::{consensus, Amount};
use jsonrpc;
use clightningrpc::responses::Invoice as LightningInvoice;
use shared_lib::structs::Invoice;
use std::{thread, time};
use std::sync::mpsc::channel;
use crate::rpc::lightning_client_factory::{LightningClient, LightningClientFactory};
use clightningrpc::common::MSat;


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
    fn pod_token_init(&self, value: &u64) -> Result<PODInfo>;

    /// API: Verify a POD token:
    ///     - Return the PODStatus struct for token_id
    fn pod_token_verify(&mut self, token_id: &Uuid) -> Result<PODStatus>;

    fn get_lightning_invoice(&self, pod_token_id: &Uuid, value: &u64) -> Result<LightningInvoice>;

    fn get_btc_payment_address(&self, pod_token_id: &Uuid) -> Result<Address>;

    fn query_lightning_payment(&mut self, id: &Uuid) -> Result<LightningInvoiceStatus>;

    //fn wait_lightning_invoice(&self, label: &String) -> Result<()>;

    fn wait_lightning_invoices(&self) -> Result<()>;

    fn query_btc_payment(&self, address: &Address, value: &u64) -> Result<bool>;
}

impl POD for SCE {
    fn pod_token_init(&self, value: &u64) -> Result<PODInfo> {
        let token_id = Uuid::new_v4();
        let lightning_invoice: Invoice = self.get_lightning_invoice(&token_id, value)?.into();
        let btc_payment_address = self.get_btc_payment_address(&token_id)?;
        let pod_info = PODInfo {lightning_invoice, btc_payment_address, value: value.to_owned()};
        self.database.set_pay_on_demand_info(&token_id, &pod_info)?;
        return Ok(pod_info)
    }

    fn pod_token_verify(&mut self, token_id: &Uuid) -> Result<PODStatus> {
        let db = &mut self.database;
        let mut pod_status = db.get_pay_on_demand_status(token_id)?;
        if (!pod_status.confirmed && !pod_status.spent) {
            let pod_info: PODInfo = db.get_pay_on_demand_info(token_id)?;
            let confirmed = match self.query_lightning_payment(&token_id)?{
                LightningInvoiceStatus::Paid => true,
                _ => self.query_btc_payment(&pod_info.btc_payment_address, &pod_info.value)?                 
            };
            if(confirmed) {
                db.set_pay_on_demand_confirmed(token_id, &true)?;
                pod_status = db.get_pay_on_demand_status(token_id)?;
            }
        }
        Ok(pod_status)
    }

    fn get_lightning_invoice(&self, pod_token_id: &Uuid, value: &u64) -> Result<LightningInvoice> {
        let id_str = &pod_token_id.to_string();
        Ok(self.lightning_client()?.invoice(value*1000, id_str, id_str, None)?.into())
    }

    fn get_btc_payment_address(&self, pod_token_id: &Uuid) -> Result<Address> {
        let id_str = pod_token_id.to_string().clone();
        let result = self.bitcoin_client()?.get_new_address(Some(&id_str), None)?.into();
        Ok(result)
    }

    fn query_lightning_payment(&mut self, id: &Uuid) -> Result<LightningInvoiceStatus> {
        let mut guard = self.lightning_invoice_statuses.as_ref().lock().unwrap();
        match guard.get(id) {
            Some(s) => Ok(s.to_owned()),
            None => {
                let mut threadpool_guard = self.lightning_waitinvoice_threadpool.as_ref().lock().unwrap();
                let lightning_rpc = LightningClientFactory::create(&self.config.lightningd)?;
                let id_clone = id.clone();
                threadpool_guard.execute(move || {
                        let invoice = lightning_rpc.waitinvoice(&id_clone.to_string()).
                            map_err(|e| SEError::from(e)).expect("failed to retrieve invoice payment");  
                        let mut guard = statuses.as_ref().lock().unwrap();
                        let status = match invoice.status.as_str() {
                            "paid" => LightningInvoiceStatus::Paid,
                            "expired" => LightningInvoiceStatus::Expired,
                            _ => LightningInvoiceStatus::Waiting,
                        };
                        guard.insert(status)
                    }
                );
                guard.insert(id.clone(), LightningInvoiceStatus::Waiting);
                Ok(LightningInvoiceStatus::Waiting)
            }
        }
    }

    /*
    fn query_lightning_payment(&self, label: &String) -> Result<bool> {
        let (tx, rx) = channel::<bool>();
        let sender = thread::spawn(move || {
            //let invoice_paid = self.lightning_client()?.waitinvoice(label).map_err(|e| SEError::from(e)).expect("failed to retrieve invoice payment");
            //tx.send(invoice_paid.status == "paid").expect("failed to send");
            tx.send(true).expect("failed to send");
        });
        thread::sleep(time::Duration::from_secs(1));
       /*
        match rx.recv() {
            Ok(value) => Ok(value),
            Err(_) => {
                sender.
            }
        }
        */
        Ok(true)
    }
    */

    fn query_btc_payment(&self, address: &Address, value: &u64) -> Result<bool> {
        let received: Amount = self.bitcoin_client()?.get_received_by_address(&address, Some(1))?.into();
        Ok(received >= Amount::from_sat(value.to_owned()))
    }

    fn wait_lightning_invoices(&self) -> Result<()> {
        unimplemented!()
    }
}

#[openapi]
/// # Initialize a pay-on-demand token
#[get("/pod/token/init/<value>", format = "json")]
pub fn deposit_init(sc_entity: State<SCE>, value: u64) -> Result<Json<PODInfo>> {
    sc_entity.check_rate_slow("pod_token_init")?;
    match sc_entity.pod_token_init(&value) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Verify confirmed and spent status of pod token
#[get("/pod/token/verify/<pod_token_id>", format = "json")]
pub fn pod_token_verify(
    sc_entity: State<SCE>,
    pod_token_id: String,
) -> Result<Json<PODStatus>> {
    sc_entity.check_rate_fast("pod_token_verify")?;
    match sc_entity.pod_token_verify(&Uuid::from_str(&pod_token_id)?.into()) {
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
    use clightningrpc::responses;

    fn get_test_sce() -> SCE {
        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_create_user_session().returning(|_, _, _, _, _| Ok(()));
        test_sc_entity(db, None, None, None, None)
    }
    
    #[test]
    fn test_pod_token_init() {
        let mut sce = get_test_sce();
        sce.database.expect_set_pay_on_demand_info().returning(|_,_| Ok(()));
        let address = Address::from_str("1DTFRJ2XFb4AGP1Tfk54iZK1q2pPfK4n3h").unwrap();
        let address_clone = address.clone();
        sce.bitcoin_client()?.expect_get_new_address().return_once(move |_,_| Ok(address_clone));
        let invoice = LightningInvoice {
            payment_hash: String::from("0001020304050607080900010203040506070809000102030405060708090102"),
            expires_at: 604800,
            bolt11: String::from("lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl\
2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcws\
pyetp5h2tztugp9lfyql"),
        };
        sce.lightning_client()?.expect_invoice().return_once(move |_,_,_,_| Ok(invoice.clone()));
        let value = 1234;
        let info: PODInfo = sce.pod_token_init(&value).unwrap();
        assert_eq!(&info.value, &value);
        assert_eq!(&info.btc_payment_address, &address);
    }

    #[test]
    fn test_get_btc_payment_address() {
        let mut sce = get_test_sce();
        let address = Address::from_str("1DTFRJ2XFb4AGP1Tfk54iZK1q2pPfK4n3h").unwrap();
        let address_clone = address.clone();
        sce.bitcoin_client()?.expect_get_new_address().return_once(move |_,_| Ok(address_clone));
        let _address: Address = sce.get_btc_payment_address(&Uuid::new_v4()).unwrap();
    }

    #[test]
    fn test_get_lightning_invoice() {
        let mut sce = get_test_sce();
        let invoice_expected = clightningrpc::responses::Invoice {
            payment_hash: String::from("0001020304050607080900010203040506070809000102030405060708090102"),
            expires_at: 604800,
            bolt11: String::from("lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl\
2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcws\
pyetp5h2tztugp9lfyql")
        };
        let invoice_expected_db : Invoice = invoice_expected.clone().into();
        sce.lightning_client()?.expect_invoice().return_once(move |_,_,_,_| Ok(invoice_expected.clone())); 
        let value = 123;
        let invoice: Invoice = sce.get_lightning_invoice(&Uuid::new_v4(), &value).unwrap().into();
        assert_eq!(invoice, invoice_expected_db);
    }

    #[test]
    fn test_pod_token_verify_unknown() {
        let mut sce = get_test_sce();
        let id = Uuid::from_fields(0, 1, 2, &[0,1,2,3,4,5,6,7]).unwrap();
        let id_clone = id.clone();
        sce.database.expect_get_pay_on_demand_status().
            return_once(move |&id_clone| 
                return Err(SEError::DBError(DBErrorType::NoDataForID, id_clone.to_string()))
            );
        let result = sce.pod_token_verify(&id);
        assert_eq!(result, Err(SEError::DBError(DBErrorType::NoDataForID, id.to_string())));
    }

    #[test]
    fn test_pod_token_verify_unpaid() {
        let mut sce = get_test_sce();
             let id = Uuid::from_fields(0, 1, 2, &[0,1,2,3,4,5,6,7]).unwrap();
        let id_clone = id.clone();
        sce.database.expect_get_pay_on_demand_status().
            return_once(|_| 
                Ok(
                    PODStatus {
                        confirmed: false,
                        spent: false
                    }
                )                    
            );
        sce.database.expect_get_pay_on_demand_info().returning(|_| Ok(
            PODInfo {
                lightning_invoice: Invoice {
                    payment_hash: String::from("0001020304050607080900010203040506070809000102030405060708090102"),
                    expires_at: 604800,
                    bolt11: String::from("lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl\
2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcws\
pyetp5h2tztugp9lfyql"),
                },
                btc_payment_address: Address::from_str("1DTFRJ2XFb4AGP1Tfk54iZK1q2pPfK4n3h").unwrap(),
                value: 1000
            }
        ));
        sce.lightning_client()?.expect_waitinvoice().returning(move |_| 
            Ok(responses::WaitInvoice {
            label: id_clone.to_string(),
            bolt11: String::from("lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl\
2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcws\
pyetp5h2tztugp9lfyql"),
            payment_hash: String::from("0001020304050607080900010203040506070809000102030405060708090102"),
            amount_msat: Some(MSat(1000)),
            status: String::from("paid"),
            pay_index: Some(0),
            amount_received_msat: Some(MSat(1000)),
            paid_at: Some(11111234),
            payment_preimage: Some(String::from("hdu8fhsafuhasfuahdu8fhsafuhasfuahdu8fhsafuhasfuahdu8fhsafuhasfua")),
            description: Some(id_clone.to_string()),
            expires_at: 9999999999999,
        })
        );
        let result = sce.pod_token_verify(&id);
        assert_eq!(result, Err(SEError::DBError(DBErrorType::NoDataForID, id.to_string())));
    }

    #[test]
    fn test_pod_token_verify_paid_lightning() {
        let mut sce = get_test_sce();
        //sce.
    }

    #[test]
    fn test_pod_token_verify_paid_btc() {
        let mut sce = get_test_sce();
        //sce.
    }

    #[test]
    fn test_pod_token_verify_unpaid_btc() {
        let mut sce = get_test_sce();
        //sce.
    }
       
}


 