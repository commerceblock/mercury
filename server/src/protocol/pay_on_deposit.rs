//! StateEntity POD (pay on deposit)
//!
//! StateEntity POD trait and implementation for StateChainEntity.

pub use super::super::Result;
extern crate shared_lib;
use crate::error::SEError;
use crate::protocol::util::RateLimiter;
use crate::server::StateChainEntity;
use crate::Database;
use shared_lib::structs::*;

use super::requests::post_cln;
use super::requests::get_cln;

use cfg_if::cfg_if;
use rocket::State;
use rocket_contrib::json::Json;
use rocket_okapi::openapi;
use shared_lib::structs::Invoice;
use uuid::Uuid;
use url::Url;
use std::os::unix::process;
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
    ) -> Result<PODInfo>;

    /// API: Verify a POD token:
    ///     - Return the PODStatus struct for token_id
    fn pod_token_verify(
        &self,
        token_id: &Uuid,
    ) -> Result<PODStatus>;

    fn get_lightning_invoice(
        &self,
        pod_token_id: &Uuid,
    ) -> Result<Invoice>;

    fn query_lightning_payment(
        &self,
        id: &Uuid,
        processor_id: &String,
    ) -> Result<bool>;

}

impl POD for SCE {
    fn pod_token_init(
        &self,
        token_id: Uuid
    ) -> Result<PODInfo> {
        let invoice: Invoice = self
            .get_lightning_invoice(&token_id)?
            .into();
        info!("Invoice {:?}", invoice);
        let btc_payment_address = "null".to_string();
        let pod_info = PODInfo {
            token_id,
            lightning_invoice: invoice.pr,
            btc_payment_address: invoice.onChainAddr,
            processor_id: invoice.id,
        };
        info!("POD info {:?}", pod_info);        
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
        token_id: &Uuid,
    ) -> Result<PODStatus> {
        let database = &self.database;

        fn confirm_payment(
            pod_info: &PODInfo,
            database: &DB,
        ) -> Result<PODStatus> {
            database.set_pay_on_demand_status(
                &pod_info.token_id,
                &PODStatus {
                    confirmed: true,
                },
            )?;
            database.get_pay_on_demand_status(&pod_info.token_id)
        }

        let mut pod_status = self.database.get_pay_on_demand_status(token_id)?;
        if (!pod_status.confirmed) {
            let pod_info = &self.database.get_pay_on_demand_info(token_id)?;

            if self.query_lightning_payment(&token_id, &pod_info.processor_id)? {
                pod_status = confirm_payment(&pod_info, database)?
            }

        }

        Ok(pod_status)
    }

    fn get_lightning_invoice(
        &self,
        pod_token_id: &Uuid,
    ) -> Result<Invoice> {
        let id_str = &pod_token_id.to_string();

        let cln_url: Url = self.cln.endpoint.clone();
        let macaroon = &self.cln.macaroon;
        let path: &str = "checkout";
        let extra: Extra = Extra {
            tag: "invoice-web".to_string(),
        };
        let inv_request: ReqInvoice = ReqInvoice {
            title: pod_token_id.clone().to_string(),
            description: "".to_string(),
            amount: "0.001".to_string(),
            unit: "BTC".to_string(),
            redirectAfterPaid: "".to_string(),
            email: "".to_string(),
            emailLanguage: "en".to_string(),
            onChain: true,
            delay: 1440,
            extra: extra,
        };
        let ret_invoice: RTLInvoice = post_cln(&cln_url, path, &inv_request, &macaroon)?;
        let invoice = Invoice {
            id: ret_invoice.id,
            pr: ret_invoice.pr,
            checkoutUrl: ret_invoice.checkoutUrl,
            onChainAddr: ret_invoice.onChainAddr,
        };
        return Ok(invoice);
    }

    fn query_lightning_payment(
        &self,
        id: &Uuid,
        processor_id: &String,
    ) -> Result<bool> {

        let id_str = &id.to_string();

        let cln_url: Url = self.cln.endpoint.clone();
        let macaroon = &self.cln.macaroon;
        let path: String = "checkout/".to_string() + processor_id;
        let invoice_list: RTLQuery = get_cln(&cln_url, &path, &macaroon)?;
        if(invoice_list.isPaid) {
            return Ok(true)
        } else {
            return Ok(false)
        }
    }

}

#[openapi]
/// # Initialize a pay-on-demand token
#[get("/pod/token/init", format = "json")]
pub fn pod_token_init(sc_entity: State<SCE>) -> Result<Json<PODInfo>> {
    sc_entity.check_rate_slow("pod_token_init")?;
    let token_id = Uuid::new_v4();
    match sc_entity.pod_token_init(token_id) {
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
    match sc_entity.pod_token_verify(&id) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}