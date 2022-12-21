//! LightningClientFactory
//!
//! Re-exports and instantiates a mock or real lighting client struct, depending on crate config

use crate::Result;
use cfg_if::cfg_if;

pub struct LightningClientFactory {}
pub use shared_lib::mocks::mock_ln_rpc_client::MockLightningRPC;

#[allow(dead_code)]
fn set_expectations(client: &mut MockLightningRPC) {
    cfg_if!{         
            if #[cfg(feature="mocklightningrpc", not(test))]{
                client.expect_invoice().returning(move |_,_,_,_|
                    Ok(mock_constants::invoice())
                );

                client.expect_waitinvoice()
                .returning(move |id_str| Ok(mock_constants::paid(id_str)));
            }
    }
}

cfg_if!{
    if #[cfg(any(test,feature="mocklightningrpc"))]{
        pub use MockLightningRPC as LightningClient;

        impl LightningClientFactory {
            pub fn create(_rpc_path: &String) -> Result<LightningClient> {
                let mut client = LightningClient::default();
                //Don't set default expectations for unit tests
                set_expectations(&mut client);    
                Ok(client)
            }
        }
    } else {
        pub use clightningrpc::LightningRPC as LightningClient;
        impl LightningClientFactory {
            pub fn create(_rpc_path: &String) -> Result<LightningClient> {
                let client = LightningClient::new(&String::default());
                client.getinfo().map_err(|e| crate::error::SEError::from(e))?;
                Ok(client)
            }
        }
    }
}

pub mod mock_constants {
    use clightningrpc::{common::MSat, responses::{Invoice, WaitInvoice}};

    pub fn invoice_amount() -> bitcoin::Amount {
        bitcoin::Amount::from_sat(1234)
    }

    pub fn invoice() -> Invoice {
        Invoice{
            payment_hash: String::from("0001020304050607080900010203040506070809000102030405060708090102"),
            expires_at: 604800,
            bolt11: String::from("lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql")
        }
    }

    pub fn waiting(id: &str) -> WaitInvoice {
        WaitInvoice {
            label: id.to_string(),
            bolt11: String::from("lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl\
2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcws\
pyetp5h2tztugp9lfyql"),
            payment_hash: String::from("0001020304050607080900010203040506070809000102030405060708090102"),
            amount_msat: Some(MSat(invoice_amount().as_sat()*1000)),
            status: String::from(""),
            pay_index: Some(0),
            amount_received_msat: Some(MSat(invoice_amount().as_sat()*1000)),
            paid_at: Some(11111234),
            payment_preimage: Some(String::from("hdu8fhsafuhasfuahdu8fhsafuhasfuahdu8fhsafuhasfuahdu8fhsafuhasfua")),
            description: Some(id.to_string()),
            expires_at: 9999999999999,
        }
    }

    pub fn paid(id: &str) -> WaitInvoice {
        let mut resp = waiting(id);
        resp.status = String::from("paid");
        resp
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create() {
        let _rpc: LightningClient = LightningClientFactory::create(&String::default()).unwrap();
    }    
}
