//! LightningClientFactory
//!
//! Re-exports and instantiates a mock or real lighting client struct, depending on crate config

use crate::Result;
use cfg_if::cfg_if;

pub struct LightningClientFactory {}

cfg_if!{
    if #[cfg(any(test,feature="mocklightningrpc"))]{
        pub use shared_lib::mocks::mock_ln_rpc_client::MockLightningRPC as LightningClient;

        fn set_expectations(client: &mut LightningClient) {
            let invoice = clightningrpc::responses::Invoice {
                    payment_hash: String::from("0001020304050607080900010203040506070809000102030405060708090102"),
                    expires_at: 0,
                    bolt11: String::from("lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql")
                };
                client.expect_invoice().returning(move |_,_,_,_|
                    Ok(invoice.clone())
                );
        }

        impl LightningClientFactory {
            pub fn create(_rpc_path: &String) -> Result<LightningClient> {
                let mut client = LightningClient::default();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create() {
        let _rpc: LightningClient = LightningClientFactory::create(&String::default()).unwrap();
    }    
}
