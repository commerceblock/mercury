//! LightningClientFactory
//!
//! Re-exports and instantiates a mock or real lighting client struct, depending on crate config

use crate::Result;
use crate::error::SEError;
use cfg_if::cfg_if;

pub struct LightningClientFactory {}

cfg_if!{
    if #[cfg(any(test,feature="mocklightningrpc"))]{
        pub use shared_lib::mocks::mock_ln_rpc_client::MockLightningRPC as LightningClient;
        impl LightningClientFactory {
            pub fn create(_rpc_path: &String) -> Result<LightningClient> {
                let client = LightningClient::default();
                Ok(client)
            }
        }
    } else {
        pub use clightningrpc::LightningRPC as LightningClient;
        impl LightningClientFactory {
            pub fn create(_rpc_path: &String) -> Result<LightningClient> {
                let client = LightningClient::new(&String::default());
                client.getinfo().map_err(|e| SEError::from(e))?;
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
