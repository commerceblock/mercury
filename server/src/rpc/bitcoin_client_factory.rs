//! BitcoinClientFactory
//!
//! Re-exports and instantiates a mock/real bitcoin client struct depending on crate config

use crate::Result;
use cfg_if::cfg_if;
pub use shared_lib::mocks::mock_rpc_client::MockClient;

pub struct BitcoinClientFactory {}
                    
       #[allow(dead_code)]
       fn set_expectations(client: &mut MockClient) {
            cfg_if!{   
                if #[cfg(feature="mockbitcoinrpc", not(test))]{
                    client.expect_get_new_address().returning(move |_,_|
                        Ok(mock_constants::address())
                    );
                    client.expect_get_received_by_address()
                    .returning(|_, _| Ok(bitcoin::Amount::from_sat(0)));
                }
            }
        }

cfg_if!{
    if #[cfg(any(test,feature="mockbitcoinrpc"))]{
        pub use MockClient as BitcoinClient;
        pub use shared_lib::mocks::mock_rpc_client::RpcApi as BitcoinRpcApi;

        impl BitcoinClientFactory {
            pub fn create(_rpc_path: &String) -> Result<BitcoinClient> {
                let mut client = BitcoinClient::new();
                //Don't set default expectations for unit tests
                set_expectations(&mut client);             
                Ok(client)
            }
        }
    } else {
        pub use bitcoincore_rpc::Client as BitcoinClient;
        pub use bitcoincore_rpc::RpcApi as BitcoinRpcApi;
        use bitcoincore_rpc::Auth as BitcoinAuth;
        impl BitcoinClientFactory {
            pub fn create(rpc_path: &String) -> Result<BitcoinClient> {
                let rpc_path_parts: Vec<&str> = rpc_path.split('@').collect();
                if rpc_path_parts.len() != 2 {
                    panic!("Invalid bitcoind RPC path")
                };
                let rpc_cred: Vec<&str> = rpc_path_parts[0].split(':').collect();
                if rpc_cred.len() != 2 {
                    panic!("Invalid bitcoind RPC credentials")
                };
                let auth = BitcoinAuth::UserPass(rpc_cred[0].to_string(),
                                rpc_cred[1].to_string());

                Ok(BitcoinClient::new(rpc_path_parts[1].to_string(),
                    auth)?.into())
            }
        }
    }
}

pub mod mock_constants {
    use bitcoin::util::address::Address;
    use std::str::FromStr;

    pub fn address() -> Address {
        Address::from_str("tb1qmfrhnm4ke95e3t6grqs99w8qjxylqdhelecvwc").unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create() {
        let _rpc: BitcoinClient = BitcoinClientFactory::create(&String::default()).unwrap();
    }    
}
