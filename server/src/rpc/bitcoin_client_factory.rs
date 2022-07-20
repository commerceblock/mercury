//! BitcoinClientFactory
//!
//! Re-exports and instantiates a mock/real bitcoin client struct depending on crate config

use crate::Result;
use cfg_if::cfg_if;

pub struct BitcoinClientFactory {}

cfg_if!{
    if #[cfg(any(test,feature="mockbitcoinrpc"))]{
        pub use shared_lib::mocks::mock_rpc_client::MockClient as BitcoinClient;
        pub use shared_lib::mocks::mock_rpc_client::RpcApi as BitcoinRpcApi;
        //use shared_lib::mocks::mock_rpc_client::Auth as BitcoinAuth;
        impl BitcoinClientFactory {
            pub fn create(rpc_path: &String) -> Result<BitcoinClient> {
                Ok(BitcoinClient::new())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create() {
        let _rpc: BitcoinClient = BitcoinClientFactory::create(&String::default()).unwrap();
    }    
}
