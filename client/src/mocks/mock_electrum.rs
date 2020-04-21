// Electrum server http RESTful API interface

use crate::wallet::wallet::{ GetWalletBalanceResponse, GetListUnspentResponse };

pub struct MockElectrum {}

impl MockElectrum {
    pub fn new() -> MockElectrum {
        MockElectrum{}
    }

    pub fn get_balance(&self, addr: &str) -> Result<GetWalletBalanceResponse,()> {
        if addr == "bcrt1qjjwk2rk7nuxt6c79tsxthf5rpnky0sdhjr493x".to_string() {
            return Ok(GetWalletBalanceResponse{unconfirmed: 0, confirmed: 5});
        }
        Ok(GetWalletBalanceResponse{unconfirmed: 0, confirmed: 0})
    }
    
    pub fn get_list_unspent(&self, addr: &str) -> Result<Vec<GetListUnspentResponse>,()> {
        if addr == "bcrt1qjjwk2rk7nuxt6c79tsxthf5rpnky0sdhjr493x".to_string() {
            return Ok(vec!(
                GetListUnspentResponse{
                    height: 123,
                    tx_hash: "tx hash".to_string(),
                    tx_pos: 1,
                    value: 10,
                    address: addr.to_string(),
                }));
        }
        return Ok(vec!(
            GetListUnspentResponse{
                height: 123,
                tx_hash: "tx hash".to_string(),
                tx_pos: 1,
                value: 10,
                address: addr.to_string(),
            },
            GetListUnspentResponse{
                height: 123,
                tx_hash: "tx hash 2".to_string(),
                tx_pos: 1,
                value: 100000,
                address: addr.to_string(),
            }))
    }
}
