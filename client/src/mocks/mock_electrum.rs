// Electrum server http RESTful API interface

use crate::wallet::wallet::{ GetWalletBalanceResponse, GetListUnspentResponse };

pub struct MockElectrum {}

impl MockElectrum {
    pub fn new() -> MockElectrum {
        MockElectrum{}
    }

    pub fn get_balance(&self, addr: &str) -> Result<GetWalletBalanceResponse,()> {
        if addr == "bcrt1qghtup486tj8vgz2l5pkh8hqw8wzdudraa6hnzs".to_string() {
            return Ok(GetWalletBalanceResponse{unconfirmed: 0, confirmed: 10});
        }

        if addr == "bcrt1qsuqsurhgfduhqw6ejquw54482sqpkfc22gytyh".to_string() {
            return Ok(GetWalletBalanceResponse{unconfirmed: 0, confirmed: 100000});
        }
        Ok(GetWalletBalanceResponse{unconfirmed: 0, confirmed: 0})
    }

    pub fn get_list_unspent(&self, addr: &str) -> Result<Vec<GetListUnspentResponse>,()> {
        if addr == "bcrt1qghtup486tj8vgz2l5pkh8hqw8wzdudraa6hnzs".to_string() {
            return Ok(vec!(
                GetListUnspentResponse{
                    height: 123,
                    tx_hash: "e0a97cb38e7e73617ef75a57eaf2841eb06833407c0eae08029bd04ea7e6115a".to_string(),
                    tx_pos: 0,
                    value: 100,
                    address: addr.to_string(),
                }));
        }
        if addr == "bcrt1qsuqsurhgfduhqw6ejquw54482sqpkfc22gytyh".to_string() {
            return Ok(vec!(
                GetListUnspentResponse{
                    height: 1234,
                    tx_hash: "40bf39ffdf4322e4d30ed783feec5bd9eb2804b81f23ebd5e24ea2aa2365a326".to_string(),
                    tx_pos: 1,
                    value: 100000000,
                    address: addr.to_string(),
                }))
        }
        Ok(vec!())
    }
}
