// Mock bitcoin-rpc interface

pub struct MockClient {}

impl MockClient {
    pub fn new() -> MockClient {
        MockClient {}
    }
    pub fn get_block_count() -> std::result::Result<u64,()> {
        todo!()
     }
    pub fn send_raw_transaction(_raw_tx: &str) -> Result<String,()> {
        todo!()
    }
}
