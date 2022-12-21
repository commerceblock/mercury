// Mock bitcoin-rpc interface
use clightningrpc::responses;
use clightningrpc::common::MSat;
use clightningrpc_common::errors::Error;
use mockall::automock;

extern crate hex;

// Dummy client
#[derive(Debug)]
pub struct Client {}

pub struct LightningRPC {
    #[allow(dead_code)]
    client: Client
}

#[automock]
impl LightningRPC {
    pub fn new(_sockpath: &str) -> LightningRPC {
        LightningRPC { client: Client{} }
    }

    /// Create an invoice for {msatoshi} with {label} and {description} with
    /// optional {expiry} seconds (default 1 hour).
    pub fn invoice(
        &self,
        _msatoshi: u64,
        _label: &str,
        _description: &str,
        _expiry: Option<u64>,
    ) -> Result<responses::Invoice, Error> {
        let invoice = responses::Invoice {
            payment_hash: String::from("0001020304050607080900010203040506070809000102030405060708090102"),
            expires_at: 604800,
            bolt11: String::from("lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl\
2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcws\
pyetp5h2tztugp9lfyql"),
        };
        Ok(invoice)
    }

    /// Wait for an incoming payment matching the invoice with {label}.
    pub fn waitinvoice(&self, label: &str) -> Result<responses::WaitInvoice, Error> {
        let response = responses::WaitInvoice {
            label: String::from(label),
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
            description: Some(String::from(label)),
            expires_at: 9999999999999,
        };
        Ok(response)
    }
}

