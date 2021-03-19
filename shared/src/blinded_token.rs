//! Blind token
//!
//! Sign blinded message and verify that the signature is valid for the unblinded message.
//! Following

//! Based on work:
//! Blind Signature Scheme Based on Elliptic Curve Cryptography
//! Chwei-Shyong Tsai, Min-Shiang Hwang, Pei-Chen Sung
//! Department of Management Information System,National Chung Hsin
//! https://pdfs.semanticscholar.org/e58a/1713858a5b9355a9e18adfe3abfc05de244e.pdf

use super::Result;
use bitcoin::hashes::{sha256d, Hash};
use curv_client::{
    arithmetic::traits::Converter,
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use uuid::Uuid;
use rocket_okapi::JsonSchema;
use schemars;
use crate::swap_data::SwapToken;

// Notation:
//  x: Signer Priv key
//  q: Sign Pub key
//  k: Sign random
//  u,v: Requester randoms
//  m: Message
//  p: Generator point
// H(.): Hash function

// Protocol:
//  Signer generates
//      r' = kp

//  Requester calculates
//      r = ur' + vp,
//      e = H(r||m)
//      e' = e/u

//  Sender calculates
//      s' = xe'+k

// Requester calculates
//      s = s'u+v
// And verifies
//      sp=eq+r

#[derive(JsonSchema)]
#[schemars(remote = "FE")]
pub struct FEDef(Vec<u8>);

#[derive(JsonSchema)]
#[schemars(remote = "GE")]
pub struct GEDef(Vec<u8>);

/// blind spend signature
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct BlindedSpendSignature {
    #[schemars(with = "FEDef")]
    s_prime: FE,
}
impl Default for BlindedSpendSignature {
    fn default() -> Self {
        BlindedSpendSignature {
            s_prime: FE::zero(),
        }
    }
}

/// (s,r) blind spend token
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct BlindedSpendToken {
    #[schemars(with = "FEDef")]
    s: FE,
    #[schemars(with = "GEDef")]
    r: GE,
    m: String,
}
impl Default for BlindedSpendToken {
    fn default() -> Self {
        BlindedSpendToken {
            s: FE::zero(),
            r: GE::generator(),
            m: String::default(),
        }
    }
}
impl BlindedSpendToken {
    pub fn new_random() -> Self {
        BlindedSpendToken {
            s: FE::new_random(),
            r: GE::random_point(),
            m: String::default(),
        }
    }
    pub fn get_msg(&self) -> String {
        self.m.to_owned()
    }
    pub fn set_msg(&mut self, msg: String) {
        self.m = msg
    }
}

/// Blind Spend Token data for each Swap. (priv, pub) keypair, k and R' value for signing and verification.
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct BSTSenderData {
    #[schemars(with = "FEDef")]
    x: FE,
    #[schemars(with = "GEDef")]
    q: GE,
    #[schemars(with = "FEDef")]
    k: FE,
    #[schemars(with = "GEDef")]
    r_prime: GE,
}
impl BSTSenderData {
    /// Generate new BSTSenderData for Swap
    pub fn setup() -> Self {
        let p: GE = ECPoint::generator(); // gen
        let x = FE::new_random(); // priv
        let q = p * x; //pub
        let (k, r_prime) = signer_gen_r_prime();
        let result = BSTSenderData { x, q, k, r_prime };
        result
    }

    pub fn get_r_prime(&self) -> GE {
        self.r_prime
    }

    /// Create a blind signature for some e_prime value
    pub fn gen_blind_signature(&self, e_prime: FE) -> BlindedSpendSignature {
        BlindedSpendSignature {
            s_prime: sender_calc_s_prime(self.x, e_prime, self.k),
        }
    }

    /// Verify blind spend token
    pub fn verify_blind_spend_token(&self, token: BlindedSpendToken) -> Result<bool> {
        verify_blind_sig(token.s, &token.m, self.q, token.r)
    }
}

/// Blind Spend Token data for each Swap. (priv, pub) keypair, k and R' value for signing and verification.
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct BSTRequestorData {
    #[schemars(with = "FEDef")]
    u: FE,
    #[schemars(with = "FEDef")]
    v: FE,
    #[schemars(with = "GEDef")]
    r: GE,
    #[schemars(with = "FEDef")]
    e_prime: FE,
    m: String,
}
impl BSTRequestorData {
    /// Generate new BSTRequestorData with senders r_prime value and a message m
    pub fn setup(r_prime: GE, m: &String) -> Result<Self> {
        let (u, v, r, e_prime) = requester_calc_e_prime(r_prime, &m)?;
        Ok(BSTRequestorData {
            u,
            v,
            r,
            e_prime,
            m: m.to_owned(),
        })
    }

    pub fn get_e_prime(&self) -> FE {
        self.e_prime
    }

    /// Unblind blind spend token signature
    pub fn unblind_signature(&self, signature: BlindedSpendSignature) -> FE {
        requester_calc_s(signature.s_prime, self.u, self.v)
    }

    /// Create BlindedSpendToken for blinded signature
    pub fn make_blind_spend_token(&self, s: FE) -> BlindedSpendToken {
        BlindedSpendToken {
            s,
            r: self.r,
            m: self.m.clone(),
        }
    }
}

///  Signer generates
///      r' = kp
pub fn signer_gen_r_prime() -> (FE, GE) {
    let k: FE = FE::new_random();
    let p: GE = ECPoint::generator();
    (k, p * k)
}

fn calc_e(r: GE, m: &String) -> Result<FE> {
    let mut data_vec = m.as_bytes().iter().cloned().collect::<Vec<u8>>();
    let mut r_vec = serde_json::to_string(&r)?
        .as_bytes()
        .iter()
        .cloned()
        .collect::<Vec<u8>>();
    data_vec.append(&mut r_vec);
    let e = sha256d::Hash::hash(&data_vec);
    let hex = hex::encode(e);
    let big_int = BigInt::from_hex(&hex);
    Ok(ECScalar::from(&big_int))
}

///  Requester calculates
///      r = ur' + vp,
///      e = H(r||m)
///      e' = e/u
pub fn requester_calc_e_prime(r_prime: GE, m: &String) -> Result<(FE, FE, GE, FE)> {
    let u: FE = FE::new_random();
    let v: FE = FE::new_random();
    let p: GE = ECPoint::generator();

    let r: GE = r_prime * u + p * v;

    let e = calc_e(r, m)?;

    let e_prime = e * u.invert();
    Ok((u, v, r, e_prime))
}

///  Sender calculates
///      s' = xe'+k
pub fn sender_calc_s_prime(x: FE, e_prime: FE, k: FE) -> FE {
    x * e_prime + k
}

/// Requester calculates
///      s = s'u+v
pub fn requester_calc_s(s_prime: FE, u: FE, v: FE) -> FE {
    s_prime * u + v
}

/// Verify sig
///      sp=eq+r
pub fn verify_blind_sig(s: FE, m: &String, q: GE, r: GE) -> Result<bool> {
    let p: GE = ECPoint::generator();
    let e = calc_e(r, m)?;
    let sp = p * s;
    let eq_plus_r = q * e + r;
    if sp == eq_plus_r {
        return Ok(true);
    }
    Ok(false)
}

/// Struct serialized to string to be used as Blind sign token message
#[derive(Serialize, Deserialize, Debug)]
pub struct BlindedSpentTokenMessage {
    pub swap_id: String,
    pub nonce: String,
}
impl BlindedSpentTokenMessage {
    pub fn new(swap_id: Uuid) -> Self {
        let nonce = Uuid::new_v4().to_string();
        BlindedSpentTokenMessage {
            swap_id: swap_id.to_string(),
            nonce,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    static BST_SENDER_DATA: &str = "{\"x\":\"a69ee11dd94ebb7d45194c5fc5b0f001b6836894aaf93e0c1a85bad88280a5bc\",\"q\":{\"x\":\"41fc72226373d61df5fa0aabcd257d9f65e54b42906fe2871de406cacb675594\",\"y\":\"f57b5133122a7a8066fd956a32df9c1f9959df3079dbfa980512c91c5d7cd160\"},\"k\":\"73098242f2b18a70a7d91aa27cf959ca88a56b3fd9493b651f7f94771ee10e90\",\"r_prime\":{\"x\":\"cde12c788fa16a0235ac148353bc4469edfd0f8e417b00eb66c18b83dff53f0f\",\"y\":\"e280715e647dcd3e0e4d390ca2098035e955796aeb50f335ddd7e20bff334942\"}}";
    static SWAP_TOKEN: &str = "{\"id\":\"00000000-0000-0000-0000-000000000001\",\"amount\":100,\"time_out\":1000,\"statechain_ids\":[\"00000000-0000-0000-0000-000000000001\",\"00000000-0000-0000-0000-000000000002\",\"00000000-0000-0000-0000-000000000003\"]}";  
    static SECRET_KEY: &[u8;32] = &[1;32];

    #[test]
    fn test_bst_sender_data() {
        //let data = BSTSenderData::setup();
        //let data_str = serde_json::to_string(&data).unwrap();
        let bst_sender: BSTSenderData = serde_json::from_str(BST_SENDER_DATA).unwrap();
        //println!("bst sender data: {}", data_str);

        let swap_token : SwapToken = serde_json::from_str(SWAP_TOKEN).unwrap();

        //Requester
        let m = serde_json::to_string(&BlindedSpentTokenMessage::new(swap_token.id)).unwrap();
        println!("BSTMsg: {}", m);

        let bst_requestor = BSTRequestorData::setup(bst_sender.get_r_prime(),&m).unwrap();
        
        let req_data_str = serde_json::to_string(&bst_requestor).unwrap();

        println!("bst requestor data: {}", req_data_str);

        let blind_sig = bst_sender.gen_blind_signature(bst_requestor.get_e_prime());

        let blind_sig_str = serde_json::to_string(&blind_sig).unwrap();

        println!("blind sig: {}", blind_sig_str);

        let unblind_sig = bst_requestor.unblind_signature(blind_sig);

        let unblind_sig_str = serde_json::to_string(&unblind_sig).unwrap();

        println!("unblind sig: {}", unblind_sig_str);

        let blind_spend_token = bst_requestor.make_blind_spend_token(unblind_sig);

        let blind_spend_token_str = serde_json::to_string(&blind_spend_token).unwrap();

        println!("blind spend token: {}", blind_spend_token_str);
        
        assert!(bst_sender.verify_blind_spend_token(&blind_spend_token).unwrap())

    }
}
