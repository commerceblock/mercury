//! Blind token
//!
//! Sign blinded message and verify that the signature is valid for the unblinded message.
//! Following

use super::Result;
use bitcoin::hashes::{sha256d, Hash};
use curv::{GE, elliptic::curves::traits::{ECPoint, ECScalar}, FE, BigInt, arithmetic::traits::Converter};

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

// pub type GE = Secp256k1Point;
// pub type FE = Secp256k1Scalar;

///  Signer generates
///      r' = kp
pub fn signer_gen_r_prime() -> (FE, GE) {
    let k: FE = FE::new_random();
    let p: GE = ECPoint::generator();
    (k, p*k)
}


fn calc_e(r: GE, m: &String) -> Result<FE> {
    let mut data_vec = m.as_bytes().iter().cloned().collect::<Vec<u8>>();
    let mut r_vec = serde_json::to_string(&r)?.as_bytes().iter().cloned().collect::<Vec<u8>>();
    data_vec.append(&mut r_vec);
    let e = sha256d::Hash::hash(&data_vec);
    let hex = hex::encode(e);
    let big_int = BigInt::from_hex(&hex);
    Ok(curv::elliptic::curves::traits::ECScalar::from(&big_int))
}

///  Requester calculates
///      r = ur' + vp,
///      e = H(r||m)
///      e' = e/u
pub fn requester_calc_e_prime(r_prime: GE, m: &String) -> Result<(FE, FE, GE, FE)> {
    let u: FE = FE::new_random();
    let v: FE = FE::new_random();
    let p: GE = ECPoint::generator();

    let r: GE = r_prime*u + p*v;

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
    let sp = p*s;
    let eq_plus_r = q*e + r;
    if sp == eq_plus_r {
        return Ok(true);
    }
    Ok(false)
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_blind_sign() {
        // Sender init vars for BST
        let p: GE = ECPoint::generator(); // gen
        let x = FE::new_random(); // priv
        let q = p*x; //pub
        let (k, r_prime) = signer_gen_r_prime();

        let m = "swap ID".to_string();

        // Requester setup BST generation
        let (u, v, r, e_prime) = requester_calc_e_prime(r_prime, &m).unwrap();

        // Sender create BST
        let s_prime = sender_calc_s_prime(x, e_prime, k);

        // Requester unblind
        let s = requester_calc_s(s_prime, u, v);

        // Sender verify
        assert!(verify_blind_sig(s, &m, q, r).unwrap());
    }
}
