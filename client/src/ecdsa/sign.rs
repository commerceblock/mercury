use std::cmp;

use super::super::utilities::requests;
use super::super::ClientShim;
use super::super::Result;
use bitcoin::secp256k1::Signature;
use curv::FE;
use curv::arithmetic::traits::Converter;
use curv::arithmetic::traits::Modulo;
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one;
use shared_lib::structs::BlindedSignMsg2;
use shared_lib::structs::BlindedSignReply;
use shared_lib::structs::BlindedSignSecondMsgRequest;
use shared_lib::structs::{Protocol, SignMsg1, SignMsg2, SignSecondMsgRequest, SignReply1};

use curv::BigInt;
use kms::ecdsa::two_party::MasterKey2;
use uuid::Uuid;

/// Co-sign message with shared key
pub fn sign(
    client_shim: &ClientShim,
    message: BigInt,
    mk: &MasterKey2,
    protocol: Protocol,
    shared_key_id: &Uuid,
) -> Result<Vec<Vec<u8>>> {
    let (eph_key_gen_first_message_party_two, eph_comm_witness, eph_ec_key_pair_party2) =
        MasterKey2::sign_first_message();

    let sign_msg1 = SignMsg1 {
        shared_key_id: *shared_key_id,
        eph_key_gen_first_message_party_two,
    };
    let sign_party_one_first_message: SignReply1 =
        requests::postb(client_shim, &format!("ecdsa/sign/first"), &sign_msg1)?;

    let party_two_sign_message = mk.sign_second_message(
        &eph_ec_key_pair_party2,
        eph_comm_witness.clone(),
        &sign_party_one_first_message.msg,
        &message,
    );

    let sign_msg2 = SignMsg2 {
        shared_key_id: *shared_key_id,
        sign_second_msg_request: SignSecondMsgRequest {
            protocol,
            message,
            party_two_sign_message,
        },
    };

    let signature = requests::postb::<&SignMsg2, Vec<Vec<u8>>>(
        client_shim,
        &format!("ecdsa/sign/second",),
        &sign_msg2,
    )?;

    Ok(signature)
}

pub fn blinded_sign(
    client_shim: &ClientShim,
    message: BigInt,
    mk: &MasterKey2,
    protocol: Protocol,
    shared_key_id: &Uuid,
) ->  Result<Vec<Vec<u8>>> {
    let (eph_key_gen_first_message_party_two, eph_comm_witness, eph_ec_key_pair_party2) =
        MasterKey2::sign_first_message();

    let sign_msg1 = SignMsg1 {
        shared_key_id: *shared_key_id,
        eph_key_gen_first_message_party_two,
    };
    let sign_party_one_first_message: SignReply1 =
        requests::postb(client_shim, &format!("ecdsa/sign/first"), &sign_msg1)?;

    let blinding_factor: FE = ECScalar::new_random();
    let inv_blinding_factor = blinding_factor.invert();

    let party_two_sign_message = mk.sign_second_message_with_blinding_factor(
        &eph_ec_key_pair_party2,
        eph_comm_witness.clone(),
        &sign_party_one_first_message.msg,
        &message,
        &blinding_factor.to_big_int(),
    );

    let r_signature = party_two_sign_message.partial_sig.r.clone();

    let sign_msg2 = BlindedSignMsg2 {
        shared_key_id: *shared_key_id,
        sign_second_msg_request: BlindedSignSecondMsgRequest {
            protocol,
            message: message.clone(),
            party_two_sign_message,
        },
    };

    let blinded_signature = requests::postb::<&BlindedSignMsg2, BlindedSignReply>(
        client_shim,
        &format!("ecdsa/blinded_sign/second",),
        &sign_msg2,
    )?;

    let q = FE::q();

    let unblinded_signature_s1 = BigInt::mod_mul(&blinded_signature.blinded_s, &inv_blinding_factor.to_big_int(), &q);

    let unblinded_message_s = cmp::min(
        unblinded_signature_s1.clone(),
        FE::q() - unblinded_signature_s1,
    );

    let signature = party_one::Signature {
        r: r_signature,
        s: unblinded_message_s,
    };

    let pubkey = mk.public.q;

    let verify = party_one::verify(&signature, &pubkey, &message).is_ok();
    assert!(verify);

    let ws: Vec<Vec<u8>>;

    // Make signature witness
    let mut r_vec = BigInt::to_vec(&signature.r);
    if r_vec.len() != 32 {
        // Check corrcet length of conversion to Signature
        let mut temp = vec![0; 32 - r_vec.len()];
        temp.extend(r_vec);
        r_vec = temp;
    }
    let mut s_vec = BigInt::to_vec(&signature.s);
    if s_vec.len() != 32 {
        // Check corrcet length of conversion to Signature
        let mut temp = vec![0; 32 - s_vec.len()];
        temp.extend(s_vec);
        s_vec = temp;
    }
    let mut v = r_vec;
    v.extend(s_vec);
    let mut sig_vec = Signature::from_compact(&v[..])?.serialize_der().to_vec();
    sig_vec.push(01);
    //let pk_vec = ssi.shared_key.public.q.get_element().serialize().to_vec();
    let pk_vec = pubkey.get_element().serialize().to_vec();
    let witness = vec![sig_vec, pk_vec];
    ws = witness;

    Ok(ws)
}

// use super::super::utilities::error_to_c_string;
// // iOS bindings
// use std::ffi::{CStr, CString};
// use std::os::raw::c_char;
//
// #[no_mangle]
// pub extern "C" fn sign_message(
//     c_endpoint: *const c_char,
//     c_auth_token: *const c_char,
//     c_message_le_hex: *const c_char,
//     c_master_key_json: *const c_char,
//     c_x_pos: i32,
//     c_y_pos: i32,
//     c_id: *const c_char,
// ) -> *mut c_char {
//     let raw_endpoint = unsafe { CStr::from_ptr(c_endpoint) };
//     let endpoint = match raw_endpoint.to_str() {
//         Ok(s) => s,
//         Err(e) => return error_to_c_string(format_err!("decoding raw endpoint failed: {}", e))
//     };
//
//     let raw_auth_token = unsafe { CStr::from_ptr(c_auth_token) };
//     let auth_token = match raw_auth_token.to_str() {
//         Ok(s) => s,
//         Err(e) => return error_to_c_string(format_err!("decoding raw auth_token failed: {}", e))
//     };
//
//     let raw_message_hex = unsafe { CStr::from_ptr(c_message_le_hex) };
//     let message_hex = match raw_message_hex.to_str() {
//         Ok(s) => s,
//         Err(e) => return error_to_c_string(format_err!("decoding raw message_hex failed: {}", e))
//     };
//
//     let raw_master_key_json = unsafe { CStr::from_ptr(c_master_key_json) };
//     let master_key_json = match raw_master_key_json.to_str() {
//         Ok(s) => s,
//         Err(e) => return error_to_c_string(format_err!("decoding raw master_key_json failed: {}", e))
//     };
//
//     let raw_id = unsafe { CStr::from_ptr(c_id) };
//     let id = match raw_id.to_str() {
//         Ok(s) => s,
//         Err(e) => return error_to_c_string(format_err!("decoding raw id failed: {}", e))
//     };
//
//     let x: BigInt = BigInt::from(c_x_pos);
//
//     let y: BigInt = BigInt::from(c_y_pos);
//
//     let client_shim = ClientShim::new(endpoint.to_string(), Some(auth_token.to_string()));
//
//     let mk: MasterKey2 = serde_json::from_str(master_key_json).unwrap();
//
//     let mk_child: MasterKey2 = mk.get_child(vec![x.clone(), y.clone()]);
//
//     let message: BigInt = serde_json::from_str(message_hex).unwrap();
//
//     let sig = match sign(
//         &client_shim,
//         message,
//         &mk_child,
//         x,
//         y,
//         &id.to_string(),
//     ) {
//         Ok(s) => s,
//         Err(e) => return error_to_c_string(format_err!("signing to endpoint {} failed: {}", endpoint, e))
//     };
//
//     let signature_json = match serde_json::to_string(&sig) {
//         Ok(share) => share,
//         Err(e) => return error_to_c_string(format_err!("signing to endpoint {} failed: {}", endpoint, e)),
//     };
//
//     CString::new(signature_json.to_owned()).unwrap().into_raw()
// }
