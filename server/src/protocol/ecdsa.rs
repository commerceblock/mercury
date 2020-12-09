pub use super::super::Result;

use crate::error::{DBErrorType, SEError};
use crate::Database;
use crate::{server::StateChainEntity, structs::*};
extern crate reqwest;
use shared_lib::{
    structs::{KeyGenMsg1, KeyGenMsg2, Protocol, SignMsg1, SignMsg2},
    util::reverse_hex_str,
};

use bitcoin::{hashes::sha256d, secp256k1::Signature, Transaction};
use cfg_if::cfg_if;
use curv::{
    arithmetic::traits::Converter,
    elliptic::curves::traits::ECPoint,
    {BigInt, FE, GE},
};
pub use kms::ecdsa::two_party::*;
pub use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use rocket::State;
use rocket_contrib::json::Json;
use std::string::ToString;
use uuid::Uuid;
use std::time::Instant;
use floating_duration::TimeFormat;

cfg_if! {
    if #[cfg(any(test,feature="mockdb"))]{
        use crate::MockDatabase;
        use monotree::database::MemoryDB;
        type SCE = StateChainEntity::<MockDatabase, MemoryDB>;
    } else {
        use crate::PGDatabase;
        type SCE = StateChainEntity::<PGDatabase, PGDatabase>;
    }
}

/// 2P-ECDSA protocol trait
pub trait Ecdsa {
    fn master_key(&self, user_id: Uuid) -> Result<()>;

    fn first_message(&self, key_gen_msg1: KeyGenMsg1) -> Result<(Uuid, party_one::KeyGenFirstMsg)>;

    fn second_message(&self, key_gen_msg2: KeyGenMsg2) -> Result<party1::KeyGenParty1Message2>;

    fn sign_first(&self, sign_msg1: SignMsg1) -> Result<party_one::EphKeyGenFirstMsg>;

    fn sign_second(&self, sign_msg2: SignMsg2) -> Result<Vec<Vec<u8>>>;
}

impl Ecdsa for SCE {
    fn master_key(&self, user_id: Uuid) -> Result<()> {
        let db = &self.database;

        let mki = db.get_ecdsa_master_key_input(user_id)?;

        let master_key = MasterKey1::set_master_key(
            &BigInt::from(0),
            mki.party_one_private,
            &mki.comm_witness.public_share,
            &mki.party2_public,
            mki.paillier_key_pair,
        );

        db.update_ecdsa_master(&user_id, master_key)
    }

    fn first_message(&self, key_gen_msg1: KeyGenMsg1) -> Result<(Uuid, party_one::KeyGenFirstMsg)> {
        let user_id = key_gen_msg1.shared_key_id;
        self.check_user_auth(&user_id)?;

        let db = &self.database;

        // Create new entry in ecdsa table if key not already in table.
        match db.get_ecdsa_master(user_id) {
            Ok(data) => match data {
                Some(_) => {
                    return Err(SEError::Generic(format!(
                        "Key Generation already completed for ID {}",
                        user_id
                    )))
                }
                None => {} // Key exists but key gen not complete. Carry on without writing user_id.
            },
            Err(e) => match e {
                SEError::DBError(DBErrorType::NoDataForID, _) =>
                // If no item has ID, create new item
                {
                    let _ = db.init_ecdsa(&user_id)?;
                }
                _ => return Err(e),
            },
        };

        // Generate shared key
        let (key_gen_first_msg, comm_witness, ec_key_pair) =
            if key_gen_msg1.protocol == Protocol::Deposit {
                MasterKey1::key_gen_first_message()
            } else {
                let s2: FE = db.get_ecdsa_s2(user_id)?;
                let theta: FE = db.get_ecdsa_theta(user_id)?;
                MasterKey1::key_gen_first_message_predefined(s2 * theta)
            };

        db.update_keygen_first_msg(&user_id, &key_gen_first_msg, comm_witness, ec_key_pair)?;

        // call lockbox
        if self.config.lockbox.is_empty() == false {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let start = Instant::now();
            let path: &str = "/ecdsa/keygen/first";
            let url = format!("{}{}", self.config.lockbox, path);

            let client = reqwest::blocking::Client::new();
            let result = client.post(&url)
                .json(&key_gen_msg1)
                .send();

            let _response = match result {
                Ok(res) => info!("{} lockbox call status: {}", url.to_string(), res.status() ),
                Err(err) => info!("ERROR: {} lockbox error: {}", url.to_string(), err),
            };
            info!("(req {}, took: {})", path, TimeFormat(start.elapsed()));
        }

        Ok((user_id, key_gen_first_msg))
    }

    fn second_message(&self, key_gen_msg2: KeyGenMsg2) -> Result<party1::KeyGenParty1Message2> {
        let db = &self.database;

        let user_id = key_gen_msg2.shared_key_id;

        let party2_public: GE = key_gen_msg2.dlog_proof.pk.clone();

        let (comm_witness, ec_key_pair) = db.get_ecdsa_witness_keypair(user_id)?;

        let (kg_party_one_second_message, paillier_key_pair, party_one_private): (
            party1::KeyGenParty1Message2,
            party_one::PaillierKeyPair,
            party_one::Party1Private,
        ) = MasterKey1::key_gen_second_message(
            comm_witness,
            &ec_key_pair,
            &key_gen_msg2.dlog_proof,
        );

        db.update_keygen_second_msg(
            &user_id,
            party2_public,
            paillier_key_pair,
            party_one_private,
        )?;

        self.master_key(user_id)?;

        // call lockbox
        if self.config.lockbox.is_empty() == false {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let start = Instant::now();
            let path: &str = "/ecdsa/keygen/second";
            let url = format!("{}{}", self.config.lockbox, path);

            let client = reqwest::blocking::Client::new();
            let result = client.post(&url)
                .json(&key_gen_msg2)
                .send();

            let _response = match result {
                Ok(res) => info!("{} lockbox call status: {}", url.to_string(), res.status() ),
                Err(err) => info!("ERROR: {} lockbox error: {}", url.to_string(), err),
            };
            info!("(req {}, took: {})", path, TimeFormat(start.elapsed()));
        }

        Ok(kg_party_one_second_message)
    }

    fn sign_first(&self, sign_msg1: SignMsg1) -> Result<party_one::EphKeyGenFirstMsg> {
        
        // call lockbox
        if self.config.lockbox.is_empty() == false {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let start = Instant::now();
            let path: &str = "/ecdsa/sign/first";
            let url = format!("{}{}", self.config.lockbox, path);

            let client = reqwest::blocking::Client::new();
            let result = client.post(&url)
                .json(&sign_msg1)
                .send();

            let _response = match result {
                Ok(res) => info!("{} lockbox call status: {}", url.to_string(), res.status() ),
                Err(err) => info!("ERROR: {} lockbox error: {}", url.to_string(), err),
            };
            info!("(req {}, took: {})", path, TimeFormat(start.elapsed()));
        }

        let user_id = sign_msg1.shared_key_id;
        self.check_user_auth(&user_id)?;

        let db = &self.database;

        let (sign_party_one_first_message, eph_ec_key_pair_party1) :
            //(multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::
                (party_one::EphKeyGenFirstMsg, party_one::EphEcKeyPair) =
            //(i64, i64) =
            MasterKey1::sign_first_message();

        db.update_ecdsa_sign_first(
            user_id,
            sign_msg1.eph_key_gen_first_message_party_two,
            eph_ec_key_pair_party1,
        )?;

        Ok(sign_party_one_first_message)
    }

    fn sign_second(&self, sign_msg2: SignMsg2) -> Result<Vec<Vec<u8>>> {

        // call lockbox
        if self.config.lockbox.is_empty() == false {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let start = Instant::now();
            let path: &str = "/ecdsa/sign/second";
            let url = format!("{}{}", self.config.lockbox, path);

            let client = reqwest::blocking::Client::new();
            let result = client.post(&url)
                .json(&sign_msg2)
                .send();

            let _response = match result {
                Ok(res) => info!("{} lockbox call status: {}", url.to_string(), res.status() ),
                Err(err) => info!("ERROR: {} lockbox error: {}", url.to_string(), err),
            };
            info!("(req {}, took: {})", path, TimeFormat(start.elapsed()));
        }

        let user_id = sign_msg2.shared_key_id;
        self.check_user_auth(&user_id)?;
        let db = &self.database;

        // Get validated sig hash for this user
        let sig_hash: sha256d::Hash = db.get_sighash(user_id)?;

        // Check sig hash is of corrcet length. Leading 0s are lost during BigInt conversion so add them
        // back here if necessary.
        let mut message_hex = sign_msg2.sign_second_msg_request.message.to_hex();
        if message_hex.len() < 64 {
            let num_zeros = 64 - message_hex.len();
            let temp = message_hex.clone();
            message_hex = format!("{:0width$}", 0, width = num_zeros);
            message_hex.push_str(&temp);
        }

        // Check sighash matches message to be signed
        let message_sig_hash = reverse_hex_str(message_hex.clone())?;
        if sig_hash.to_string() != message_sig_hash {
            return Err(SEError::SigningError(format!(
                "Message to be signed does not match verified sig hash. \n{}, {}",
                sig_hash.to_string(),
                message_sig_hash
            )));
        }

        // Get 2P-Ecdsa data
        let ssi: ECDSASignSecondInput = db.get_ecdsa_sign_second_input(user_id)?;

        let signature;
        match ssi.shared_key.sign_second_message(
            &sign_msg2.sign_second_msg_request.party_two_sign_message,
            &ssi.eph_key_gen_first_message_party_two,
            &ssi.eph_ec_key_pair_party1,
            &sign_msg2.sign_second_msg_request.message,
        ) {
            Ok(sig) => signature = sig,
            Err(_) => {
                return Err(SEError::SigningError(String::from(
                    "Signature validation failed.",
                )))
            }
        };

        // Get transaction which is being signed.
        let mut tx: Transaction = match sign_msg2.sign_second_msg_request.protocol {
            Protocol::Withdraw => db.get_tx_withdraw(user_id)?,
            _ => db.get_user_backup_tx(user_id)?,
        };

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
        let pk_vec = ssi.shared_key.public.q.get_element().serialize().to_vec();
        let mut witness = vec![sig_vec, pk_vec];

        // Add signature to tx
        tx.input[0].witness = witness.clone();

        match sign_msg2.sign_second_msg_request.protocol {
            Protocol::Withdraw => {
                // Store signed withdraw tx in UserSession DB object
                db.update_tx_withdraw(user_id, tx)?;

                info!("WITHDRAW: Tx signed and stored. User ID: {}", user_id);
                // Do not return withdraw tx witness until /withdraw/confirm is complete
                witness = vec![];
            }
            _ => {
                // Store signed backup tx in UserSession DB object
                db.update_user_backup_tx(&user_id, tx)?;
                info!(
                    "DEPOSIT/TRANSFER: Backup Tx signed and stored. User: {}",
                    user_id
                );
            }
        };

        Ok(witness)
    }
}

#[post("/ecdsa/keygen/first", format = "json", data = "<key_gen_msg1>")]
pub fn first_message(
    sc_entity: State<SCE>,
    key_gen_msg1: Json<KeyGenMsg1>,
) -> Result<Json<(Uuid, party_one::KeyGenFirstMsg)>> {
    match sc_entity.first_message(key_gen_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/ecdsa/keygen/second", format = "json", data = "<key_gen_msg2>")]
pub fn second_message(
    sc_entity: State<SCE>,
    key_gen_msg2: Json<KeyGenMsg2>,
) -> Result<Json<party1::KeyGenParty1Message2>> {
    match sc_entity.second_message(key_gen_msg2.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/ecdsa/sign/first", format = "json", data = "<sign_msg1>")]
pub fn sign_first(
    sc_entity: State<SCE>,
    sign_msg1: Json<SignMsg1>,
) -> Result<Json<party_one::EphKeyGenFirstMsg>> {
    match sc_entity.sign_first(sign_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/ecdsa/sign/second", format = "json", data = "<sign_msg2>")]
pub fn sign_second(sc_entity: State<SCE>, sign_msg2: Json<SignMsg2>) -> Result<Json<Vec<Vec<u8>>>> {
    match sc_entity.sign_second(sign_msg2.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}
