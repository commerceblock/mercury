pub use super::super::Result;

use crate::error::{DBErrorType, SEError};
use crate::Database;
use crate::{server::StateChainEntity, structs::*};
use shared_lib::{
    structs::{KeyGenMsg1, KeyGenMsg2, KeyGenReply1, KeyGenReply2, SignReply1, Protocol, SignMsg1, SignMsg2},
    util::reverse_hex_str,
};
use super::requests::post_lb;

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
use rocket_okapi::openapi;

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

    fn first_message(&self, key_gen_msg1: KeyGenMsg1) -> Result<KeyGenReply1>;

    fn second_message(&self, key_gen_msg2: KeyGenMsg2) -> Result<KeyGenReply2>;

    fn sign_first(&self, sign_msg1: SignMsg1) -> Result<SignReply1>;

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

    fn first_message(&self, key_gen_msg1: KeyGenMsg1) -> Result<KeyGenReply1> {
        let user_id = key_gen_msg1.shared_key_id;
        self.check_user_auth(&user_id)?;

        let kg_first_msg;
        // call lockbox
        if self.lockbox.active {
            let path: &str = "ecdsa/keygen/first";
            let (_id, key_gen_first_msg): (Uuid, party_one::KeyGenFirstMsg) = post_lb(&self.lockbox, path, &key_gen_msg1)?;
            kg_first_msg = key_gen_first_msg;
        }
        else {
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
                    MasterKey1::key_gen_first_message_predefined(s2)
                };

            db.update_keygen_first_msg(&user_id, &key_gen_first_msg, comm_witness, ec_key_pair)?;
            kg_first_msg = key_gen_first_msg;
        }
        Ok(KeyGenReply1 {user_id: user_id, msg: kg_first_msg } )
    }

    fn second_message(&self, key_gen_msg2: KeyGenMsg2) -> Result<KeyGenReply2> {
        let kg_party_one_second_msg: party1::KeyGenParty1Message2;
        // call lockbox
        if self.lockbox.active {
            let path: &str = "ecdsa/keygen/second";
            let kg_party_one_second_message: party1::KeyGenParty1Message2 = post_lb(&self.lockbox, path, &key_gen_msg2)?;
            kg_party_one_second_msg = kg_party_one_second_message;
        }
        else {
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
            kg_party_one_second_msg = kg_party_one_second_message;
        }

        Ok(KeyGenReply2 { msg: kg_party_one_second_msg } )
    }

    fn sign_first(&self, sign_msg1: SignMsg1) -> Result<SignReply1> {

        let user_id = sign_msg1.shared_key_id;
        self.check_user_auth(&user_id)?;

        let sign_party_one_first_msg: party_one::EphKeyGenFirstMsg;

        if self.lockbox.active {
            let path: &str = "ecdsa/sign/first";
            let sign_party_one_first_message: party_one::EphKeyGenFirstMsg = post_lb(&self.lockbox, path, &sign_msg1)?;
            sign_party_one_first_msg = sign_party_one_first_message;
        }
        else {
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
            sign_party_one_first_msg = sign_party_one_first_message;
        }

        Ok(SignReply1 { msg: sign_party_one_first_msg } )
    }

    fn sign_second(&self, sign_msg2: SignMsg2) -> Result<Vec<Vec<u8>>> {

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

        let mut ws: Vec<Vec<u8>>;

        if self.lockbox.active {
            let path: &str = "ecdsa/sign/second";
            let witness: Vec<Vec<u8>> = post_lb(&self.lockbox, path, &sign_msg2)?;
            ws = witness;
        }
        else {
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
            let witness = vec![sig_vec, pk_vec];
            ws = witness;
        }

        // Get transaction which is being signed.
        let mut tx: Transaction = match sign_msg2.sign_second_msg_request.protocol {
            Protocol::Withdraw => db.get_tx_withdraw(user_id)?,
            _ => db.get_user_backup_tx(user_id)?,
        };

        // Add signature to tx
        tx.input[0].witness = ws.clone();

        match sign_msg2.sign_second_msg_request.protocol {
            Protocol::Withdraw => {
                // Store signed withdraw tx in UserSession DB object
                db.update_tx_withdraw(user_id, tx)?;

                info!("WITHDRAW: Tx signed and stored. User ID: {}", user_id);
                // Do not return withdraw tx witness until /withdraw/confirm is complete
                ws = vec![];
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

        Ok(ws)
    }
}

#[openapi]
/// # First round of the 2P-ECDSA key generation protocol: get pubkey and ZK proof commitments
#[post("/ecdsa/keygen/first", format = "json", data = "<key_gen_msg1>")]
pub fn first_message(
    sc_entity: State<SCE>,
    key_gen_msg1: Json<KeyGenMsg1>,
) -> Result<Json<KeyGenReply1>> {
    match sc_entity.first_message(key_gen_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Second round of the 2P-ECDSA key generation protocol: get Paillier share and proofs
#[post("/ecdsa/keygen/second", format = "json", data = "<key_gen_msg2>")]
pub fn second_message(
    sc_entity: State<SCE>,
    key_gen_msg2: Json<KeyGenMsg2>,
) -> Result<Json<KeyGenReply2>> {
    match sc_entity.second_message(key_gen_msg2.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # First round of the 2P-ECDSA signing protocol: shared ephemeral keygen and proofs 
#[post("/ecdsa/sign/first", format = "json", data = "<sign_msg1>")]
pub fn sign_first(
    sc_entity: State<SCE>,
    sign_msg1: Json<SignMsg1>,
) -> Result<Json<SignReply1>> {
    match sc_entity.sign_first(sign_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Second round of the 2P-ECDSA signing protocol: signature generation and verification
#[post("/ecdsa/sign/second", format = "json", data = "<sign_msg2>")]
pub fn sign_second(sc_entity: State<SCE>, sign_msg2: Json<SignMsg2>) -> Result<Json<Vec<Vec<u8>>>> {
    match sc_entity.sign_second(sign_msg2.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::protocol::util::tests::test_sc_entity;
    use shared_lib::structs::SignSecondMsgRequest;
    use crate::protocol::util::tests::BACKUP_TX_NOT_SIGNED;
    use bitcoin::Transaction;
    use std::str::FromStr;
    use mockito;
    use serde_json;
    use curv::elliptic::curves::traits::ECScalar;
    use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
    use crate::curv::cryptographic_primitives::proofs::sigma_dlog::ProveDLog;
    use curv::cryptographic_primitives::proofs::sigma_ec_ddh::ECDDHProof;

    #[test]
    fn test_keygen_lockbox_client() {
        let user_id = Uuid::from_str("001203c9-93f0-46f9-abda-0678c891b2d3").unwrap();
        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_create_user_session().returning(|_, _, _| Ok(()));
        db.expect_get_user_auth().returning(move |_| Ok(user_id));

        let mut sc_entity = test_sc_entity(db);

        sc_entity.lockbox.active = true;
        sc_entity.lockbox.endpoint = mockito::server_url();

        let kg_first_msg = party_one::KeyGenFirstMsg { pk_commitment: BigInt::from(0), zk_pok_commitment: BigInt::from(1) };

        let serialized_m1 = serde_json::to_string(&(&user_id,&kg_first_msg)).unwrap();

        let _m_1 = mockito::mock("POST", "/ecdsa/keygen/first")
          .with_header("content-type", "application/json")
          .with_body(serialized_m1)
          .create();

        let kg_msg_1 = KeyGenMsg1 { shared_key_id: user_id, protocol: Protocol::Deposit };

        let return_msg = sc_entity.first_message(kg_msg_1).unwrap();

        assert_eq!(kg_first_msg.pk_commitment,return_msg.msg.pk_commitment);
        assert_eq!(kg_first_msg.zk_pok_commitment,return_msg.msg.zk_pok_commitment);

        let secret_share: FE = ECScalar::new_random();
        let d_log_proof = DLogProof::prove(&secret_share);
        let json = r#"
                {
                    "public_share":{"x":"de6822e27f1223c9a8200408fa002c612c3635d801ea6c3315789f8cf3e3fe29","y":"e3231aca5034eb8bd5271b728a516720088a69e124ccbd982003c50b474bb22a"},
                    "secret_share":"eddb897ad33e4fef8b71bd4b6eab7e6f3c6acfe8d6346989389706e4c2331be6"
                }
            "#;

        let ec_key_pair: party_one::EcKeyPair = serde_json::from_str(&json.to_string()).unwrap();

        let comm_witness = party_one::CommWitness {
            pk_commitment_blind_factor: BigInt::from(0),
            zk_pok_blind_factor: BigInt::from(1),
            public_share: ECPoint::generator(),
            d_log_proof: d_log_proof.clone(),
        };

        let (kg_party_one_second_message, _, _): (
            party1::KeyGenParty1Message2,
            party_one::PaillierKeyPair,
            party_one::Party1Private,
        ) = MasterKey1::key_gen_second_message(
            comm_witness,
            &ec_key_pair,
            &d_log_proof,
        );

        let serialized_m2 = serde_json::to_string(&kg_party_one_second_message).unwrap();

        let _m_2 = mockito::mock("POST", "/ecdsa/keygen/second")
          .with_header("content-type", "application/json")
          .with_body(serialized_m2)
          .create();

        let kg_msg_2 = KeyGenMsg2 { shared_key_id: user_id, dlog_proof: d_log_proof};

        let return_msg = sc_entity.second_message(kg_msg_2).unwrap();

        assert_eq!(kg_party_one_second_message.c_key,return_msg.msg.c_key);

    }

    #[test]
    fn test_sign_lockbox_client() {
        let user_id = Uuid::from_str("001203c9-93f0-46f9-abda-0678c891b2d3").unwrap();
        let tx_backup: Transaction = serde_json::from_str(&BACKUP_TX_NOT_SIGNED).unwrap();
        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_create_user_session().returning(|_, _, _| Ok(()));
        db.expect_get_user_auth().returning(move |_| Ok(user_id));
        db.expect_get_user_backup_tx().returning(move |_| Ok(tx_backup.clone()));
        db.expect_update_user_backup_tx().returning(|_, _| Ok(()));
        let hexhash = r#"
                "0000000000000000000000000000000000000000000000000000000000000000"
            "#;
        let sig_hash: sha256d::Hash = serde_json::from_str(&hexhash.to_string()).unwrap();
        db.expect_get_sighash().returning(move |_| Ok(sig_hash));

        let mut sc_entity = test_sc_entity(db);

        sc_entity.lockbox.active = true;
        sc_entity.lockbox.endpoint = mockito::server_url();

        let (eph_key_gen_first_message_party_two, _, _) =
            MasterKey2::sign_first_message();

        let sign_msg1 = SignMsg1 {
            shared_key_id: user_id,
            eph_key_gen_first_message_party_two,
        };

        let (sign_party_one_first_message, _) :
                (party_one::EphKeyGenFirstMsg, party_one::EphEcKeyPair) = MasterKey1::sign_first_message();

        let serialized_m1 = serde_json::to_string(&sign_party_one_first_message).unwrap();

        let _m_1 = mockito::mock("POST", "/ecdsa/sign/first")
          .with_header("content-type", "application/json")
          .with_body(serialized_m1)
          .create();

        let return_msg = sc_entity.sign_first(sign_msg1).unwrap();

        assert_eq!(sign_party_one_first_message.public_share,return_msg.msg.public_share);
        assert_eq!(sign_party_one_first_message.c,return_msg.msg.c);

        let d_log_proof = ECDDHProof {
            a1: ECPoint::generator(),
            a2: ECPoint::generator(),
            z: ECScalar::new_random(),
        };
        let comm_witness = party_two::EphCommWitness {
            pk_commitment_blind_factor: BigInt::from(0),
            zk_pok_blind_factor: BigInt::from(1),
            public_share: ECPoint::generator(),
            d_log_proof: d_log_proof.clone(),
            c: ECPoint::generator(),
        };

        let sign_msg2 = SignMsg2 {
            shared_key_id: user_id,
            sign_second_msg_request: SignSecondMsgRequest {
                protocol: Protocol::Deposit,
                message: BigInt::from(0),
                party_two_sign_message: party2::SignMessage {
                    partial_sig: party_two::PartialSig {c3: BigInt::from(3)},
                    second_message: party_two::EphKeyGenSecondMsg {comm_witness},
                },
            },
        };

        let witness: Vec<Vec<u8>> = vec![vec![48, 68, 2, 32, 94, 197, 64, 97, 183, 140, 229, 202, 52, 141, 214, 128, 218, 92, 31, 159, 14, 192, 114, 167, 169, 166, 85, 208, 129, 89, 59, 72, 233, 119, 11, 69, 2, 32, 101, 93, 62, 147, 163, 225, 79, 143, 112, 88, 161, 251, 186, 215, 255, 67, 246, 19, 93, 17, 135, 235, 196, 111, 228, 236, 109, 196, 131, 192, 230, 245, 1], vec![3, 120, 158, 98, 241, 124, 29, 175, 68, 206, 87, 99, 45, 189, 226, 48, 73, 247, 39, 150, 105, 96, 216, 148, 31, 95, 159, 155, 255, 127, 61, 19, 169]];

        let serialized_m2 = serde_json::to_string(&witness).unwrap();
        let _m_2 = mockito::mock("POST", "/ecdsa/sign/second")
          .with_header("content-type", "application/json")
          .with_body(serialized_m2)
          .create();

        let return_msg = sc_entity.sign_second(sign_msg2).unwrap();

        assert_eq!(return_msg,witness);

    }

}
