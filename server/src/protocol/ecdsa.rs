use super::super::{Result, StateChainEntity};

use crate::error::{DBErrorType, SEError};
use crate::{
    storage::db::{
        //db_deser, db_get_1, db_get_2, db_get_3, db_get_4, db_insert, db_ser, db_update, 
        Column,
        Table,
    },
    //DatabaseR, DatabaseW,
    Database
};
use shared_lib::{
    structs::{KeyGenMsg1, KeyGenMsg2, KeyGenMsg3, KeyGenMsg4, Protocol, SignMsg1, SignMsg2},
    util::reverse_hex_str,
};

use bitcoin::{hashes::sha256d, secp256k1::Signature, Transaction};
use curv::{
    arithmetic::traits::Converter,
    elliptic::curves::traits::ECPoint,
    {BigInt, FE, GE},
};

use crate::storage::db::{Alpha, HDPos};
use crate::Database as DB;
use crate::PGDatabase as PGDB;
use crate::structs::*;

use kms::ecdsa::two_party::*;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use rocket::State;
use rocket_contrib::json::Json;

use std::string::ToString;
use uuid::Uuid;

/// 2P-ECDSA protocol trait
pub trait Ecdsa {
    fn master_key(&self, user_id: Uuid) -> Result<()>;

    fn first_message(
        &self,
        key_gen_msg1: KeyGenMsg1,
    ) -> Result<(Uuid, party_one::KeyGenFirstMsg)>;

    fn second_message(
        &self,
        key_gen_msg2: KeyGenMsg2,
    ) -> Result<party1::KeyGenParty1Message2>;

    fn third_message(
        &self,
        key_gen_msg3: KeyGenMsg3,
    ) -> Result<party_one::PDLFirstMessage>;

    fn fourth_message(
        &self,
        key_gen_msg4: KeyGenMsg4,
    ) -> Result<party_one::PDLSecondMessage>;

    fn sign_first(
        &self,
        sign_msg1: SignMsg1,
    ) -> Result<party_one::EphKeyGenFirstMsg>;

    fn sign_second(
        &self,
        sign_msg2: SignMsg2,
    ) -> Result<Vec<Vec<u8>>>;
}


impl Ecdsa for StateChainEntity {
    fn master_key(&self, user_id: Uuid) -> Result<()> {
        let db = &self.database;
        let (party2_public_str, paillier_key_pair_str, party_one_private_str, comm_witness_str) =
            db.get_4::<String, String, String, String>(
                user_id,
                Table::Ecdsa,
                vec![
                    Column::Party2Public,
                    Column::PaillierKeyPair,
                    Column::Party1Private,
                    Column::CommWitness,
                ],
            )?;
    
        let party2_public: GE = PGDB::deser(party2_public_str)?;
        let paillier_key_pair: party_one::PaillierKeyPair = PGDB::deser(paillier_key_pair_str)?;
        let party_one_private: party_one::Party1Private = PGDB::deser(party_one_private_str)?;
        let comm_witness: party_one::CommWitness = PGDB::deser(comm_witness_str)?;
    
        let master_key = MasterKey1::set_master_key(
            &BigInt::from(0),
            party_one_private,
            &comm_witness.public_share,
            &party2_public,
            paillier_key_pair,
        );
    
        db.update(
            &user_id,
            Table::Ecdsa,
            vec![Column::Party1MasterKey],
            vec![&PGDB::ser(master_key)?],
        )
    }

    fn first_message(
        &self,
        key_gen_msg1: KeyGenMsg1,
    ) -> Result<(Uuid, party_one::KeyGenFirstMsg)> {
        let user_id = key_gen_msg1.shared_key_id;
        self.check_user_auth(&user_id)?;

        let db = &self.database;

        // Create new entry in ecdsa table if key not already in table.
        match db.get_ecdsa_master(user_id)
        {
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

        Ok((user_id, key_gen_first_msg))
    }

    fn second_message(
        &self,
        key_gen_msg2: KeyGenMsg2,
    ) -> Result<party1::KeyGenParty1Message2> {
        let db = &self.database;

        let user_id = key_gen_msg2.shared_key_id;

        let party2_public: GE = key_gen_msg2.dlog_proof.pk.clone();

        let (comm_witness, ec_key_pair) = 
            db.get_ecdsa_witness_keypair(user_id)?;

        

        let (kg_party_one_second_message, paillier_key_pair, party_one_private) : 
                (party1::KeyGenParty1Message2, party_one::PaillierKeyPair, party_one::Party1Private) =
            MasterKey1::key_gen_second_message(
                comm_witness,
                &ec_key_pair,
                &key_gen_msg2.dlog_proof,
            );

        db.update_keygen_second_msg(
            &user_id, 
            party2_public, 
            paillier_key_pair,
            party_one_private
        )?;

        Ok(kg_party_one_second_message)
    }

    fn third_message(
        &self,
        key_gen_msg3: KeyGenMsg3,
    ) -> Result<party_one::PDLFirstMessage> {
        let user_id = key_gen_msg3.shared_key_id;
        let db = &self.database;
        let party_one_private: party_one::Party1Private = 
            db.get_ecdsa_party_1_private(user_id)?;

        let (party_one_third_message, party_one_pdl_decommit, alpha) =
            MasterKey1::key_gen_third_message(
                &key_gen_msg3.party_two_pdl_first_message,
                &party_one_private,
            );

        db.update_keygen_third_msg(&user_id,
            party_one_pdl_decommit,
            key_gen_msg3.party_two_pdl_first_message,
            alpha)?;

        Ok(party_one_third_message)
    }

    fn fourth_message(
        &self,
        key_gen_msg4: KeyGenMsg4,
    ) -> Result<party_one::PDLSecondMessage> {
        let user_id = key_gen_msg4.shared_key_id;
        let db = &self.database;

        let fmi : ECDSAFourthMessageInput =
            db.get_ecdsa_fourth_message_input(user_id)?;

        let pdl_second_msg = MasterKey1::key_gen_fourth_message(
            &fmi.party_two_pdl_first_message,
            &key_gen_msg4.party_two_pdl_second_message,
            fmi.party_one_private,
            fmi.party_one_pdl_decommit,
            fmi.alpha.value,
        );

        assert!(pdl_second_msg.is_ok());

        self.master_key(user_id)?;

        Ok(pdl_second_msg.unwrap())
    }

    fn sign_first(
        &self,
        sign_msg1: SignMsg1,
    ) -> Result<party_one::EphKeyGenFirstMsg> {
        let user_id = sign_msg1.shared_key_id;
        self.check_user_auth(&user_id)?;

        let db = &self.database;

        let (sign_party_one_first_message, eph_ec_key_pair_party1) :
            //(multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::
                (party_one::EphKeyGenFirstMsg, party_one::EphEcKeyPair) =
            //(i64, i64) =
            MasterKey1::sign_first_message();

        self.database.update_ecdsa_sign_first(user_id, 
            sign_msg1.eph_key_gen_first_message_party_two,
            eph_ec_key_pair_party1
        )?;

        Ok(sign_party_one_first_message)
    }

    fn sign_second(
        &self,
        sign_msg2: SignMsg2,
    ) -> Result<Vec<Vec<u8>>> {
        let user_id = sign_msg2.shared_key_id;
        self.check_user_auth(&user_id)?;
        let db = &self.database;

        // Get validated sig hash for this user
        let sig_hash: sha256d::Hash = PGDB::deser(db.get_1(
            user_id,
            Table::UserSession,
            vec![Column::SigHash],
        )?)?;

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
            _ => db.get_backup_transaction(user_id)?
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
    sc_entity: State<StateChainEntity>,
    key_gen_msg1: Json<KeyGenMsg1>,
) -> Result<Json<(Uuid, party_one::KeyGenFirstMsg)>> {
    match sc_entity.first_message(key_gen_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/ecdsa/keygen/second", format = "json", data = "<key_gen_msg2>")]
pub fn second_message(
    sc_entity: State<StateChainEntity>,
    key_gen_msg2: Json<KeyGenMsg2>,
) -> Result<Json<party1::KeyGenParty1Message2>> {
    match sc_entity.second_message(key_gen_msg2.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/ecdsa/keygen/third", format = "json", data = "<key_gen_msg3>")]
pub fn third_message(
    sc_entity: State<StateChainEntity>,
    key_gen_msg3: Json<KeyGenMsg3>,
) -> Result<Json<party_one::PDLFirstMessage>> {
    match sc_entity.third_message(key_gen_msg3.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/ecdsa/keygen/fourth", format = "json", data = "<key_gen_msg4>")]
pub fn fourth_message(
    sc_entity: State<StateChainEntity>,
    key_gen_msg4: Json<KeyGenMsg4>,
) -> Result<Json<party_one::PDLSecondMessage>> {
    match sc_entity.fourth_message(key_gen_msg4.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/ecdsa/sign/first", format = "json", data = "<sign_msg1>")]
pub fn sign_first(
    sc_entity: State<StateChainEntity>,
    sign_msg1: Json<SignMsg1>,
) -> Result<Json<party_one::EphKeyGenFirstMsg>> {
    match sc_entity.sign_first(sign_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/ecdsa/sign/second", format = "json", data = "<sign_msg2>")]
pub fn sign_second(
    sc_entity: State<StateChainEntity>,
    sign_msg2: Json<SignMsg2>,
) -> Result<Json<Vec<Vec<u8>>>> {
    match sc_entity.sign_second(sign_msg2.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}
