//! StateEntity Transfer
//!
//! StateEntity Transfer protocol trait and implementation.

pub use super::super::Result;
extern crate shared_lib;
extern crate reqwest;
use crate::server::TRANSFERS_COUNT;
use super::transfer_batch::transfer_batch_is_ended;
use shared_lib::{ecies, ecies::WalletDecryptable, ecies::SelfEncryptable, 
    state_chain::*, structs::*, util::transaction_deserialise};
use bitcoin::secp256k1::key::SecretKey;
use bitcoin::secp256k1::PublicKey;
use bitcoin::util::key::PrivateKey;
use bitcoin::network::constants::Network;

use crate::error::SEError;
use crate::Database;
use crate::{server::StateChainEntity, storage::Storage};
use super::requests::post_lb;
use rocket_okapi::openapi;

use cfg_if::cfg_if;
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    arithmetic::traits::Converter,
    {FE, GE, BigInt},
};
use rocket::State;
use rocket_contrib::json::Json;
use std::str::FromStr;
use uuid::Uuid;
use url::Url;
use crate::protocol::{util::{Utilities, RateLimiter}, withdraw::Withdraw};


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



/// StateChain Transfer protocol trait
pub trait Transfer {
    /// API: Initiliase transfer protocol:
    ///     - Authorisation of Owner and DoS protection
    ///     - Validate transfer parameters
    ///     - Store transfer parameters
    fn transfer_sender(&self, transfer_msg1: TransferMsg1) -> Result<TransferMsg2>;

    /// API: Get the current SE/Lockbox public key share
    fn transfer_get_pubkey(&self, user_id: Uuid) -> Result<S1PubKey>;

    /// API: Transfer shared wallet to new Owner:
    ///     - Check new Owner's state chain is correct
    ///     - Perform 2P-ECDSA key rotation
    ///     - Return new public shared key S2
    fn transfer_receiver(&self, transfer_msg4: TransferMsg4) -> Result<TransferMsg5>;

    /// Update DB and SMT after successful transfer.
    /// This function is called immediately in the regular transfer case or after confirmation of atomic
    /// transfers completion in the batch transfer case.
    fn transfer_finalize(&self, finalized_data: &TransferFinalizeData) -> Result<()>;

    /// API: Update the state entity database with transfer message 3
    fn transfer_update_msg(&self, transfer_msg3: TransferMsg3) -> Result<()>;

    /// API: Get the transfer message 3 set by update_transfer_msg
    fn transfer_get_msg(&self, statechain_id: Uuid) -> Result<TransferMsg3>;

    /// API: Get the transfer message 3 set by update_transfer_msg from the receiver address
    fn transfer_get_msg_addr(&self, receive_addr: String) -> Result<Vec<TransferMsg3>>;
}

impl Transfer for SCE {
    fn transfer_sender(&self, transfer_msg1: TransferMsg1) -> Result<TransferMsg2> {
        self.check_user_auth(&transfer_msg1.shared_key_id)?;
        let user_id = transfer_msg1.shared_key_id;
        debug!("TRANSFER: Sender Side. Shared Key ID: {}", user_id);

        if(self.get_if_signed_for_withdrawal(&user_id)?.is_some()) {
            return Err(SEError::Generic(format!("transfer_sender - shared key id: {} is signed for withdrawal", &user_id)));
        }

        // Get state_chain id
        let statechain_id = self.database.get_statechain_id(user_id)?;

        // Get back up tx and proof key
        let (tx_backup,_) = self.database.get_backup_transaction_and_proof_key(user_id)?;

        // Check that the funding transaction has the required number of confirmations
        self.verify_tx_confirmed(&tx_backup.input[0].previous_output.txid.to_string())?;
        self.database.set_confirmed(&statechain_id)?;

        // Check if state chain is owned by user and not locked
        let sco = self.database.get_statechain_owner(statechain_id)?;

        is_locked(sco.locked_until)?;
        if sco.owner_id != user_id {
            return Err(SEError::Generic(format!(
                "State Chain not owned by User ID: {}.",
                user_id
            )));
        }

        // verify statechain sig
        // TODO

        // Generate x1
        let x1: FE = ECScalar::new_random();
        let x1_ser = FESer::from_fe(&x1);

        self.database
            .create_transfer(&statechain_id, &transfer_msg1.statechain_sig, &x1, transfer_msg1.batch_id)?;

        info!(
            "TRANSFER: Sender side complete. Previous shared key ID: {}. State Chain ID: {}",
            user_id.to_string(),
            statechain_id
        );
        debug!("TRANSFER: Sender side complete. State Chain ID: {}. State Chain Signature: {:?}. x1: {:?}.", statechain_id, transfer_msg1.statechain_sig, x1);

        // encrypt x1 with Senders proof key
        let proof_key = match ecies::PublicKey::from_str(&self.database.get_proof_key(user_id)?) {
            Ok(k) => k,
            Err(e) => {
                return Err(SEError::SharedLibError(format!(
                    "error deserialising proof key: {}",
                    e
                )))
            }
        };

        let mut msg2 = TransferMsg2 {
            x1: x1_ser,
            proof_key,
        };

        match msg2.encrypt() {
            Ok(_) => (),
            Err(e) => return Err(SEError::SharedLibError(format!("{}", e))),
        };

        let msg2 = msg2;

        Ok(msg2)
    }

    fn transfer_get_pubkey(&self, user_id: Uuid) -> Result<S1PubKey> {
        let pubkey = self.database.get_s1_pubkey(&user_id)?;
        Ok(S1PubKey { key: hex::encode(&PublicKey::from_slice(&pubkey.pk_to_key_slice()).unwrap().serialize()) } )
    }

    fn transfer_receiver(&self, mut transfer_msg4: TransferMsg4) -> Result<TransferMsg5> {
        
        let user_id = transfer_msg4.shared_key_id;
        let statechain_id = transfer_msg4.statechain_id;

        // Get Transfer Data for statechain_id
        let td = self.database.get_transfer_data(statechain_id)?;

        // Ensure statechain_sigs are the same
        if td.statechain_sig != transfer_msg4.statechain_sig.to_owned() {
            return Err(SEError::Generic(format!(
                "State chain siganture provided does not match state chain at id {}",
                statechain_id
            )));
        }

        // Check if batch transfer and batch ID matches
        if td.batch_id.is_some() {
            if transfer_msg4.batch_data.is_some() {
                let batch_id = transfer_msg4.batch_data.clone().unwrap().id;
                if batch_id != td.batch_id.unwrap() {
                    return Err(SEError::Generic(format!(
                        "Incorrect batch ID for receive. Expected {}",
                        td.batch_id.unwrap()
                    )));                
                }
            } else {
                return Err(SEError::Generic(format!(
                    "Expect receive in batch ID {}",
                    td.batch_id.unwrap()
                )));
            }
        }

        let s2: FE;
        let s2_pub: GE;
        match &self.get_lockbox_url(&user_id)? {
            Some(l) => {
            let ku_send = KUSendMsg {
                user_id,
                statechain_id,
                x1: td.x1,
                t2: transfer_msg4.t2,
                o2_pub: transfer_msg4.o2_pub,
            };
            let path: &str = "ecdsa/keyupdate/first";
            let ku_receive: KUReceiveMsg = post_lb(&l.0, path, &ku_send)?;
            s2 = FE::new_random();
            s2_pub = ku_receive.s2_pub;
        },
        None => {
            let kp = self.database.get_ecdsa_keypair(user_id)?;

            // let x1 = transfer_data.x1;
            let s1 = kp.party_1_private.get_private_key();

            let s1_priv = PrivateKey {
                compressed: true,
                network: Network::Regtest,
                key: SecretKey::from_slice(&BigInt::to_vec(&s1.clone().to_big_int())).unwrap(),
            };

            match transfer_msg4.decrypt(&s1_priv) {
                Ok(_) => (),
                Err(e) => return Err(SEError::SharedLibError(format!("Failed to decrypt t2 in transfer_msg4. Error: {}", e.to_string()))),
            };

            let t2 = match transfer_msg4.t2.get_fe() {
                Ok(r) => r,
                Err(e) => {
                    return Err(SEError::Generic(format!(
                        "Failed to get FE from transfer_msg_4 {:?} error: {}",
                        transfer_msg4,
                        e.to_string()
                    )))
                }
            };

            s2 = t2 * (td.x1.invert()) * s1;

            let g: GE = ECPoint::generator();
            s2_pub = g * s2;

            let p1_pub = kp.party_2_public * s1;
            let p2_pub = transfer_msg4.o2_pub * s2;

            // Check P1 = o1_pub*s1 === p2 = o2_pub*s2
            if p1_pub != p2_pub {
                error!("TRANSFER: Protocol failed. P1 != P2.");
                return Err(SEError::Generic(String::from(
                    "Transfer protocol error: P1 != P2",
                )));
            }
        }}

        // Create user ID for new UserSession (receiver of transfer)
        let new_shared_key_id = Uuid::new_v4();

        let finalized_data = TransferFinalizeData {
            new_shared_key_id: new_shared_key_id.clone(),
            statechain_id: statechain_id.clone(),
            statechain_sig: td.statechain_sig,
            s2,
            new_tx_backup_hex: transfer_msg4.tx_backup_hex,
            batch_data: transfer_msg4.batch_data.clone(),
        };

        // If batch transfer then mark StateChain as complete and store finalized data in TransferBatch table.
        // This is so the transfers can be finalized when all transfers in the batch are complete.
        if transfer_msg4.batch_data.is_some() {
            let batch_id = transfer_msg4.batch_data.clone().unwrap().id;
            debug!(
                "TRANSFER: Transfer as part of batch {}. State Chain ID: {}",
                batch_id, statechain_id
            );

            // Ensure batch transfer is still active
            if transfer_batch_is_ended(self.database.get_transfer_batch_start_time(&batch_id)?,
                                       self.config.batch_lifetime as i64) {
                return Err(SEError::TransferBatchEnded(String::from(
                    "Too late to complete transfer.",
                )));
            }

            self.database.update_finalize_batch_data(
                &statechain_id,
                &finalized_data,
            )?;

        // If not batch then finalize transfer now
        } else {
            debug!(
                "TRANSFER: Single (non-batch) transfer. State Chain ID: {}",
                 statechain_id
            );
            // Update DB and SMT with new transfer data
            self.transfer_finalize(&finalized_data)?;
        }

        info!(
            "TRANSFER: Receiver side complete. New shared key ID: {}",
            new_shared_key_id
        );
        debug!("TRANSFER: Receiver side complete. State Chain ID: {}. New Shared Key ID: {}. Finalized data: {:?}",statechain_id,statechain_id,finalized_data);

        Ok(TransferMsg5 {
            new_shared_key_id,
            s2_pub,
        })
    }

    /// Update DB and SMT after successful transfer.
    /// This function is called immediately in the regular transfer case or after confirmation of atomic
    /// transfers completion in the batch transfer case.
    fn transfer_finalize(&self, finalized_data: &TransferFinalizeData) -> Result<()> {
              
        let statechain_id = finalized_data.statechain_id;

        info!("TRANSFER_FINALIZE: State Chain ID: {}", statechain_id);

        // Update state chain
        let mut state_chain: StateChain = self.database.get_statechain(statechain_id)?;

        state_chain.add(&finalized_data.statechain_sig)?;

        let new_user_id = finalized_data.new_shared_key_id;

        let sco = self.database.get_statechain_owner(statechain_id)?;
        let lockbox_url: Option<(Url, usize)> = self.get_lockbox_url(&sco.owner_id).map_err(|e| {dbg!("{}",&e); e} )?;

        self.database.update_statechain_owner(
            &statechain_id,
            state_chain.clone(),
            &new_user_id,
        )?;

        // Create new UserSession to allow new owner to generate shared wallet

        self.database.transfer_init_user_session(
            &new_user_id,
            &statechain_id,
            finalized_data.to_owned(),
            self.user_ids.clone()   
        )?;

        //lockbox finalise and delete key
        match lockbox_url {
            Some(l) => {
                dbg!("using lockbox", &l);
                let ku_send = KUFinalize {
                    statechain_id,
                    shared_key_id: new_user_id,
                };
                let path: &str = "ecdsa/keyupdate/second";
                let _ku_receive: KUAttest = post_lb(&l.0, path, &ku_send)?;
                self.database.update_lockbox_index(&new_user_id, &l.1)?;
            },
            None => ()
        };

        let new_tx_backup_hex = transaction_deserialise(&finalized_data.new_tx_backup_hex)?;

        self.database
            .update_backup_tx(&statechain_id, new_tx_backup_hex.clone())?;

        info!(
            "TRANSFER: Finalized. New shared key ID: {}. State Chain ID: {}",
            finalized_data.new_shared_key_id, statechain_id
        );

        // Update sparse merkle tree with new StateChain entry
        let (prev_root, new_root) = self.update_smt(
            &new_tx_backup_hex
                .input
                .get(0)
                .unwrap()
                .previous_output
                .txid
                .to_string(),
            &state_chain
                .get_tip()
                .data
                .clone(),
        )?;

        info!(
            "TRANSFER: Included in sparse merkle tree. State Chain ID: {}",
            statechain_id
        );
        debug!(
            "TRANSFER: State Chain ID: {}. New root: {:?}. Previous root: {:?}.",
            statechain_id, &new_root, &prev_root
        );

        // Remove TransferData for this transfer
        self.database.remove_transfer_data(&statechain_id)?;

        //increment transfer counter
        TRANSFERS_COUNT.inc();

        Ok(())
    }

    /// API: Update the state entity database with transfer message 3
    fn transfer_update_msg(&self, transfer_msg3: TransferMsg3) -> Result<()> {
        self.database
            .update_transfer_msg(&transfer_msg3.statechain_id, &transfer_msg3)
    }

    /// API: Get the transfer message 3 set by update_transfer_msg
    fn transfer_get_msg(&self, statechain_id: Uuid) -> Result<TransferMsg3> {
        self.database.get_transfer_msg(&statechain_id)
    }

    /// API: Get the transfer message 3 set by update_transfer_msg from the receiver address
    fn transfer_get_msg_addr(&self, receive_addr: String) -> Result<Vec<TransferMsg3>> {
        self.database.get_transfer_msg_addr(&receive_addr)
    }
}

#[openapi]
/// # Transfer initiation by sender: get x1 and new backup transaction
#[post("/transfer/sender", format = "json", data = "<transfer_msg1>")]
pub fn transfer_sender(
    sc_entity: State<SCE>,
    transfer_msg1: Json<TransferMsg1>,
) -> Result<Json<TransferMsg2>> {
    sc_entity.check_rate_fast("transfer")?;
    match sc_entity.transfer_sender(transfer_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Retreive the current SE public key share for t2 encryption
#[post("/transfer/pubkey", format = "json", data = "<user_id>")]
pub fn transfer_get_pubkey(
    sc_entity: State<SCE>,
    user_id: Json<UserID>,
) -> Result<Json<S1PubKey>> {
    sc_entity.check_rate_fast("transfer")?;
    match sc_entity.transfer_get_pubkey(user_id.id) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Transfer completing by receiver: key share update and deletion
#[post("/transfer/receiver", format = "json", data = "<transfer_msg4>")]
pub fn transfer_receiver(
    sc_entity: State<SCE>,
    transfer_msg4: Json<TransferMsg4>,
) -> Result<Json<TransferMsg5>> {
    sc_entity.check_rate_fast("transfer")?;
    match sc_entity.transfer_receiver(transfer_msg4.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Update stored transfer message (TransferMsg3)
#[post("/transfer/update_msg", format = "json", data = "<transfer_msg3>")]
pub fn transfer_update_msg(
    sc_entity: State<SCE>,
    transfer_msg3: Json<TransferMsg3>,
) -> Result<Json<()>> {
    sc_entity.check_rate_fast("transfer")?;
    match sc_entity.transfer_update_msg(transfer_msg3.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Get stored transfer message (TransferMsg3)
#[post("/transfer/get_msg", format = "json", data = "<statechain_id>")]
pub fn transfer_get_msg(
    sc_entity: State<SCE>,
    statechain_id: Json<StatechainID>,
) -> Result<Json<TransferMsg3>> {
    sc_entity.check_rate_fast("transfer")?;
    match sc_entity.transfer_get_msg(statechain_id.id) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Get stored transfer message (TransferMsg3)
#[get("/transfer/get_msg_addr/<receive_addr>", format = "json")]
pub fn transfer_get_msg_addr(
    sc_entity: State<SCE>,
    receive_addr: String,
) -> Result<Json<Vec<TransferMsg3>>> {
    sc_entity.check_rate_fast("info")?;
    match sc_entity.transfer_get_msg_addr(receive_addr) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockDatabase;
    use crate::{
        error::DBErrorType,
        protocol::util::{
            mocks,
            tests::{test_sc_entity, BACKUP_TX_NOT_SIGNED},
        },
        structs::{ECDSAKeypair, StateChainOwner, TransferData, TransferFinalizeBatchData},
    };
    use chrono::{Duration, Utc};
    use mockall::predicate;
    use mockito;
    use serde_json;
    use bitcoin::Transaction;
    use crate::shared_lib::util::transaction_serialise;
    use std::convert::TryInto;
    use crate::structs::WithdrawConfirmData;

    // Data from a run of transfer protocol.
    // static TRANSFER_MSG_1: &str = "{\"shared_key_id\":\"707ea4c9-5ddb-4f08-a240-2b4d80ae630d\",\"statechain_sig\":{\"purpose\":\"TRANSFER\",\"data\":\"0213be735d05adea658d78df4719072a6debf152845044402c5fe09dd41879fa01\",\"sig\":\"3044022028d56cfdb4e02d46b2f8158b0414746ddf42ecaaaa995a3a02df8807c5062c0202207569dc0f49b64ae997b4c902539cddc1f4e4434d6b4b05af38af4b98232ebee8\"}}";
    static TRANSFER_MSG_2: &str = "{\"x1\":{\"secret_bytes\":[50,125,83,219,71,208,81,134,217,92,70,185,127,178,160,88,58,35,104,206,209,53,194,34,11,60,12,105,150,25,45,26]},\"proof_key\":\"026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e\"}";
    // static TRANSFER_MSG_3: &str = "{\"shared_key_id\":\"707ea4c9-5ddb-4f08-a240-2b4d80ae630d\",\"t1\":\"34c9a329617b8dd3cdeb3d491fa09f023f84f28005bdf40f0682eb020969183b\",\"statechain_sig\":{\"purpose\":\"TRANSFER\",\"data\":\"0213be735d05adea658d78df4719072a6debf152845044402c5fe09dd41879fa01\",\"sig\":\"3044022028d56cfdb4e02d46b2f8158b0414746ddf42ecaaaa995a3a02df8807c5062c0202207569dc0f49b64ae997b4c902539cddc1f4e4434d6b4b05af38af4b98232ebee8\"},\"statechain_id\":\"9b0ba36b-406a-499c-8c83-696b77f003a9\",\"tx_backup_psm\":{\"shared_key_id\":\"707ea4c9-5ddb-4f08-a240-2b4d80ae630d\",\"protocol\":\"Transfer\",\"tx\":{\"version\":2,\"lock_time\":0,\"input\":[{\"previous_output\":\"53e1d67d837fdaddb016c5de85d8903bc033f7f2208d3ff40430fc42edeab4cb:0\",\"script_sig\":\"\",\"sequence\":4294967295,\"witness\":[[48,69,2,33,0,177,248,103,71,170,95,47,217,222,7,130,181,12,9,254,115,96,166,180,164,162,4,14,110,145,113,106,97,155,231,190,22,2,32,63,119,90,178,253,249,43,242,42,177,250,25,29,251,156,37,12,61,70,252,201,155,252,188,56,242,36,211,50,136,203,95,1],[2,108,195,112,80,86,19,121,166,106,134,63,140,162,115,194,178,158,147,92,173,6,188,127,94,107,131,160,62,11,191,241,230]]}],\"output\":[{\"value\":9000,\"script_pubkey\":\"0014a5c378a7de7311e6836253a28830b48cc6b9e252\"}]},\"input_addrs\":[\"026cc37050561379a66a863f8ca273c2b29e935cad06bc7f5e6b83a03e0bbff1e6\"],\"input_amounts\":[10000],\"proof_key\":\"0213be735d05adea658d78df4719072a6debf152845044402c5fe09dd41879fa01\"},\"rec_se_addr\":{\"tx_backup_addr\":\"bcrt1q5hph3f77wvg7dqmz2w3gsv953nrtncjjzyj3m9\",\"proof_key\":\"0213be735d05adea658d78df4719072a6debf152845044402c5fe09dd41879fa01\"}}";
    static TRANSFER_MSG_4: &str = "{\"shared_key_id\":\"ef69278c-5143-4b2d-b443-4d25443242be\",\"statechain_id\":\"64070bf6-50af-4ee6-93c1-11e5f9588b39\",\"t2\":{\"secret_bytes\":[4,131,85,93,205,98,134,155,94,139,48,160,11,27,171,75,13,14,182,56,56,131,127,210,123,228,92,98,63,144,186,146,124,118,157,232,31,188,76,110,221,135,121,55,36,178,115,131,41,27,169,250,205,138,124,255,143,220,209,140,169,180,220,91,215,231,196,94,122,110,126,30,214,88,2,179,48,0,186,209,242,81,241,205,189,189,191,129,83,46,172,152,117,42,241,144,118,69,89,144,11,34,137,246,15,0,86,50,176,17,76,24,29,52,215,228,26,216,156,173,227,69,101,119,119]},\"statechain_sig\":{\"purpose\":\"TRANSFER\",\"data\":\"022d7ea3d286541ed593e0158e315d73908646abcfa46aa56c12229a2910cce48c\",\"sig\":\"3045022100869f749bc9f194076d105574ac74dafa6a07c54c6a5347d99916da11ad7edf5d0220047ee8579676babbb3990b9e95b84f8bc5f2df7082d12d789e28d7c15c15f8af\"},\"o2_pub\":{\"x\":\"4f42b26991577385dd4155a702306ff1b7c4bc89f10d98741b5998cbd6c8e708\",\"y\":\"2193d0f3600d4f7d430ac281dc7e07c9700e44bd77aabd45a7d6ea23667566fb\"},\"tx_backup_hex\":\"0200000000010170fab16bf256c5262c064ff7153edd77ddedb09a9fddcba656e132848b094ec00000000000feffffff02b824000000000000160014c4a4890486350f57f1b9418877487f479eec13352c010000000000001600141319a227287cfac4d8660830f4c9b0e1724a81000247304402205d3aebbce7863d1c7427b85cc4b85561040a6ad58d9b8f071c1ff92d2962eb1502203c794fc2959e09ea243444dedabb59f712ba3e3d47ad48ab0ca54a10ae6c281801210256185198842dae834fa3b98a11eec9864beb535c894038ccaa8fb728bc29338c17340000\",\"batch_data\":null}";
    static FINALIZED_DATA: &str = "{\"new_shared_key_id\":\"a693a98e-d370-42a0-be22-0ce6a9887ed9\",\"statechain_id\":\"64070bf6-50af-4ee6-93c1-11e5f9588b39\",\"statechain_sig\":{\"purpose\":\"TRANSFER\",\"data\":\"022d7ea3d286541ed593e0158e315d73908646abcfa46aa56c12229a2910cce48c\",\"sig\":\"3045022100869f749bc9f194076d105574ac74dafa6a07c54c6a5347d99916da11ad7edf5d0220047ee8579676babbb3990b9e95b84f8bc5f2df7082d12d789e28d7c15c15f8af\"},\"s2\":\"aaa600f5e6bf19640203868a01cb1964005a0577b7393441d41c02ff8b80ba3d\",\"new_tx_backup_hex\":\"0200000000010170fab16bf256c5262c064ff7153edd77ddedb09a9fddcba656e132848b094ec00000000000feffffff02b824000000000000160014c4a4890486350f57f1b9418877487f479eec13352c010000000000001600141319a227287cfac4d8660830f4c9b0e1724a81000247304402205d3aebbce7863d1c7427b85cc4b85561040a6ad58d9b8f071c1ff92d2962eb1502203c794fc2959e09ea243444dedabb59f712ba3e3d47ad48ab0ca54a10ae6c281801210256185198842dae834fa3b98a11eec9864beb535c894038ccaa8fb728bc29338c17340000\",\"batch_data\":null}";
    pub static PARTY_1_PRIVATE: &str = "{\"x1\":\"90dcad79e709cd0e9721ea530bdaae824f25d694f9141d44c34f8c45b83a619a\",\"paillier_priv\":{\"p\":\"114413871311317346857216248124398373253057789180865139463658909581309809925099684086705518674269955826879417786610662265699564218950421752552463442949710298739699236291018601890635623572620844010612962848524109675418307426543377258756575401823280458998724649947851944337182752344801543308408780339793598493911\",\"q\":\"143642110993616480789938157546368017212072711379036975069374679010429977311234473719247827342504091910445056259588213765288791327321051188553463176893894215343606711582011189827766980183694378516680292236218631062799658567268548617381466151102553381323573366960980002823730109177797219479930574386517898816387\"},\"c_key_randomness\":\"185cb997a51310b4d9b8d58db7b6c6bd401e92af0f310aa7d91421be8396ba2cd521225b4cefe13341a7a609f4c06a7632231fbbc2ee3d3e62387e13d62ca3e9ca43ab89da60a139177c309d86651d4283463d40c5b9cb842156ba0591d436743a4fcd34863df434f724a4f67b694904a6de829e8ab70b7c79930b7230b2bab65653ade92da15dd31d3a6a34227a323322868d84e162cffe4c731e8b5e83f0921c69d48ebe9c2fcbe976dd59ab38709cf76ae155f33916333938a22551aea66a2c2ccd40712d55b2d8f477354700d83f179010d6374971a9994dfe5d67bcc69ef07f48a5034b5e63953eed4ab15ac9d40162a9bb1c66c70fca85bd625cea4fc7\"}";
    pub static PARTY_2_PUBLIC: &str = "{\"x\":\"5220bc6ebcc83d0a1e4482ab1f2194cb69648100e8be78acde47ca56b996bd9e\",\"y\":\"8dfbb36ef76f2197598738329ffab7d3b3a06d80467db8e739c6b165abc20231\"}";
    static STATE_CHAIN: &str = "{\"chain\":[{\"data\":\"026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e\",\"next_state\":null}]}";
    static STATE_CHAIN_SIG: &str = "{\"purpose\":\"WITHDRAW\",\"data\":\"bcrt1qt3jh638mmuzmh92jz8c4wj392p9gj2erf2zut8\",\"sig\":\"304402201abaa7f64b50e8a75ca840a2be6317b501e3b5b5abd057465c165c9b872799f4022000d8e36734857237cab323c7244dd5249295b51905b43bf4e93396b58317d872\"}";
    
    #[test]
    fn test_transfer_sender() {
        let transfer_msg_4 =
            serde_json::from_str::<TransferMsg4>(&TRANSFER_MSG_4.to_string()).unwrap();
        let shared_key_id = transfer_msg_4.shared_key_id;
        let no_sc_shared_key_id = Uuid::from_str("deadb33f-1111-46f9-aaaa-0678c891b2d3").unwrap(); // random Uuid
        let statechain_id = transfer_msg_4.statechain_id;
        let statechain_sig: StateChainSig =
            serde_json::from_str::<TransferMsg4>(&TRANSFER_MSG_4.to_string())
                .unwrap()
                .statechain_sig;
        let tx_backup: Transaction = serde_json::from_str(&BACKUP_TX_NOT_SIGNED).unwrap();
        let transfer_msg_1 = TransferMsg1 {
            shared_key_id,
            statechain_sig,
            batch_id: None
        };

        let mut db = MockDatabase::new();
        let (_privkey, pubkey) = shared_lib::util::keygen::generate_keypair();
        db.expect_get_proof_key()
            .returning(move |_| Ok(pubkey.to_string()));
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_get_user_auth()
           .returning(|_user_id| Ok(String::from("user_auth")));

           db.expect_get_withdraw_confirm_data()
           .returning(move |_| {
               Ok(WithdrawConfirmData {
                   tx_withdraw: serde_json::from_str(&BACKUP_TX_NOT_SIGNED).unwrap(), // any tx is fine here
                   withdraw_sc_sig: serde_json::from_str::<StateChainSig>(
                       &STATE_CHAIN_SIG.to_string(),
                   )
                   .unwrap(),
                   statechain_id,
               })
           });

        db.expect_get_statechain_id()
            .with(predicate::eq(shared_key_id))
            .returning(move |_| Ok(statechain_id));
        db.expect_get_backup_transaction_and_proof_key()
            .with(predicate::eq(shared_key_id))
            .returning(move |_| Ok((tx_backup.clone(), no_sc_shared_key_id.to_string())));        
        // userid does not own a state
        db.expect_get_statechain_id()
            .with(predicate::eq(no_sc_shared_key_id))
            .returning(move |_| {
                Err(SEError::DBError(
                    DBErrorType::NoDataForID,
                    no_sc_shared_key_id.to_string(),
                ))
            });
        db.expect_transfer_is_completed()
            .with(predicate::eq(statechain_id))
            .returning(|_| false);
        db.expect_get_statechain_owner() // sc locked
            .with(predicate::eq(statechain_id))
            .times(1)
            .returning(move |_| {
                Ok(StateChainOwner {
                    locked_until: Utc::now().naive_utc() + Duration::seconds(5),
                    owner_id: shared_key_id,
                    chain: serde_json::from_str::<StateChainUnchecked>(&STATE_CHAIN.to_string()).unwrap().try_into().unwrap(),
                })
            });
        db.expect_get_statechain_owner()
            .with(predicate::eq(statechain_id))
            .returning(move |_| {
                Ok(StateChainOwner {
                    locked_until: Utc::now().naive_utc(),
                    owner_id: shared_key_id,
                    chain: serde_json::from_str::<StateChainUnchecked>(&STATE_CHAIN.to_string()).unwrap().try_into().unwrap(),
                })
            });
        db.expect_create_transfer().returning(|_, _, _, _| Ok(()));
        db.expect_update_transfer_msg().returning(|_, _| Ok(()));
        db.expect_set_confirmed().returning(|_| Ok(()));

        let sc_entity = test_sc_entity(db, None, None, None, None);

        // user does not own State Chain
        let mut msg_1_wrong_shared_key_id = transfer_msg_1.clone();
        msg_1_wrong_shared_key_id.shared_key_id = no_sc_shared_key_id;
        match sc_entity.transfer_sender(msg_1_wrong_shared_key_id) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("DB Error: No data for identifier.")),
        }

        // Sc locked
        match sc_entity.transfer_sender(transfer_msg_1.clone()) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e
                .to_string()
                .contains("SharedLibError Error: Error: State Chain locked for 1 minutes.")),
        }

        assert!(sc_entity.transfer_sender(transfer_msg_1).is_ok());
    }

    #[test]
    fn test_multi_transfer() {
        let transfer_msg_5 = do_transfer_receiver();
        assert!(transfer_msg_5.is_ok());
    }

    #[test]
    fn test_transfer_receiver() {
        assert!(do_transfer_receiver().is_ok())
    }

    fn do_transfer_receiver() -> Result<TransferMsg5> {
        let transfer_msg_4 =
            serde_json::from_str::<TransferMsg4>(&TRANSFER_MSG_4.to_string()).unwrap();
        let shared_key_id = transfer_msg_4.shared_key_id;
        let statechain_id = transfer_msg_4.statechain_id;
        let s2 = serde_json::from_str::<TransferFinalizeData>(&FINALIZED_DATA.to_string())
            .unwrap()
            .s2;
        let msg2: TransferMsg2 = serde_json::from_str(&TRANSFER_MSG_2.to_string()).unwrap();
        let x1 = msg2.x1.get_fe().expect("failed to get fe");

        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_get_user_auth()
           .returning(|_user_id| Ok(String::from("user_auth")));
        db.expect_get_transfer_data()
            .with(predicate::eq(statechain_id))
            .returning(move |_| {
                Ok(TransferData {
                    statechain_id,
                    statechain_sig: serde_json::from_str::<TransferMsg4>(
                        &TRANSFER_MSG_4.to_string(),
                    )
                    .unwrap()
                    .statechain_sig,
                    x1,
                    batch_id: None
                })
            });
        db.expect_get_ecdsa_keypair()
            .with(predicate::eq(shared_key_id))
            .returning(|_| {
                Ok(ECDSAKeypair {
                    party_1_private: serde_json::from_str(&PARTY_1_PRIVATE.to_string()).unwrap(),
                    party_2_public: serde_json::from_str(&PARTY_2_PUBLIC.to_string()).unwrap(),
                })
            });
        db.expect_get_statechain().returning(move |_| {
            Ok(serde_json::from_str::<StateChainUnchecked>(&STATE_CHAIN.to_string()).unwrap().try_into().unwrap())
        });
        db.expect_get_statechain_owner() //Lockbox update
        .with(predicate::eq(statechain_id))
        .returning(move |_| {
            Ok(StateChainOwner {
                locked_until: Utc::now().naive_utc(),
                owner_id: shared_key_id,
                chain: serde_json::from_str::<StateChainUnchecked>(&STATE_CHAIN.to_string()).unwrap().try_into().unwrap(),
            })
        });
        db.expect_get_lockbox_index().returning(|_| Ok(None));
        db.expect_update_statechain_owner()
            .returning(|_, _, _| Ok(()));
        db.expect_transfer_init_user_session()
            .returning(|_, _, _, _| Ok(()));
        db.expect_update_backup_tx().returning(|_, _| Ok(()));
        db.expect_remove_transfer_data().returning(|_| Ok(()));
        db.expect_root_get_current_id().returning(|| Ok(1 as i64));
        db.expect_get_root().returning(|_| Ok(None));
        db.expect_root_update().returning(|_| Ok(1));
        db.expect_get_finalize_batch_data().returning(move |_| {
            Ok(TransferFinalizeBatchData {
                finalized_data_vec: vec![TransferFinalizeData {
                    new_shared_key_id: shared_key_id,
                    statechain_id,
                    statechain_sig: serde_json::from_str::<TransferMsg4>(
                        &TRANSFER_MSG_4.to_string(),
                    )
                    .unwrap()
                    .statechain_sig,
                    s2: s2,
                    new_tx_backup_hex: transaction_serialise(
                        &serde_json::from_str::<Transaction>(
                            &BACKUP_TX_NOT_SIGNED.to_string(),
                        )
                        .unwrap()
                    ),
                    batch_data: Some(BatchData {
                        id: shared_key_id,
                        commitment: String::default(),
                    }),
                }],
                start_time: Utc::now().naive_utc(),
            })
        });
        db.expect_get_transfer_batch_start_time()
        .times(1)
        .returning(move |_| Ok(Utc::now().naive_utc() - Duration::seconds(999999)));
        db.expect_get_transfer_batch_start_time()
        .times(1)
        .returning(move |_| Ok(Utc::now().naive_utc() - Duration::seconds(1)));

        db.expect_update_finalize_batch_data()
            .returning(|_, _| Ok(()));

        let sc_entity = test_sc_entity(db, None, None, None, None);
        let _m = mocks::ms::post_commitment().create(); //Mainstay post commitment mock

        // Input data to transfer_receiver
        let mut transfer_msg_4 =
            serde_json::from_str::<TransferMsg4>(&TRANSFER_MSG_4.to_string()).unwrap();

        // Incorrect x1, t1 or t2 => t2 is incorrect
        let mut msg_4_incorrect_t2 = transfer_msg_4.clone();

        //Generate an invalid x1 by adding x1 to itself
        let sk = x1.get_element();
        let x1_invalid = x1.add(&sk);
        msg_4_incorrect_t2.t2 = FESer::from_fe(&x1_invalid);

        match sc_entity.transfer_receiver(msg_4_incorrect_t2) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("Error: Invalid message")),
        }

        // StateChain incorreclty signed for
        let mut msg_4_incorrect_sc = transfer_msg_4.clone();
        msg_4_incorrect_sc.statechain_sig.data =
            "deadb33f88579c6aafcfcc8ca91b0556a2044e6c61dfb7fca5f90c40ed119349ec".to_string();
        match sc_entity.transfer_receiver(msg_4_incorrect_sc) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e
                .to_string()
                .contains("Error: State chain siganture provided does not match state chain at")),
        }

        assert!(sc_entity.transfer_receiver(transfer_msg_4.clone()).is_ok());

        // Test transfer involved in batch
        transfer_msg_4.batch_data = Some(BatchData {
            id: shared_key_id,
            commitment: String::default(),
        });

        // Batch lifetime over
        match sc_entity.transfer_receiver(transfer_msg_4.clone()) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e
                .to_string()
                .contains("Error: Transfer batch ended. Too late to complete transfer.")),
        }

        sc_entity.transfer_receiver(transfer_msg_4)
    }

    #[test]
    fn do_transfer_receiver_lockbox() {
        let mut transfer_msg_4 =
            serde_json::from_str::<TransferMsg4>(&TRANSFER_MSG_4.to_string()).unwrap();
        let shared_key_id = transfer_msg_4.shared_key_id;
        let statechain_id = transfer_msg_4.statechain_id;
        let s2 = serde_json::from_str::<TransferFinalizeData>(&FINALIZED_DATA.to_string())
            .unwrap()
            .s2;
        let msg2: TransferMsg2 = serde_json::from_str(&TRANSFER_MSG_2.to_string()).unwrap();
        let x1 = msg2.x1.get_fe().expect("failed to get fe");

        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_get_user_auth()
           .returning(|_user_id| Ok(String::from("user_auth")));
        db.expect_get_transfer_data()
            .with(predicate::eq(statechain_id))
            .returning(move |_| {
                Ok(TransferData {
                    statechain_id,
                    statechain_sig: serde_json::from_str::<TransferMsg4>(
                        &TRANSFER_MSG_4.to_string(),
                    )
                    .unwrap()
                    .statechain_sig,
                    x1,
                    batch_id: None
                })
            });
        db.expect_get_ecdsa_keypair()
            .with(predicate::eq(shared_key_id))
            .returning(|_| {
                Ok(ECDSAKeypair {
                    party_1_private: serde_json::from_str(&PARTY_1_PRIVATE.to_string()).unwrap(),
                    party_2_public: serde_json::from_str(&PARTY_2_PUBLIC.to_string()).unwrap(),
                })
            });
        db.expect_get_statechain().returning(move |_| {
            Ok(serde_json::from_str::<StateChainUnchecked>(&STATE_CHAIN.to_string()).unwrap().try_into().unwrap())
        });

        db.expect_get_statechain_owner() //Lockbox update
        .with(predicate::eq(statechain_id))
        .returning(move |_| {
            Ok(StateChainOwner {
                locked_until: Utc::now().naive_utc(),
                owner_id: shared_key_id,
                chain: serde_json::from_str::<StateChainUnchecked>(&STATE_CHAIN.to_string()).unwrap().try_into().unwrap(),
            })
        });
        db.expect_get_lockbox_index().returning(|_| Ok(Some(0)));
        db.expect_update_lockbox_index().returning(|_,_|Ok(()));
        db.expect_update_statechain_owner()
            .returning(|_, _, _| Ok(()));
        db.expect_transfer_init_user_session()
            .returning(|_, _, _, _| Ok(()));
        db.expect_update_backup_tx().returning(|_, _| Ok(()));
        db.expect_remove_transfer_data().returning(|_| Ok(()));
        db.expect_root_get_current_id().returning(|| Ok(1 as i64));
        db.expect_get_root().returning(|_| Ok(None));
        db.expect_root_update().returning(|_| Ok(1));
        db.expect_get_finalize_batch_data().returning(move |_| {
            Ok(TransferFinalizeBatchData {
                finalized_data_vec: vec![TransferFinalizeData {
                    new_shared_key_id: shared_key_id,
                    statechain_id,
                    statechain_sig: serde_json::from_str::<TransferMsg4>(
                        &TRANSFER_MSG_4.to_string(),
                    )
                    .unwrap()
                    .statechain_sig,
                    s2: s2,
                    new_tx_backup_hex: transaction_serialise(
                        &serde_json::from_str::<Transaction>(
                            &BACKUP_TX_NOT_SIGNED.to_string(),
                        ).unwrap()),
                    batch_data: Some(BatchData {
                        id: shared_key_id,
                        commitment: String::default(),
                    }),
                }],
                start_time: Utc::now().naive_utc(),
            })
        });
        db.expect_update_finalize_batch_data()
            .returning(|_, _| Ok(()));

        let sc_entity = test_sc_entity(db, Some(mockito::server_url()), None, None, None);
        let _m = mocks::ms::post_commitment().create(); //Mainstay post commitment mock

        // simulate lockbox secret operations
        let kp = ECDSAKeypair {
                    party_1_private: serde_json::from_str(&PARTY_1_PRIVATE.to_string()).unwrap(),
                    party_2_public: serde_json::from_str(&PARTY_2_PUBLIC.to_string()).unwrap(),
                };
        let s1 = kp.party_1_private.get_private_key();

        let s1_priv = PrivateKey {
            compressed: true,
            network: Network::Regtest,
            key: SecretKey::from_slice(&BigInt::to_vec(&s1.clone().to_big_int())).unwrap(),
        };

        match transfer_msg_4.decrypt(&s1_priv) {
            Ok(_) => (),
            Err(e) => println!("{:?}", e.to_string()),
        };

        let t2 = transfer_msg_4.t2;

        //let mut rng = OsRng::new().expect("OsRng");
        let s2t = t2.get_fe().unwrap() * (x1.invert()) * s1;
        let g: GE = ECPoint::generator();
        let s2_pub = g * s2t;

        let ku_lb_rec = KUReceiveMsg {
            s2_pub,
        };

        let serialized_m1 = serde_json::to_string(&ku_lb_rec).unwrap();

        let _m_1 = mockito::mock("POST", "/ecdsa/keyupdate/first")
          .with_header("content-type", "application/json")
          .with_body(serialized_m1)
          .create();

        let ku_lb_fin_rec = KUAttest {
            statechain_id,
            attestation: "Attestation".to_string(),
        };

        let serialized_m2 = serde_json::to_string(&ku_lb_fin_rec).unwrap();

        let _m_2 = mockito::mock("POST", "/ecdsa/keyupdate/second")
          .with_header("content-type", "application/json")
          .with_body(serialized_m2)
          .create();

        // Input data to transfer_receiver
        let transfer_msg_4 =
            serde_json::from_str::<TransferMsg4>(&TRANSFER_MSG_4.to_string()).unwrap();

        // StateChain incorreclty signed for
        let mut msg_4_incorrect_sc = transfer_msg_4.clone();
        msg_4_incorrect_sc.statechain_sig.data =
            "deadb33f88579c6aafcfcc8ca91b0556a2044e6c61dfb7fca5f90c40ed119349ec".to_string();
        match sc_entity.transfer_receiver(msg_4_incorrect_sc) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e
                .to_string()
                .contains("Error: State chain siganture provided does not match state chain at")),
        }
        // Expected successful run
        sc_entity.transfer_receiver(transfer_msg_4.clone()).expect("expected transfer_receiver to return Ok");
    }
}
