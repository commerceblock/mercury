//! StateEntity Transfer
//!
//! StateEntity Transfer protocol trait and implementation.

pub use super::super::Result;
extern crate shared_lib;
extern crate reqwest;
use crate::server::TRANSFERS_COUNT;
use super::transfer_batch::transfer_batch_is_ended;
use shared_lib::{ecies, ecies::WalletDecryptable, ecies::SelfEncryptable, state_chain::*, structs::*, util::transaction_deserialise};
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

/// Struct holds data when transfer is complete but not yet finalized
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferFinalizeData {
    pub new_shared_key_id: Uuid,
    pub statechain_id: Uuid,
    pub statechain_sig: StateChainSig,
    pub s2: FE,
    pub new_tx_backup_hex: String,
    pub batch_data: Option<BatchData>,
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
}

impl Transfer for SCE {
    fn transfer_sender(&self, transfer_msg1: TransferMsg1) -> Result<TransferMsg2> {
        let user_id = transfer_msg1.shared_key_id;
        self.check_user_auth(&user_id)?;

        info!("TRANSFER: Sender Side. Shared Key ID: {}", user_id);

        // Get state_chain id
        let statechain_id = self.database.get_statechain_id(user_id)?;

        // Get back up tx and proof key
        let (tx_backup,_) = self.database.get_backup_transaction_and_proof_key(user_id)?;

        // Check that the funding transaction has the required number of confirmations
        self.verify_tx_confirmed(&tx_backup.input[0].previous_output.txid.to_string())?;

        // Check if transfer has already been completed (but not finalized)
        if self.database.transfer_is_completed(statechain_id) {
            return Err(SEError::Generic(String::from(
                "Transfer already completed. Waiting for finalize.",
            )));
        }

        // Check if state chain is owned by user and not locked
        let sco = self.database.get_statechain_owner(statechain_id)?;

        is_locked(sco.locked_until)?;
        if sco.owner_id != user_id {
            return Err(SEError::Generic(format!(
                "State Chain not owned by User ID: {}.",
                user_id
            )));
        }

        // Generate x1
        let x1: FE = ECScalar::new_random();
        let x1_ser = FESer::from_fe(&x1);

        self.database
            .create_transfer(&statechain_id, &transfer_msg1.statechain_sig, &x1)?;

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
        info!("transfer receiver: TransferMsg4 received: {:?}", transfer_msg4);
        let user_id = transfer_msg4.shared_key_id;
        let statechain_id = transfer_msg4.statechain_id;

        info!("TRANSFER: Receiver side. Shared Key ID: {}", user_id);

        // Get Transfer Data for statechain_id
        let td = self.database.get_transfer_data(statechain_id)?;

        // Ensure statechain_sigs are the same
        if td.statechain_sig != transfer_msg4.statechain_sig.to_owned() {
            return Err(SEError::Generic(format!(
                "State chain siganture provided does not match state chain at id {}",
                statechain_id
            )));
        }

        let s2: FE;
        let s2_pub: GE;
        if self.lockbox.active {
            let ku_send = KUSendMsg {
                user_id,
                statechain_id,
                x1: td.x1,
                t2: transfer_msg4.t2,
                o2_pub: transfer_msg4.o2_pub,
            };
            let path: &str = "ecdsa/keyupdate/first";
            let ku_receive: KUReceiveMsg = post_lb(&self.lockbox, path, &ku_send)?;
            s2 = FE::zero();
            s2_pub = ku_receive.s2_pub;
        }
        else {
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
        }

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
            info!(
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
            info!(
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

        state_chain.add(finalized_data.statechain_sig.to_owned())?;

        let new_user_id = finalized_data.new_shared_key_id;

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
        )?;

        //lockbox finalise and delete key
        if self.lockbox.active {
            let ku_send = KUFinalize {
                statechain_id,
                shared_key_id: new_user_id,
            };
            let path: &str = "ecdsa/keyupdate/second";
            let _ku_receive: KUAttest = post_lb(&self.lockbox, path, &ku_send)?;
        }

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
                .chain
                .last()
                .ok_or(SEError::Generic(String::from("StateChain empty")))?
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
}

#[openapi]
/// # Transfer initiation by sender: get x1 and new backup transaction
#[post("/transfer/sender", format = "json", data = "<transfer_msg1>")]
pub fn transfer_sender(
    sc_entity: State<SCE>,
    transfer_msg1: Json<TransferMsg1>,
) -> Result<Json<TransferMsg2>> {
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
    match sc_entity.transfer_get_msg(statechain_id.id) {
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

    // Data from a run of transfer protocol.
    // static TRANSFER_MSG_1: &str = "{\"shared_key_id\":\"707ea4c9-5ddb-4f08-a240-2b4d80ae630d\",\"statechain_sig\":{\"purpose\":\"TRANSFER\",\"data\":\"0213be735d05adea658d78df4719072a6debf152845044402c5fe09dd41879fa01\",\"sig\":\"3044022028d56cfdb4e02d46b2f8158b0414746ddf42ecaaaa995a3a02df8807c5062c0202207569dc0f49b64ae997b4c902539cddc1f4e4434d6b4b05af38af4b98232ebee8\"}}";
    static TRANSFER_MSG_2: &str = "{\"x1\":{\"secret_bytes\":[88,245,63,83,101,154,49,170,232,129,177,102,30,130,74,32,197,83,72,92,6,154,167,239,106,224,14,55,162,67,230,112]},\"proof_key\":\"0325e1688baf8ab36e40be1e5362bd4bb24f78e2428aa8ff7631fc2fd8bd0a8bbc\"}";
    // static TRANSFER_MSG_3: &str = "{\"shared_key_id\":\"707ea4c9-5ddb-4f08-a240-2b4d80ae630d\",\"t1\":\"34c9a329617b8dd3cdeb3d491fa09f023f84f28005bdf40f0682eb020969183b\",\"statechain_sig\":{\"purpose\":\"TRANSFER\",\"data\":\"0213be735d05adea658d78df4719072a6debf152845044402c5fe09dd41879fa01\",\"sig\":\"3044022028d56cfdb4e02d46b2f8158b0414746ddf42ecaaaa995a3a02df8807c5062c0202207569dc0f49b64ae997b4c902539cddc1f4e4434d6b4b05af38af4b98232ebee8\"},\"statechain_id\":\"9b0ba36b-406a-499c-8c83-696b77f003a9\",\"tx_backup_psm\":{\"shared_key_id\":\"707ea4c9-5ddb-4f08-a240-2b4d80ae630d\",\"protocol\":\"Transfer\",\"tx\":{\"version\":2,\"lock_time\":0,\"input\":[{\"previous_output\":\"53e1d67d837fdaddb016c5de85d8903bc033f7f2208d3ff40430fc42edeab4cb:0\",\"script_sig\":\"\",\"sequence\":4294967295,\"witness\":[[48,69,2,33,0,177,248,103,71,170,95,47,217,222,7,130,181,12,9,254,115,96,166,180,164,162,4,14,110,145,113,106,97,155,231,190,22,2,32,63,119,90,178,253,249,43,242,42,177,250,25,29,251,156,37,12,61,70,252,201,155,252,188,56,242,36,211,50,136,203,95,1],[2,108,195,112,80,86,19,121,166,106,134,63,140,162,115,194,178,158,147,92,173,6,188,127,94,107,131,160,62,11,191,241,230]]}],\"output\":[{\"value\":9000,\"script_pubkey\":\"0014a5c378a7de7311e6836253a28830b48cc6b9e252\"}]},\"input_addrs\":[\"026cc37050561379a66a863f8ca273c2b29e935cad06bc7f5e6b83a03e0bbff1e6\"],\"input_amounts\":[10000],\"proof_key\":\"0213be735d05adea658d78df4719072a6debf152845044402c5fe09dd41879fa01\"},\"rec_se_addr\":{\"tx_backup_addr\":\"bcrt1q5hph3f77wvg7dqmz2w3gsv953nrtncjjzyj3m9\",\"proof_key\":\"0213be735d05adea658d78df4719072a6debf152845044402c5fe09dd41879fa01\"}}";
    static TRANSFER_MSG_4: &str = "{\"shared_key_id\":\"c2c864d0-12df-4a31-ad17-1d9779b55097\",\"statechain_id\":\"86d9483a-11f6-412a-b117-572695f9f7dd\",\"t2\":{\"secret_bytes\":[4,244,43,195,129,203,211,215,196,36,206,154,82,104,119,27,73,46,95,178,212,1,242,72,74,179,197,30,0,234,137,66,249,208,187,141,37,85,176,22,242,152,190,240,46,206,104,114,58,35,4,76,17,4,136,183,40,225,11,73,235,132,28,129,7,89,81,112,187,237,202,12,174,109,83,170,103,238,138,195,137,138,67,30,48,57,115,151,45,39,212,92,99,15,128,206,50,123,74,105,27,53,250,96,22,69,134,143,163,193,249,12,172,33,38,109,45,178,183,162,162,238,64,65,62,233,219,98,120]},\"statechain_sig\":{\"purpose\":\"TRANSFER\",\"data\":\"02ec87054ed8d2f04ac9d71f44243023821fec6fc60f3e230ffa7626089033d8b1\",\"sig\":\"3044022005dbe013f6d93725a92af0c1bca687c8d8b02167ef13e221470d361127e537fb02205157db1b5267ba985339bd8e0d944d8a77ea465fcd8acb80761cfefbabf39661\"},\"o2_pub\":{\"x\":\"6e7374dc612b65f1f3b634b82ca867e66635e65bf29794b256047bbd8f2dc911\",\"y\":\"fc04939b4df3cca6fadebff3f8188b6a77f396446e04e818ce16daf76aebe0a3\"},\"tx_backup_hex\":\"02000000000101adb81a8811447ae7d568c42e55ad2725fa67f5c3e471342ba7fcac1a4055bb620000000000ffffffff02eca800000000000016001460804be0d67f1107dae3af48f4a20223572e97dd58050000000000001600141319a227287cfac4d8660830f4c9b0e1724a8100024730440220334cbb130ccb168121741e33b87b83c1f7d07f504c5a181973ad82a2e93482fa02203bb31ef62bf08d2ed268fb7042665be5a3f686519a4c0765fa58757b713536cf01210353ce5b54d23d07de4828cb96d0485f6ab1a8db9c589486cd8d4362524bee405317340000\",\"batch_data\":null}";
    static FINALIZED_DATA: &str = "{\"new_shared_key_id\":\"d1a3a9a6-b64e-4b4e-b3c6-0c55a0e1f8c6\",\"statechain_id\":\"86d9483a-11f6-412a-b117-572695f9f7dd\",\"statechain_sig\":{\"purpose\":\"TRANSFER\",\"data\":\"02ec87054ed8d2f04ac9d71f44243023821fec6fc60f3e230ffa7626089033d8b1\",\"sig\":\"3044022005dbe013f6d93725a92af0c1bca687c8d8b02167ef13e221470d361127e537fb02205157db1b5267ba985339bd8e0d944d8a77ea465fcd8acb80761cfefbabf39661\"},\"s2\":\"9a06341e81792bca72ef7120e94c93a3c97e8f150f9c4fd57f1758f50232f938\",\"new_tx_backup_hex\":\"02000000000101adb81a8811447ae7d568c42e55ad2725fa67f5c3e471342ba7fcac1a4055bb620000000000ffffffff02eca800000000000016001460804be0d67f1107dae3af48f4a20223572e97dd58050000000000001600141319a227287cfac4d8660830f4c9b0e1724a8100024730440220334cbb130ccb168121741e33b87b83c1f7d07f504c5a181973ad82a2e93482fa02203bb31ef62bf08d2ed268fb7042665be5a3f686519a4c0765fa58757b713536cf01210353ce5b54d23d07de4828cb96d0485f6ab1a8db9c589486cd8d4362524bee405317340000\",\"batch_data\":null}";
    pub static PARTY_1_PRIVATE: &str = "{\"x1\":\"62fccd3b8e1ec9847a81da39dbd12248649a56a5bd826993a0be1ef7e5dbaff6\",\"paillier_priv\":{\"p\":\"175105153600741631732008635643568979650827093652618445865555498830310239779193993937919065748609864882562533521325401979357004940357735331137242744377931301179917304999674039005453503946248939473532166164488354001195043141677905998318715771948374633284282386723061505364048790027483575020641965955188382828043\",\"q\":\"176107056094363704009530683741685388080833654947191096034654854567664678756371593133182239495448766868278040275902304993107585397542355074990977649321727244853545689372964609905231205840920297987033622047920439606987774726496544858149573923439784574804611753120265479364394401830948243108767573192431824915223\"},\"c_key_randomness\":\"c3d4d31f59de5dc74bd5f89a92d498197ea5fd93069556cde819db50b0fa9fc4649ee5f89404d943c2a227453defb2c58908869f13ec12897b150778c41dd037a6c88015e53be46beeed355ce2e41d8351005b06264f397cde4adde9d881e9abf3d4278a89b1d66beb335a4f81128e1e78e069a8ddfee1756585ff3aa80f714fe4f4ced8822b73a1d8c9c04375b76f055791a60b683443eb959ffb292aa152fd23561a69bfe20c1d711cc8be4a404591bf04cab07c472ca013e06b9b370cdb53a668af4f1646854a225a7cf07ea12e6c53f7d55014d445d2a1ed061e2320656a4afad19593f9de4fef4f0c73f018373a0eb61b7cd8c1d5efd1c485bd90b845bb\"}";
    pub static PARTY_2_PUBLIC: &str = "{\"x\":\"f4d5ddb9e3a9aab03a75b30b287e007016894c528d2d41949a142c8361a6323a\",\"y\":\"67905d786f47a76a09338bed4360327b12831afdf01d376dd3d2308d882c9f3a\"}";
    static STATE_CHAIN: &str = "{\"chain\":[{\"data\":\"0325e1688baf8ab36e40be1e5362bd4bb24f78e2428aa8ff7631fc2fd8bd0a8bbc\",\"next_state\":null}]}";

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
        };

        let mut db = MockDatabase::new();
        let (_privkey, pubkey) = shared_lib::util::keygen::generate_keypair();
        db.expect_get_proof_key()
            .returning(move |_| Ok(pubkey.to_string()));
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_get_user_auth()
            .returning(move |_| Ok(shared_key_id));
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
                    chain: serde_json::from_str::<StateChain>(&STATE_CHAIN.to_string()).unwrap(),
                })
            });
        db.expect_get_statechain_owner()
            .with(predicate::eq(statechain_id))
            .returning(move |_| {
                Ok(StateChainOwner {
                    locked_until: Utc::now().naive_utc(),
                    owner_id: shared_key_id,
                    chain: serde_json::from_str::<StateChain>(&STATE_CHAIN.to_string()).unwrap(),
                })
            });
        db.expect_create_transfer().returning(|_, _, _| Ok(()));
        db.expect_update_transfer_msg().returning(|_, _| Ok(()));

        let sc_entity = test_sc_entity(db);

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
            .returning(move |_| Ok(shared_key_id));
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
            Ok(serde_json::from_str::<StateChain>(&STATE_CHAIN.to_string()).unwrap())
        });
        db.expect_update_statechain_owner()
            .returning(|_, _, _| Ok(()));
        db.expect_transfer_init_user_session()
            .returning(|_, _, _| Ok(()));
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

        let sc_entity = test_sc_entity(db);
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
            .returning(move |_| Ok(shared_key_id));
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
            Ok(serde_json::from_str::<StateChain>(&STATE_CHAIN.to_string()).unwrap())
        });
        db.expect_update_statechain_owner()
            .returning(|_, _, _| Ok(()));
        db.expect_transfer_init_user_session()
            .returning(|_, _, _| Ok(()));
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

        let mut sc_entity = test_sc_entity(db);
        let _m = mocks::ms::post_commitment().create(); //Mainstay post commitment mock

        sc_entity.lockbox.active = true;
        sc_entity.lockbox.endpoint = mockito::server_url();

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
        assert!(sc_entity.transfer_receiver(transfer_msg_4.clone()).is_ok());
    }
}
