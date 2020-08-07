//! StateEntity Transfer
//!
//! StateEntity Transfer protocol trait and implementation.

pub use super::super::Result;
use super::transfer_batch::transfer_batch_is_ended;


extern crate shared_lib;
use crate::error::SEError;
use crate::Database;
use shared_lib::{state_chain::*, structs::*};
use crate::{server::StateChainEntity, storage::Storage};
use crate::{MockDatabase, PGDatabase};

use bitcoin::Transaction;
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    {BigInt, FE, GE},
};
use rocket::State;
use rocket_contrib::json::Json;
use uuid::Uuid;
use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(test)]{
        use MockDatabase as DB;
        type SCE = StateChainEntity::<MockDatabase>;
    } else {
        use PGDatabase as DB;
        type SCE = StateChainEntity::<PGDatabase>;
    }
}

/// Struct holds data when transfer is complete but not yet finalized
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferFinalizeData {
    pub new_shared_key_id: Uuid,
    pub state_chain_id: Uuid,
    pub state_chain_sig: StateChainSig,
    pub s2: FE,
    pub new_tx_backup: Transaction,
    pub batch_data: Option<BatchData>,
}

/// StateChain Transfer protocol trait
pub trait Transfer {
    /// API: Initiliase transfer protocol:
    ///     - Authorisation of Owner and DoS protection
    ///     - Validate transfer parameters
    ///     - Store transfer parameters
    fn transfer_sender(
        &self,
        transfer_msg1: TransferMsg1,
    ) -> Result<TransferMsg2>;

    /// API: Transfer shared wallet to new Owner:
    ///     - Check new Owner's state chain is correct
    ///     - Perform 2P-ECDSA key rotation
    ///     - Return new public shared key S2
    fn transfer_receiver(
        &self,
        transfer_msg4: TransferMsg4,
    ) -> Result<TransferMsg5>;

    /// Update DB and SMT after successful transfer.
    /// This function is called immediately in the regular transfer case or after confirmation of atomic
    /// transfers completion in the batch transfer case.
    fn transfer_finalize(
        &self,
        finalized_data: &TransferFinalizeData,
    ) -> Result<()>;
}

impl Transfer for SCE {
    fn transfer_sender(
        &self,
        transfer_msg1: TransferMsg1,
    ) -> Result<TransferMsg2> {
        let user_id = transfer_msg1.shared_key_id;
        self.check_user_auth(&user_id)?;

        info!("TRANSFER: Sender Side. Shared Key ID: {}", user_id);

        // Get state_chain id
        let state_chain_id = self.database.get_statechain_id(user_id)?;

        // Check if transfer has already been completed (but not finalized)
        if self.database.transfer_is_completed(state_chain_id){
            return Err(SEError::Generic(String::from(
                "Transfer already completed. Waiting for finalize.",
            )));
        }

        // Check if state chain is owned by user and not locked
        let sco = self.database.get_statechain_owner(state_chain_id)?;

        is_locked(sco.locked_until)?;
        if sco.owner_id != user_id {
            return Err(SEError::Generic(format!(
                "State Chain not owned by User ID: {}.",
                user_id
            )));
        }

        // Generate x1
        let x1: FE = ECScalar::new_random();

        self.database.create_transfer(&state_chain_id, &transfer_msg1.state_chain_sig, &x1)?;

        info!(
            "TRANSFER: Sender side complete. Previous shared key ID: {}. State Chain ID: {}",
            user_id.to_string(),
            state_chain_id
        );
        debug!("TRANSFER: Sender side complete. State Chain ID: {}. State Chain Signature: {:?}. x1: {:?}.", state_chain_id, transfer_msg1.state_chain_sig, x1);

        // TODO encrypt x1 with Senders proof key

        Ok(TransferMsg2 { x1 })
    }

    fn transfer_receiver(
        &self,
        transfer_msg4: TransferMsg4,
    ) -> Result<TransferMsg5> {
        let user_id = transfer_msg4.shared_key_id;
        let state_chain_id = transfer_msg4.state_chain_id;

        info!("TRANSFER: Receiver side. Shared Key ID: {}", user_id);

        // Get Transfer Data for state_chain_id
        let td = self.database.get_transfer_data(state_chain_id)?;

        // Ensure state_chain_sigs are the same
        if td.state_chain_sig != transfer_msg4.state_chain_sig.to_owned() {
            return Err(SEError::Generic(format!(
                "State chain siganture provided does not match state chain at id {}",
                state_chain_id
            )));
        }

        let kp = self.database.get_ecdsa_keypair(user_id)?;

        // TODO: decrypt t2

        // let x1 = transfer_data.x1;
        let t2 = transfer_msg4.t2;
        let s1 = kp.party_1_private.get_private_key();

        // Note:
        //  s2 = o1*o2_inv*s1
        //  t2 = o1*x1*o2_inv
        let s2 = t2 * (td.x1.invert()) * s1;

        // Check s2 is valid for Lindell protocol (s2<q/3)
        let sk_bigint = s2.to_big_int();
        let q_third = FE::q();
        if sk_bigint >= q_third.div_floor(&BigInt::from(3)) {
            return Err(SEError::Generic(format!("Invalid o2, try again.")));
        }

        let g: GE = ECPoint::generator();
        let s2_pub: GE = g * s2;

        let p1_pub = kp.party_2_public * s1;
        let p2_pub = transfer_msg4.o2_pub * s2;

        // Check P1 = o1_pub*s1 === p2 = o2_pub*s2
        if p1_pub != p2_pub {
            error!("TRANSFER: Protocol failed. P1 != P2.");
            return Err(SEError::Generic(String::from(
                "Transfer protocol error: P1 != P2",
            )));
        }

        // Create user ID for new UserSession (receiver of transfer)
        let new_shared_key_id = Uuid::new_v4();

        let finalized_data = TransferFinalizeData {
            new_shared_key_id: new_shared_key_id.clone(),
            state_chain_id: state_chain_id.clone(),
            state_chain_sig: td.state_chain_sig,
            s2,
            new_tx_backup: transfer_msg4.tx_backup.clone(),
            batch_data: transfer_msg4.batch_data.clone(),
        };

        // If batch transfer then mark StateChain as complete and store finalized data in TransferBatch table.
        // This is so the transfers can be finalized when all transfers in the batch are complete.
        if transfer_msg4.batch_data.is_some() {
            let batch_id = transfer_msg4.batch_data.clone().unwrap().id;
            info!(
                "TRANSFER: Transfer as part of batch {}. State Chain ID: {}",
                batch_id, state_chain_id
            );
            // Get TransferBatch data
            let mut tbd = self.database.get_finalize_batch_data(batch_id)?;

            // Ensure batch transfer is still active
            if transfer_batch_is_ended(tbd.start_time, self.config.batch_lifetime as i64) {
                return Err(SEError::Generic(String::from(
                    "Transfer batch ended. Too late to complete transfer.",
                )));
            }

            tbd.state_chains.insert(state_chain_id.clone(), true);
            tbd.finalized_data_vec.push(finalized_data.clone());

            self.database.update_finalize_batch_data(&batch_id, tbd.state_chains,
                                                        tbd.finalized_data_vec)?;

        // If not batch then finalize transfer now
        } else {
            // Update DB and SMT with new transfer data
            self.transfer_finalize(&finalized_data)?;
        }

        info!(
            "TRANSFER: Receiver side complete. State Chain ID: {}",
            new_shared_key_id
        );
        debug!("TRANSFER: Receiver side complete. State Chain ID: {}. New Shared Key ID: {}. Finalized data: {:?}",state_chain_id,state_chain_id,finalized_data);

        Ok(TransferMsg5 {
            new_shared_key_id,
            s2_pub,
        })
    }

    /// Update DB and SMT after successful transfer.
    /// This function is called immediately in the regular transfer case or after confirmation of atomic
    /// transfers completion in the batch transfer case.
    fn transfer_finalize(
        &self,
        finalized_data: &TransferFinalizeData,
    ) -> Result<()> {
        let state_chain_id = finalized_data.state_chain_id;

        info!("TRANSFER_FINALIZE: State Chain ID: {}", state_chain_id);

        // Update state chain
        let mut state_chain: StateChain = self.database.get_statechain(state_chain_id)?;

        state_chain.add(finalized_data.state_chain_sig.to_owned())?;


        let new_user_id = finalized_data.new_shared_key_id;

        self.database.update_statechain_owner(&state_chain_id,
            state_chain.clone(), &new_user_id)?;

        // Create new UserSession to allow new owner to generate shared wallet

        self.database.transfer_init_user_session(&new_user_id, &state_chain_id,
            finalized_data.to_owned())?;


        self.database.update_backup_tx(&state_chain_id, finalized_data.new_tx_backup.to_owned())?;


        info!(
            "TRANSFER: Finalized. New shared key ID: {}. State Chain ID: {}",
            finalized_data.new_shared_key_id, state_chain_id
        );

        // Update sparse merkle tree with new StateChain entry
        let (new_root, prev_root) = self.update_smt(
            &finalized_data
                .new_tx_backup
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
                .clone()
        )?;

        info!(
            "TRANSFER: Included in sparse merkle tree. State Chain ID: {}",
            state_chain_id
        );
        debug!(
            "TRANSFER: State Chain ID: {}. New root: {:?}. Previous root: {:?}.",
            state_chain_id, &new_root, &prev_root
        );

        // Remove TransferData for this transfer
        self.database.remove_transfer_data(&state_chain_id)?;

        Ok(())
    }
}

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


#[cfg(test)]
mod tests {
    use super::*;
    use shared_lib::Root;
    use std::str::FromStr;
    use std::convert::TryInto;
    use bitcoin::{secp256k1::{PublicKey, Secp256k1, SecretKey}, consensus, Transaction, util::misc::hex_bytes};
    use crate::structs::StateChainOwner;
    use chrono::Utc;
    use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one::Party1Private;

    fn test_transfer() {
        let user_id = Uuid::from_str("203001c9-93f0-46f9-aaaa-0678c891b2d3").unwrap();
        let state_chain_id = String::from("65aab40995d3ed5d03a0567b04819ff12641b84c17f5e9d5dd075571e183469c8f");
        let state_chain_id = Uuid::from_str("001203c9-93f0-46f9-abda-0678c891b2d3").unwrap();
        let sender_proof_key_priv = SecretKey::from_slice(&[1; 32]).unwrap(); // Proof key priv part
        let sender_proof_key = PublicKey::from_secret_key(&Secp256k1::new(), &sender_proof_key_priv);
        let receiver_proof_key_priv = SecretKey::from_slice(&[2; 32]).unwrap(); // Proof key priv part
        let receiver_proof_key = PublicKey::from_secret_key(&Secp256k1::new(), &receiver_proof_key_priv);

        let state_chain = StateChain::new(sender_proof_key_priv.to_string());
        let state_chain_owner = StateChainOwner{
            locked_until: Utc::now().naive_utc(),
            owner_id: user_id,
            chain: state_chain
        };
        let state_chain_sig = StateChainSig::new(&sender_proof_key_priv, &"TRANSFER".to_string(), &receiver_proof_key.to_string());


        // Sender

        // server.expect_check_user_auth(user_id)
        // .returning(|_| Ok());

        // db.expect_get_statechain_id(user_id)
        // .returning(|_| Ok(state_chain_id));

        // db.expect_transfer_is_completed(state_chain_id)
        // .returning(|_| Ok(false));

        // db.expect_get_statechain_owner(state_chain_id)
        // .returning(|_| Ok(StateChainOwner{
        //     locked_until: Utc::now().naive_utc(),
        //     owner_id: user_id,
        //     chain: StateChain::new(proof_key)
        // }));

        // db.expect_create_transfer(_)
        // .returning(|_| Ok());

        // let x1 = server.transfer_sender(TransferMsg1{
        //     shared_key_id: user_id,
        //     state_chain_sig: state_chain_sig
        // } )



        // Receiver

        // db.expect_get_transfer_data(state_chain_id)
        // .returning(|_| Ok(TransferData {
        //     state_chain_id,
        //     state_chain_sig: state_chain_sig,
        //     x1: x1
        // }));

        // let party_1_private: Party1Private = db.deser(    "{\"x1\":\"36f0733c49c7c500845ce8c8528700a5766bb2be0afb3dc6a92609bdeb7d77de\",\"paillier_priv\":{\"p\":\"150868972667051630375631289145931811000926269697172215034129550299519830596932237114864076011910332526564014374880702421540181692143893778193268394508356621097793334071789326969733477612737448744970159004363244991682697217411574313037164309131787024001958133617279097706925728557760967475682234607674230244397\",\"q\":\"122604155030420179713896927958393174492845903159909866799286880352148165272070472842234696094969924097112221990618586011682737086679586235795050785989838852426407767438224718505007700566694816217355837730739352784228079347155718834896806259316377005605429791326022985755525955843192908883717457575135889036987\"},\"c_key_randomness\":\"8031148b56d2d9e3323994fb1ca7038083dd86cbd3b41867bdddd8a7b8d95c4e8a0fe5c3be0cf45ebbe3dc637055eecab4f82da9b3071b6302aaf8eed54aaa544822605c849573e1d85a9367fb1a8760958ca5dabd497a642e8dd0286b354a47384dbd10b2aa4a4feeb3b389332029515e61aa1d1c746b2584ef8ebb250b27612e22d184282afdc63773a0b0a40cafb4011fd014c2c189ac016a367012f94eff3e47e77d088f2d7db485b03feecd0d60ffe2837ffe7af54b7fd8636725240c31ccdb9d7dffc1e49f4c480ff30e545cb5b7faa771c211cf9d8e4287cdddba075a85bb95213dec06d9322624872e9d80a41f15cd900118f8b89f16cd5c332ef484\"}"
        // .to_string()).unwrap();
        // let party_2_public: GE = db.deser(
        //     "{\"x\":\"5220bc6ebcc83d0a1e4482ab1f2194cb69648100e8be78acde47ca56b996bd9e\",\"y\":\"8dfbb36ef76f2197598738329ffab7d3b3a06d80467db8e739c6b165abc20231\"}".to_string()
        // ).unwrap();

        // db.expect_get_ecdsa_keypair(user_id)
        // .returning(|_| Ok(ECDSAKeypair {
        //     party_1_private,
        //     party_2_public,
        //     x1: x1
        // }));

    }

}
