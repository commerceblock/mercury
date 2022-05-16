//! Transfer
//!
//! Transfer coins in state entity to new owner

// transfer() messages:
// 0. Receiver communicates address to Sender (B2 and C2)
// 1. Sender Initialises transfer protocol with State Entity
//      a. init, authorisation, provide receivers proofkey C2
//      b. State Entity generates x1 and sends to Sender
//      c. Sender and State Entity Co-sign new back up transaction sending to Receivers
//          backup address Addr(B2)
// 2. Receiver performs transfer with State Entity
//      a. Verify state chain is updated
//      b. calculate t1=01x1
//      c. calucaulte t2 = t1*o2_inv
//      d. Send t2, O2 to state entity
//      e. Verify o2*S2 = P

use super::super::Result;

use crate::error::{CError, WalletErrorType};
use crate::state_entity::{
    api::{get_smt_proof, get_smt_root, get_statecoin, get_statechain, get_statechain_fee_info},
    util::{cosign_tx_input, verify_statechain_smt},
};
use crate::wallet::{key_paths::funding_txid_to_int, wallet::Wallet};
use crate::{utilities::requests, ClientShim};
use shared_lib::{ecies::WalletDecryptable, ecies::SelfEncryptable, state_chain::StateChainSig, structs::*, util::{transaction_serialise, transaction_deserialise}};
use bitcoin::{Address, PublicKey};
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{FE, GE};
use std::str::FromStr;
use uuid::Uuid;
use shared_lib::structs::TransferFinalizeData as TransferFinalizeDataAPI;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferFinalizeData {
    pub new_shared_key_id: Uuid,
    pub o2: FE,
    pub s2_pub: GE,
    pub statechain_data: StateChainDataAPI,
    pub proof_key: String,
    pub statechain_id: Uuid,
    pub tx_backup_psm: PrepareSignTxMsg,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferFinalizeDataForRecovery {
    pub new_shared_key_id: Uuid,
    pub o2: FE,
    pub statechain_data: StateChainDataAPI,
    pub proof_key: String,
    pub statechain_id: Uuid,
    pub tx_backup_hex: String,
}

//Check that the transfer finalize data for recovery
//corresponds to the transfer finalize data
impl TransferFinalizeDataForRecovery {
    pub fn compare(&self, tfd: &TransferFinalizeData)-> Result<()>{
        if self.new_shared_key_id != tfd.new_shared_key_id {
            return Err(CError::Generic(
                format!(
                    "new_shared_key_id: {}, {}", 
                    self.new_shared_key_id, tfd.new_shared_key_id)))
        }
        if self.statechain_id != tfd.statechain_id {
            return Err(CError::Generic(
                format!(
                    "statechain_id: {}, {}", 
                    self.statechain_id, tfd.statechain_id)))
        }
        if self.tx_backup_hex != tfd.tx_backup_psm.tx_hex {
            return Err(CError::Generic(
                format!(
                    "tx_backup_hex: {}, {}", 
                    self.tx_backup_hex, tfd.tx_backup_psm.tx_hex)))
        }
        if self.proof_key != tfd.proof_key {
            return Err(CError::Generic(
                format!(
                    "proof_key: {}, {}", 
                    self.proof_key, tfd.proof_key)))
        }
        if self.o2 != tfd.o2 {
            return Err(CError::Generic(
                format!(
                    "o2: {:#?}, {:#?}", 
                    self.o2, tfd.o2)))
        }
        Ok(())
    }
}

//Get the TransferFinalizeData from TransferFinalizeDataAPI, RocoveryData and the wallet
pub fn get_transfer_finalize_data_for_recovery(wallet: &mut Wallet, 
    tfd_api: &TransferFinalizeDataAPI,
    recovery_data: &RecoveryDataMsg, proof_key: &String) -> Result<TransferFinalizeDataForRecovery>{
 
    let statechain_data=get_statechain(&wallet.client_shim, &recovery_data.statechain_id.expect("expected some recovery_data.statechain_id")).unwrap();
    let funding_txid=&statechain_data.utxo.txid.to_string();
    // generate o2 private key and corresponding 02 public key
    let funding_txid_int = match funding_txid_to_int(funding_txid) {
        Ok(r) => r,
        Err(e) => {
            return Err(CError::Generic(format!(
                "Failed to get funding txid int from funding_txid: {:?} error: {}",
                funding_txid,
                e.to_string()
            )))
        }
    };
    let mut o2: FE = ECScalar::zero();
    let _key_share_pub = match wallet
        .se_key_shares
        .get_new_key_encoded_id(funding_txid_int, Some(&mut o2))
    {
        Ok(r) => r,
        Err(e) => {
            return Err(CError::Generic(format!(
                "Failed to get new key encoded id from funding_txid_int: {} error: {}",
                funding_txid_int,
                e.to_string()
            )))
        }
    };

    if tfd_api.new_shared_key_id != recovery_data.shared_key_id {
       return Err(CError::Generic(String::from("transfer finalize and recovery data shared keys do not match")));
    }
    Ok(
        TransferFinalizeDataForRecovery{
        new_shared_key_id: tfd_api.new_shared_key_id.to_owned(),
        o2,
        statechain_data,
        proof_key: proof_key.to_owned(),
        statechain_id: tfd_api.statechain_id.to_owned(),
        tx_backup_hex: recovery_data.tx_hex.as_ref().expect("expected some recovery_data.tx_hex").to_owned(),
    })
}

/// Transfer coins to new Owner from this wallet
pub fn transfer_sender(
    wallet: &mut Wallet,
    statechain_id: &Uuid,
    receiver_addr: SCEAddress,
    batch_id: Option<Uuid>
) -> Result<TransferMsg3> {
    // Get required shared key data
    let shared_key_id;
    let mut prepare_sign_msg;
    {
        let shared_key = wallet.get_shared_key_by_statechain_id(statechain_id)?;
        shared_key_id = shared_key.id.clone();
        prepare_sign_msg = shared_key
            .tx_backup_psm
            .clone()
            .ok_or(CError::WalletError(WalletErrorType::KeyMissingData))?;
    }

    // Get state entity fee and locktime info
    let se_fee_info = get_statechain_fee_info(&wallet.client_shim)?;

    // First sign state chain
    let statecoin_data: StateCoinDataAPI = get_statecoin(&wallet.client_shim, &statechain_id)?;
    
    // Get proof key for signing
    let proof_key_derivation = wallet
        .se_proof_keys
        .get_key_derivation(&PublicKey::from_str(&statecoin_data.statecoin.data).unwrap());
    let statechain_sig = StateChainSig::new(
        &proof_key_derivation
            .ok_or(CError::WalletError(WalletErrorType::KeyNotFound))?
            .private_key
            .key,
        &String::from("TRANSFER"),
        &receiver_addr.proof_key.clone().to_string(),
    )?;

    // Init transfer: Send statechain signature or batch data
    let mut transfer_msg2: TransferMsg2 = requests::postb(
        &wallet.client_shim,
        &format!("transfer/sender"),
        &TransferMsg1 {
            shared_key_id: shared_key_id.to_owned(),
            statechain_sig: statechain_sig.clone(),
            batch_id: batch_id,
        },
    )?;

    wallet.decrypt(&mut transfer_msg2)?;

    let mut tx = transaction_deserialise(&prepare_sign_msg.tx_hex)?;

    // Update prepare_sign_msg with new owners address, proof key
    prepare_sign_msg.protocol = Protocol::Transfer;
    match tx.output.get_mut(0) {
        Some(v) => match receiver_addr.tx_backup_addr.clone() {
            Some(v2) => v.script_pubkey = v2.script_pubkey(),
            None => (),
        },
        None => (),
    };
    prepare_sign_msg.proof_key = Some(receiver_addr.proof_key.clone().to_string());
    //set updated decremented locktime
    tx.lock_time = statecoin_data.locktime - se_fee_info.interval;
    prepare_sign_msg.tx_hex = transaction_serialise(&tx);

    // Sign new back up tx
    let new_backup_witness = {
        let tmp = cosign_tx_input(wallet, &prepare_sign_msg)?;
        if tmp.len() != 1 {return Err(CError::Generic(String::from("expected one tx input witness")));}
        tmp[0].to_owned()
    };

    let mut tx = transaction_deserialise(&prepare_sign_msg.tx_hex)?;
    // Update back up tx with new witness
    tx.input[0].witness = new_backup_witness;
    prepare_sign_msg.tx_hex = transaction_serialise(&tx);

    // Get o1 priv key
    let shared_key = wallet.get_shared_key(&shared_key_id)?;
    let o1 = shared_key.share.private.get_private_key();

    // t1 = o1x1
    let x1 = transfer_msg2.x1.get_fe()?;
    let t1 = o1 * x1;
    let t1_encryptable = FESer::from_fe(&t1);

    let mut transfer_msg3 = TransferMsg3 {
        shared_key_id: shared_key_id.to_owned(),
        t1: t1_encryptable,
        statechain_sig,
        statechain_id: statechain_id.to_owned(),
        tx_backup_psm: prepare_sign_msg.to_owned(),
        rec_se_addr: receiver_addr,
    };

    //encrypt then make immutable
    transfer_msg3.encrypt()?;
    let transfer_msg3 = transfer_msg3;

    // Mark funds as spent in wallet
    {
        let mut shared_key = wallet.get_shared_key_mut(&shared_key_id)?;
        shared_key.unspent = false;
    }

    //store transfer_msg_3 in db

    // Update server database with transfer message 3 so that
    // the receiver can get the message
    requests::postb(
        &wallet.client_shim,
        &format!("transfer/update_msg"),
        &transfer_msg3,
    )?;

    Ok(transfer_msg3)
}

// Get the transfer message 3
// created by the sender and stored in the SE database
pub fn transfer_get_msg(wallet: &mut Wallet, statechain_id: &Uuid) -> Result<TransferMsg3> {
    requests::postb(
        &wallet.client_shim,
        &format!("transfer/get_msg"),
        &StatechainID {id: *statechain_id},
    )
}

// Get the transfer message 3
// created by the sender and stored in the SE database
pub fn transfer_get_msg_addr(wallet: &mut Wallet, receive_addr: &str) -> Result<Vec<TransferMsg3>> {
    requests::get(&wallet.client_shim, &format!("transfer/get_msg_addr/{}", receive_addr))
}

/// Receiver side of Transfer protocol.
pub fn transfer_receiver(
    wallet: &mut Wallet,
    transfer_msg3: &mut TransferMsg3,
    batch_data: &Option<BatchData>,
) -> Result<TransferFinalizeData> {
    transfer_receiver_repeat_keygen(wallet,transfer_msg3,batch_data,0)
}

/// Receiver side of Transfer protocol.
pub fn transfer_receiver_repeat_keygen(
    wallet: &mut Wallet,
    transfer_msg3: &mut TransferMsg3,
    batch_data: &Option<BatchData>,
    keygen1_reps: u32
) -> Result<TransferFinalizeData> {
    //Decrypt the message on receipt
    match wallet.decrypt(transfer_msg3) {
        Ok(_) => (),
        Err(e) => {
            return Err(CError::Generic(format!(
                "error decrypting message: {}",
                e.to_string()
            )))
        }
    };
    //Make immutable
    let transfer_msg3 = &*transfer_msg3;
    // Get statechain data (will Err if statechain not yet finalized)
    let statechain_data: StateChainDataAPI =
        get_statechain(&wallet.client_shim, &transfer_msg3.statechain_id)?;

    let tx_backup = transaction_deserialise(&transfer_msg3.tx_backup_psm.tx_hex)?;
    // Ensure backup tx funds are sent to address owned by this wallet
    let back_up_rec_se_addr = Address::from_script(
        &tx_backup.output[0].script_pubkey,
        wallet.get_bitcoin_network(),
    )
    .ok_or(CError::Generic(String::from(
        "Failed to decode ScriptpubKey.",
    )))?;
    wallet
        .se_backup_keys
        .get_address_derivation(&back_up_rec_se_addr.to_string())
        .ok_or(CError::Generic(String::from(
            "Backup Tx receiving address not found in this wallet!",
        )))?;

    // Check locktime of recieved backup transaction
    let chaintip = wallet
        .electrumx_client
        .instance
        .get_tip_header()?;
    debug!("Transfer receiver: Got current best block height: {}", chaintip.height.to_string());
    if tx_backup.lock_time <= (chaintip.height as u32) {
            return Err(CError::Generic(format!(
                "Error: backup tx locktime ({:?}) expired, blockheight {:?}",tx_backup.lock_time,chaintip.height
            )));
    }

    // Check validity of the backup transaction
    // check inputs
    // check signatures
    // TODO

    // Verify state chain represents this address as new owner
    let prev_owner_proof_key = statechain_data.get_tip()?.data.clone();
    transfer_msg3
        .statechain_sig
        .verify(&prev_owner_proof_key)?;
    debug!("State chain signature is valid.");

    // Check signature is for proof key owned by this wallet
    let new_owner_proof_key = transfer_msg3.statechain_sig.data.clone();
    wallet
        .se_proof_keys
        .get_key_derivation(&PublicKey::from_str(&new_owner_proof_key).unwrap())
        .ok_or(CError::Generic(String::from(
            "Transfer Error: StateChain is signed over to proof key not owned by this wallet!",
        )))?;

    // t1 in transfer_msg3 is ECIES encrypted.
    let t1 = match transfer_msg3.t1.get_fe() {
        Ok(r) => r,
        Err(e) => {
            return Err(CError::Generic(format!(
                "Failed to get FE from transfer_msg_3 {:?} error: {}",
                transfer_msg3,
                e.to_string()
            )))
        }
    };

    // generate o2 private key and corresponding 02 public key
    let funding_txid_int = match funding_txid_to_int(&statechain_data.utxo.txid.to_string()) {
        Ok(r) => r,
        Err(e) => {
            return Err(CError::Generic(format!(
                "Failed to get funding txid int from statechain_data: {:?} error: {}",
                statechain_data,
                e.to_string()
            )))
        }
    };
    let mut o2: FE = ECScalar::zero();
    let _key_share_pub = match wallet
        .se_key_shares
        .get_new_key_encoded_id(funding_txid_int, Some(&mut o2))
    {
        Ok(r) => r,
        Err(e) => {
            return Err(CError::Generic(format!(
                "Failed to get new key encoded id from funding_txid_int: {} error: {}",
                funding_txid_int,
                e.to_string()
            )))
        }
    };

    let g: GE = ECPoint::generator();
    let o2_pub: GE = g * o2;

    let t2 = t1 * (o2.invert());
    let t2_encryptable = FESer::from_fe(&t2);

    // get SE/lockbox public key share
    let s1_pub: S1PubKey =
        requests::postb(&wallet.client_shim, &format!("transfer/pubkey"), UserID { id: transfer_msg3.shared_key_id, challenge: None })?;

    let msg4 = &mut TransferMsg4 {
        shared_key_id: transfer_msg3.shared_key_id,
        statechain_id: transfer_msg3.statechain_id,
        t2: t2_encryptable,
        statechain_sig: transfer_msg3.statechain_sig.clone(),
        o2_pub,
        tx_backup_hex: transfer_msg3.tx_backup_psm.tx_hex.clone(),
        batch_data: batch_data.to_owned(),
    };

    //encrypt then make immutable
    msg4.encrypt_with_pubkey(&PublicKey::from_str(&s1_pub.key).unwrap())?;
    let msg4 = msg4;

    let transfer_msg5: TransferMsg5 =
        requests::postb(&wallet.client_shim, &format!("transfer/receiver"), msg4)?;

    // Update tx_backup_psm shared_key_id with new one
    let mut tx_backup_psm = transfer_msg3.tx_backup_psm.clone();
    tx_backup_psm.shared_key_ids = vec![transfer_msg5.new_shared_key_id.clone()];

    // Data to update wallet with transfer. Should only be applied after StateEntity has finalized.
    let mut finalize_data = TransferFinalizeData {
        new_shared_key_id: transfer_msg5.new_shared_key_id,
        o2,
        s2_pub: transfer_msg5.s2_pub,
        statechain_data,
        proof_key: transfer_msg3.rec_se_addr.proof_key.clone().to_string(),
        statechain_id: transfer_msg3.statechain_id,
        tx_backup_psm,
    };

    // In batch case this step is performed once all other transfers in the batch are complete.
    if batch_data.is_none() {
        // Finalize protocol run by generating new shared key and updating wallet.
        transfer_receiver_finalize_repeat_keygen(wallet, &mut finalize_data, keygen1_reps)?;
    }

    Ok(finalize_data)
}

/// Finalize protocol run by generating new shared key and updating wallet.
/// This function is called immediately in the regular transfer case or after confirmation of atomic
/// transfers completion in the batch transfer case.
pub fn transfer_receiver_finalize(
    wallet: &mut Wallet,
    mut finalize_data: TransferFinalizeData,
) -> Result<()> {
    transfer_receiver_finalize_repeat_keygen(wallet, &mut finalize_data, 0)
} 


pub fn transfer_receiver_finalize_repeat_keygen(
    wallet: &mut Wallet,
    mut finalize_data: &mut TransferFinalizeData,
    keygen1_reps: u32
) -> Result<()> {
    // Make shared key with new private share
    wallet.gen_shared_key_fixed_secret_key_repeat_keygen(
        &finalize_data.new_shared_key_id,
        &finalize_data.o2.get_element(),
        &finalize_data.statechain_data.amount,
        keygen1_reps
    )?;

    // shared pk
    let pk = wallet.get_shared_key(&finalize_data.new_shared_key_id)?.share.public.q.get_element();

    // Check shared key master public key == private share * SE public share
    if (finalize_data.s2_pub * finalize_data.o2).get_element()
        != pk
    {
        return Err(CError::StateEntityError(String::from(
            "Transfer failed. Incorrect master public key generated.",
        )));
    }

    // TODO when node is integrated: Should also check that funding tx output address is address derived from shared key.
    let rec_proof_key = finalize_data.proof_key.clone();

    // Verify proof key inclusion in SE sparse merkle tree
    let root = get_smt_root(&wallet.client_shim)?.unwrap();
    let funding_txid = &finalize_data.statechain_data.utxo.txid.to_string();
    let proof = get_smt_proof(&wallet.client_shim, &root, funding_txid)?;
    assert!(verify_statechain_smt(
        &Some(root.hash()),
        &rec_proof_key,
        &proof
    ));

    let amount = finalize_data.statechain_data.amount.clone();

    finalize_data.tx_backup_psm.input_addrs = vec![pk];
    finalize_data.tx_backup_psm.input_amounts = vec![amount];

    // Add state chain id, proof key and SMT inclusion proofs to local SharedKey data
    {
        let shared_key = wallet.get_shared_key_mut(&finalize_data.new_shared_key_id)?;
        shared_key.statechain_id = Some(finalize_data.statechain_id);
        shared_key.tx_backup_psm = Some(finalize_data.tx_backup_psm.clone());
        shared_key.add_proof_data(&rec_proof_key, &root, &proof, funding_txid);
    }

    Ok(())
}

/// Sign data signalling intention to carry out transfer_batch protocol with given state chain
pub fn transfer_batch_sign(
    wallet: &mut Wallet,
    statechain_id: &Uuid,
    batch_id: &Uuid,
) -> Result<StateChainSig> {
    // First sign state chain
    let statecoin_data: StateCoinDataAPI = get_statecoin(&wallet.client_shim, &statechain_id)?;
    
    // Get proof key for signing
    let proof_key_derivation = wallet
        .se_proof_keys
        .get_key_derivation(&PublicKey::from_str(&statecoin_data.statecoin.data).unwrap());

    match StateChainSig::new_transfer_batch_sig(
        &proof_key_derivation.unwrap().private_key.key,
        &batch_id,
        &statechain_id,
    ) {
        Ok(r) => Ok(r),
        Err(e) => Err(e.into()),
    }
}

/// Request StateEntity start transfer_batch protocol
pub fn transfer_batch_init(
    client_shim: &ClientShim,
    signatures: &Vec<StateChainSig>,
    batch_id: &Uuid,
) -> Result<()> {
    requests::postb(
        &client_shim,
        &format!("transfer/batch/init  "),
        &TransferBatchInitMsg {
            id: batch_id.clone(),
            signatures: signatures.clone(),
        },
    )
}

/// Reveal nonce to State Entity. Used when transfer batch has failed and punishment is removed
/// from honest participants.
pub fn transfer_reveal_nonce(
    client_shim: &ClientShim,
    statechain_id: &Uuid,
    batch_id: &Uuid,
    hash: &String,
    nonce: &[u8; 32],
) -> Result<()> {
    requests::postb(
        &client_shim,
        &format!("transfer/batch/reveal"),
        &TransferRevealNonce {
            batch_id: batch_id.to_owned(),
            hash: hash.to_owned(),
            statechain_id: statechain_id.to_owned(),
            nonce: nonce.to_owned(),
        },
    )
}

#[cfg(test)]
mod tests {

    // use curv::elliptic::curves::traits::{ECPoint, ECScalar};
    // use curv::{FE, GE};

    // #[test]
    // fn math() {
    //     let g: GE = ECPoint::generator();
    //
    //     //owner1 share
    //     let o1_s: FE = ECScalar::new_random();
    //     let o1_p: GE = g * o1_s;
    //
    //     // SE share
    //     let s1_s: FE = ECScalar::new_random();
    //     let s1_p: GE = g * s1_s;
    //
    //     // deposit P
    //     let p_p = s1_p*o1_s;
    //     println!("P1: {:?}",p_p);
    //     let p_p = o1_p*s1_s;
    //     println!("P1: {:?}",p_p);
    //
    //
    //     // transfer
    //     // SE new random key x1
    //     let x1_s: FE = ECScalar::new_random();
    //
    //     // owner2 share
    //     let o2_s: FE = ECScalar::new_random();
    //     let o2_p: GE = g * o2_s;
    //
    //     // t1 = o1*x1*o2_inv
    //     let t1 = o1_s*x1_s*(o2_s.invert());
    //
    //     // t2 = t1*x1_inv*s1
    //     let s2_s = t1*(x1_s.invert())*s1_s;
    //
    //     println!("P2: {:?}",o2_p*s2_s);
    // }
}
