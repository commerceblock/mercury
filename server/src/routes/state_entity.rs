//! state_entity
//!
//! StateEntity implementation

use super::super::{{Result,Config},
    auth::jwt::Claims,
    storage::db};

extern crate shared_lib;
use shared_lib::{
    util::{tx_backup_verify, get_sighash, tx_withdraw_verify, FEE},
    structs::*,
    state_chain::*,
    Root,
    mocks::mock_electrum::MockElectrum};

use crate::error::{SEError,DBErrorType::NoDataForID};
use crate::routes::ecdsa;
use crate::storage::db::{get_root, get_current_root};

use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one::Party1Private;
use bitcoin::{{Transaction, consensus},
    util::misc::hex_bytes, hashes::sha256d};
use consensus::encode::deserialize;

use electrumx_client::{
    interface::Electrumx,
    electrumx_client::ElectrumxClient};

use curv::{
    elliptic::curves::traits::{ECScalar,ECPoint},
    {BigInt,FE,GE}};

use monotree::Proof;
use rocket_contrib::json::Json;
use rocket::State;
use uuid::Uuid;
use db::{DB_SC_LOC, update_root};
use std::{thread, time, collections::HashMap};


/// Structs for DB storage.
#[derive(Debug)]
pub enum StateEntityStruct {
    UserSession,
    StateChain,
    TransferData,
    TransferBatchData
}
impl db::MPCStruct for StateEntityStruct {
    fn to_string(&self) -> String {
        format!("StateChain{:?}", self)
    }
}

/// UserSession represents a User in a particular state chain session.
/// The same client co-owning 2 distinct UTXOs wth the state entity would have 2 unrelated UserSession's.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct UserSession {
    /// User's identification
    pub id: String,
    /// User's password
    // pub pass: String
    /// User's authorisation
    pub auth: String,
    /// users proof key
    pub proof_key: String,
    /// back up tx for this user session
    pub tx_backup: Option<Transaction>,
    /// withdraw tx for end of user session and end of state chain
    pub tx_withdraw: Option<Transaction>,
    /// ID of state chain that data is for
    pub state_chain_id: Option<String>,
    /// If UserSession created for transfer() then SE must know s2 value to create shared wallet
    pub s2: Option<FE>,
    /// sig hash of tx to be signed. This value is checked in co-signing to ensure that message being
    /// signed is the sig hash of a tx that SE has verified.
    /// Used when signing both backup and withdraw tx.
    pub sig_hash: Option<sha256d::Hash>,
    /// StateChain Signature for withdrawal. Presence of this data signals user has passed Authorisation
    /// for withdrawl.
    pub withdraw_sc_sig: Option<StateChainSig>
}

/// TransferData provides new Owner's data for their new UserSession struct created in transfer_receiver.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct TransferData {
    pub state_chain_id: String,
    pub state_chain_sig: StateChainSig,
    pub x1: FE
}

/// TransferBatch stores list of StateChains involved in a batch transfer and their status in the potocol.
/// When all transfers in the batch are complete these transfers are finalized atomically.
#[derive(Serialize, Deserialize, Debug)]
pub struct TransferBatchData {
    pub id: String,
    pub state_chains: HashMap<String, bool>,
    pub finalized_data: Vec<TransferFinalizeData>
}
/// Struct holds data when transfer is complete but not yet finalized
#[derive(Serialize, Deserialize, Debug)]
pub struct TransferFinalizeData {
    pub new_shared_key_id: String,
    pub state_chain_id: String,
    pub state_chain_sig: StateChainSig,
    pub s2: FE
}


/// API: Return StateEntity fee information.
#[post("/info/fee", format = "json")]
pub fn get_state_entity_fees(
    state: State<Config>,
) -> Result<Json<StateEntityFeeInfoAPI>> {
    Ok(Json(StateEntityFeeInfoAPI {
        address: state.fee_address.clone(),
        deposit: state.fee_deposit,
        withdraw: state.fee_withdraw,
    }))
}

/// API: Return StateChain info: funding txid and state chain list of proof keys and signatures.
#[post("/info/statechain/<state_chain_id>", format = "json")]
pub fn get_statechain(
    state: State<Config>,
    claim: Claims,
    state_chain_id: String,
) -> Result<Json<StateChainDataAPI>> {
    let state_chain: StateChain =
        db::get(&state.db, &claim.sub, &state_chain_id, &StateEntityStruct::StateChain)?
            .ok_or(SEError::DBError(NoDataForID, state_chain_id.clone()))?;
    Ok(Json({
        StateChainDataAPI {
            amount: state_chain.amount,
            utxo: state_chain.tx_backup.input.get(0).unwrap().previous_output,
            chain: state_chain.chain
        }
    }))
}

/// API: Generates sparse merkle tree inclusion proof for some key in a tree with some root.
#[post("/info/proof", format = "json", data = "<smt_proof_msg>")]
pub fn get_smt_proof(
    state: State<Config>,
    smt_proof_msg: Json<SmtProofMsgAPI>,
) -> Result<Json<Option<Proof>>> {
    // ensure root exists
    if get_root::<[u8;32]>(&state.db, &smt_proof_msg.root.id)?.is_none() {
        return Err(SEError::DBError(NoDataForID, format!("Root id: {}",smt_proof_msg.root.id.to_string())));
    }

    Ok(Json(gen_proof_smt(DB_SC_LOC, &smt_proof_msg.root.value, &smt_proof_msg.funding_txid)?))
}

/// API: Get root of sparse merkle tree. Will be via Mainstay in the future.
#[post("/info/root", format = "json")]
pub fn get_smt_root(
    state: State<Config>,
) -> Result<Json<Root>> {
    Ok(Json(get_current_root::<Root>(&state.db)?))
}

/// API: Return TransferBatchData status. Triggers check for all transfers complete - if so then finalize all.
#[post("/info/transfer-batch/<batch_id>", format = "json")]
pub fn get_transfer_batch_status(
    state: State<Config>,
    claim: Claims,
    batch_id: String,
) -> Result<Json<TransferBatchDataAPI>> {
    let transfer_batch_data: TransferBatchData =
        db::get(&state.db, &claim.sub, &batch_id, &StateEntityStruct::TransferBatchData)?
            .ok_or(SEError::DBError(NoDataForID, batch_id.clone()))?;

    // Check if all transfers are complete. If so then all transfers in batch can be finalized.
    let mut state_chains_copy = transfer_batch_data.state_chains.clone();
    state_chains_copy.retain(|_, &mut v| v == false);
    if state_chains_copy.len() == 0 {
        debug!("All trtansfers complete in batch {}. Finalizing...", batch_id);
        finalize_batch(
            &state,
            &claim,
            &batch_id
        )?;
    }

    // return status of transfers
    Ok(Json(TransferBatchDataAPI{
        state_chains: transfer_batch_data.state_chains,
    }))
}


/// Check if user has passed authentication.
pub fn check_user_auth(
    state: &State<Config>,
    claim: &Claims,
    id: &String
) -> Result<UserSession> {
    // check authorisation id is in DB (and check password?)
    db::get(
        &state.db,
        &claim.sub,
        &id,
        &StateEntityStruct::UserSession).unwrap()
    .ok_or(SEError::AuthError)
}



/// Prepare to co-sign a transaction input. This is where SE checks that the tx to be signed is
/// honest and error free:
///     - Check tx data
///     - calculate and store tx sighash for validation before performing ecdsa::sign
#[post("/prepare-sign", format = "json", data = "<prepare_sign_msg>")]
pub fn prepare_sign_tx(
    state: State<Config>,
    claim: Claims,
    prepare_sign_msg: Json<PrepareSignTxMsg>,
) -> Result<Json<()>> {
    // Auth user
    check_user_auth(&state, &claim, &prepare_sign_msg.shared_key_id)?;

    let prepare_sign_msg: PrepareSignTxMsg = prepare_sign_msg.into_inner();

    // Get user session for this user
    let mut user_session: UserSession =
    db::get(&state.db, &claim.sub, &prepare_sign_msg.shared_key_id, &StateEntityStruct::UserSession)?
    .ok_or(SEError::DBError(NoDataForID, prepare_sign_msg.shared_key_id.clone()))?;


    // Which protocol are we signing for?
    match prepare_sign_msg.protocol {
        Protocol::Withdraw => {

            // Verify withdrawl has been authorised via presense of withdraw_sc_sig
            if user_session.withdraw_sc_sig.is_none() {
                return Err(SEError::Generic(String::from("Withdraw has not been authorised. /withdraw/init must be called first.")));
            }

            // Verify unsigned withdraw tx to ensure co-sign will be signing the correct data
            tx_withdraw_verify(&prepare_sign_msg, &state.fee_address, &state.fee_withdraw)?;

            // Check funding txid UTXO info
            let state_chain_id = user_session.state_chain_id.clone() // check exists
                .ok_or(SEError::Generic(String::from("No state chain session found for this user.")))?;
            let state_chain: StateChain =
                db::get(&state.db, &claim.sub, &state_chain_id, &StateEntityStruct::StateChain)?
                    .ok_or(SEError::DBError(NoDataForID, state_chain_id.clone()))?;
            let tx_backup_input = state_chain.tx_backup.input.get(0).unwrap().previous_output.to_owned();
            if prepare_sign_msg.tx.input.get(0).unwrap().previous_output.to_owned() != tx_backup_input {
                return Err(SEError::Generic(String::from("Incorrect withdraw transacton input.")));
            }

            // Update UserSession with withdraw tx info
            let sig_hash = get_sighash(
                &prepare_sign_msg.tx,
                &0,
                &prepare_sign_msg.input_addrs[0],
                &prepare_sign_msg.input_amounts[0],
                &state.network
            );

            user_session.sig_hash = Some(sig_hash);
            user_session.tx_withdraw = Some(prepare_sign_msg.tx);

            db::insert(
                &state.db,
                &claim.sub,
                &prepare_sign_msg.shared_key_id,
                &StateEntityStruct::UserSession,
                &user_session
            )?;

            debug!("Withdraw: Withdraw tx ready for signing.");
        }
        _ => {
            // Verify unsigned backup tx to ensure co-sign will be signing the correct data
            tx_backup_verify(&prepare_sign_msg)?;

            let sig_hash = get_sighash(
                &prepare_sign_msg.tx,
                &0,
                &prepare_sign_msg.input_addrs[0],
                &prepare_sign_msg.input_amounts[0],
                &state.network
            );

            user_session.sig_hash = Some(sig_hash.clone());
            // Only in deposit case add backup tx to UserSession
            if prepare_sign_msg.protocol == Protocol::Deposit {
                user_session.tx_backup = Some(prepare_sign_msg.tx.clone());
            }


            debug!("Deposit: Statechain created and backup tx ready for signing.");
        }
    }

    // Update DB UserSession object
    db::insert(
        &state.db,
        &claim.sub,
        &prepare_sign_msg.shared_key_id,
        &StateEntityStruct::UserSession,
        &user_session
    )?;

    Ok(Json(()))
}


/// Initiliase deposit protocol:
///     - Generate and return shared wallet ID
///     - Can do auth or other DoS mitigation here
#[post("/deposit/init", format = "json", data = "<deposit_msg1>")]
pub fn deposit_init(
    state: State<Config>,
    claim: Claims,
    deposit_msg1: Json<DepositMsg1>,
) -> Result<Json<String>> {
    // Generate shared wallet ID (user ID)
    let user_id = Uuid::new_v4().to_string();

    // if Verification/PoW/authoriation failed {
    //      Err(SEError::AuthError)
    //  }

    // Create DB entry for newly generated ID signalling that user has passed some
    // verification. For now use ID as 'password' to interact with state entity
    db::insert(
        &state.db,
        &claim.sub,
        &user_id,
        &StateEntityStruct::UserSession,
        &UserSession {
            id: user_id.clone(),
            auth: deposit_msg1.auth.clone(),
            proof_key: deposit_msg1.proof_key.to_owned(),
            state_chain_id: None,
            tx_backup: None,
            tx_withdraw: None,
            sig_hash: None,
            s2: None,
            withdraw_sc_sig: None
        }
    )?;

    debug!("Deposit: Protocol initiated. UserId generated: {}",user_id);

    Ok(Json(user_id))
}

/// Query an Electrum Server for a transaction's confirmation status.
/// Return Ok() if confirmed or Error if not after some waiting period.
pub fn verify_tx_confirmed(tx_hash: &String, state: &State<Config>) -> Result<()> {
    let mut electrum: Box<dyn Electrumx> = if state.testing_mode {
        Box::new(MockElectrum::new())
    } else {
        Box::new(ElectrumxClient::new(state.electrum_server.clone()).unwrap())
    };

    debug!("Waiting for funding transaction confirmation. Txid: {}",
        deserialize::<Transaction>(&hex_bytes(tx_hash).unwrap()).unwrap().txid().to_string());

    let mut is_broadcast = 0;   // num blocks waited for tx to be broadcast
    let mut is_mined = 0;       // num blocks waited for tx to be mined
    while is_broadcast < 3 {    // Check for tx broadcast. If not after 3*(block time) then return error.
        match electrum.get_transaction_conf_status(tx_hash.clone(), false) {
            Ok(res) => {
                // Check for tx confs. If none after 10*(block time) then return error.
                if res.confirmations.is_none() {
                    is_mined += 1;
                    if is_mined > 9 {
                        return Err(SEError::Generic(String::from("Funding transaction failure to be mined - consider increasing the fee. Deposit failed.")));
                    }
                    thread::sleep(time::Duration::from_millis(state.block_time)); //
                } else { // If confs increase then wait 6*(block time) and return Ok()
                    debug!("Funding transaction mined. Waiting for 6 blocks confirmation.");
                    thread::sleep(time::Duration::from_millis(6*state.block_time)); //
                    return Ok(())
                }
            },
            Err(_) => {
                is_broadcast += 1;
                thread::sleep(time::Duration::from_millis(state.block_time));
            }
        }
    }
    return Err(SEError::Generic(String::from("Funding Transaction not found in blockchain. Deposit failed.")));
}

/// Final step in deposit protocol:
///     - Wait for confirmation of funding tx in blockchain
///     - Create StateChain DB object
///     - Update sparse merkle tree with new StateChain entry
#[post("/deposit/confirm", format = "json", data = "<deposit_msg2>")]
pub fn deposit_confirm(
    state: State<Config>,
    claim: Claims,
    deposit_msg2: Json<DepositMsg2>,
) -> Result<Json<String>> {

    // Get UserSession info
    let mut user_session: UserSession =
    db::get(&state.db, &claim.sub, &deposit_msg2.shared_key_id, &StateEntityStruct::UserSession)?
        .ok_or(SEError::DBError(NoDataForID, deposit_msg2.shared_key_id.clone()))?;

    // Ensure backup tx exists and is signed
    let tx_backup = user_session.tx_backup.clone()
        .ok_or(SEError::DBError(NoDataForID, String::from("Signed Back up transaction not found.")))?;
    if tx_backup.input[0].witness.len() == 0 {
        return Err(SEError::DBError(NoDataForID, String::from("Signed Back up transaction not found.")));
    }

    // Wait for funding tx existence in blockchain and confs
    verify_tx_confirmed(&user_session.tx_backup.clone().unwrap().input[0].previous_output.txid.to_string(), &state)?;

    // Create state chain DB object
    let state_chain = StateChain::new(
        user_session.proof_key.clone(),
        tx_backup.clone(),
        tx_backup.output.last().unwrap().value+FEE
    );

    db::insert(
        &state.db,
        &claim.sub,
        &state_chain.id,
        &StateEntityStruct::StateChain,
        &state_chain
    )?;
    debug!("Deposit: State Chain created. ID: {}", state_chain.id);


    // Update sparse merkle tree with new StateChain entry
    let root = get_current_root::<Root>(&state.db)?;
    let new_root = update_statechain_smt(
        DB_SC_LOC,
        &root.value,
        &tx_backup.input.get(0).unwrap().previous_output.txid.to_string(),
        &user_session.proof_key
    )?;
    update_root(&state.db, new_root.unwrap())?;

    debug!("Deposit: Added to sparse merkle tree. State Chain: {}", state_chain.id);


    // Update UserSesison with StateChain's ID
    user_session.state_chain_id = Some(state_chain.id.to_owned());
    db::insert(
        &state.db,
        &claim.sub,
        &deposit_msg2.shared_key_id,
        &StateEntityStruct::UserSession,
        &user_session
    )?;

    Ok(Json(state_chain.id))
}


/// Initiliase transfer protocol:
///     - Authorisation of Owner and DoS protection
///     - Validate transfer parameters
///     - Store transfer parameters
#[post("/transfer/sender", format = "json", data = "<transfer_msg1>")]
pub fn transfer_sender(
    state: State<Config>,
    claim: Claims,
    transfer_msg1: Json<TransferMsg1>,
) -> Result<Json<TransferMsg2>> {
    // Auth user
    check_user_auth(&state, &claim, &transfer_msg1.shared_key_id)?;

    // Verification/PoW/authoriation failed
    // Err(SEError::AuthError)

    // Ensure transfer has not already been completed (but not finalized)
    if db::get::<TransferData>(&state.db, &claim.sub, &transfer_msg1.shared_key_id, &StateEntityStruct::TransferData)?.is_some() {
        return Err(SEError::Generic(String::from("Transfer already completed.")));
    }

    // Get state_chain id
    let user_session: UserSession =
        db::get(&state.db, &claim.sub, &transfer_msg1.shared_key_id, &StateEntityStruct::UserSession)?
            .ok_or(SEError::DBError(NoDataForID, transfer_msg1.shared_key_id.clone()))?;
    if user_session.state_chain_id.is_none() {
        return Err(SEError::Generic(String::from("Transfer Error: User does not own a state chain.")));
    }

    // Generate x1
    let x1: FE = ECScalar::new_random();

    // Create TransferData DB entry
    db::insert(
        &state.db,
        &claim.sub,
        &transfer_msg1.shared_key_id,
        &StateEntityStruct::TransferData,
        &TransferData {
            state_chain_id: user_session.state_chain_id.clone().unwrap(),
            state_chain_sig: transfer_msg1.state_chain_sig.to_owned(),
            x1
        }
    )?;

    debug!("Transfer: Sender side complete. For State Chain: {}",user_session.state_chain_id.unwrap());

    // TODO encrypt x1 with Senders proof key

    Ok(Json(TransferMsg2{x1}))
}

/// Transfer shared wallet to new Owner:
///     - Check new Owner's state chain is correct
///     - Perform 2P-ECDSA key rotation
///     - Return new public shared key S2
#[post("/transfer/receiver", format = "json", data = "<transfer_msg4>")]
pub fn transfer_receiver(
    state: State<Config>,
    claim: Claims,
    transfer_msg4: Json<TransferMsg4>,
) -> Result<Json<TransferMsg5>> {
    let id = transfer_msg4.shared_key_id.clone();
    // Get TransferData for shared_key_id
    let transfer_data: TransferData =
        db::get(&state.db, &claim.sub, &id, &StateEntityStruct::TransferData)?
            .ok_or(SEError::DBError(NoDataForID, id.clone()))?;
    let state_chain_sig = transfer_data.state_chain_sig;

    // Ensure state_chain_sigs are the same
    if state_chain_sig != transfer_msg4.state_chain_sig.to_owned() {
        return Err(SEError::Generic(format!("State chain siganture provided does not match state chain at id {}",transfer_data.state_chain_id)));
    }

    // Get Party1 (State Entity) private share
    let party_1_private: Party1Private = db::get(&state.db, &claim.sub, &id, &ecdsa::EcdsaStruct::Party1Private)?
    .ok_or(SEError::DBError(NoDataForID, id.clone()))?;
    // Get Party2 (Owner 1) public share
    let party_2_public: GE = db::get(&state.db, &claim.sub, &id, &ecdsa::EcdsaStruct::Party2Public)?
        .ok_or(SEError::DBError(NoDataForID, id.clone()))?;

    // TODO: decrypt t2

    let x1 = transfer_data.x1;
    let t2 = transfer_msg4.t2;
    let s1 = party_1_private.get_private_key();

    // Note:
    //  s2 = o1*o2_inv*s1
    //  t2 = o1*x1*o2_inv
    let s2 = t2 * (x1.invert()) * s1;

    // Check s2 is valid for Lindell protocol (s2<q/3)
    let sk_bigint = s2.to_big_int();
    let q_third = FE::q();
    if sk_bigint >= q_third.div_floor(&BigInt::from(3)) {
        return Err(SEError::Generic(format!("Invalid o2, try again.")));
    }

    let g: GE = ECPoint::generator();
    let s2_pub: GE = g * s2;

    let p1_pub = party_2_public * s1;
    let p2_pub = transfer_msg4.o2_pub * s2;

    // Check P1 = o1_pub*s1 === p2 = o2_pub*s2
    if p1_pub != p2_pub {
        debug!("Transfer protocol failed. P1 != P2.");
        return Err(SEError::Generic(String::from("Transfer protocol error: P1 != P2")));
    }

    // Create user ID for new UserSession (receiver of transfer)
    let new_shared_key_id = Uuid::new_v4().to_string();

    let state_chain_id = transfer_data.state_chain_id.clone();
    let finalized_data = TransferFinalizeData {
        new_shared_key_id: new_shared_key_id.clone(),
        state_chain_id: state_chain_id.clone(),
        state_chain_sig,
        s2
    };

    // If batch transfer then mark StateChain as complete and store finalized data in TransferBatchData.
    // This is so the transfers can be finalized when all transfers in the batch are complete.
    if transfer_msg4.batch_id.is_some() {
        let batch_id = transfer_msg4.batch_id.clone().unwrap();
        let mut transfer_batch_data: TransferBatchData =
            db::get(&state.db, &claim.sub, &batch_id, &StateEntityStruct::TransferBatchData)?
                .ok_or(SEError::DBError(NoDataForID, batch_id.clone()))?;

        transfer_batch_data.state_chains.insert(state_chain_id, true);
        transfer_batch_data.finalized_data.push(finalized_data);
        db::insert(
            &state.db,
            &claim.sub,
            &batch_id,
            &StateEntityStruct::TransferBatchData,
            &transfer_batch_data
        )?;
    // If not batch then finalize transfer now
    } else {
        // Update DB and SMT with new transfer data
        transfer_finalize(
            &state,
            &claim,
            &finalized_data
        )?;
    }

    debug!("Transfer: Receiver side complete and DB updated. State Chain ID: {}",transfer_data.state_chain_id);

    Ok(Json(
        TransferMsg5 {
            new_shared_key_id,
            s2_pub,
        }
    ))
}

/// Finalize all transfers in a batch.
pub fn finalize_batch(
    state: &State<Config>,
    claim: &Claims,
    batch_id: &String
) -> Result<()> {
    let transfer_batch_data: TransferBatchData =
        db::get(&state.db, &claim.sub, &batch_id, &StateEntityStruct::TransferBatchData)?
            .ok_or(SEError::DBError(NoDataForID, batch_id.clone()))?;

    if transfer_batch_data.state_chains.len() != transfer_batch_data.finalized_data.len() {
        // Because a user has transferred twice? Prevent this somehow
        return Err(SEError::Generic(String::from("TransferBatchData has unequal finalized data to state chains.")))
    }

    for finalized_data in transfer_batch_data.finalized_data {
        transfer_finalize(
            &state,
            &claim,
            &finalized_data
        )?;
    }

    Ok(())
}

/// Update DB and SMT after successful transfer.
/// This function is called immediately in the regular transfer case or after confirmation of atomic
/// transfers completion in the batch transfer case.
pub fn transfer_finalize(
    state: &State<Config>,
    claim: &Claims,
    finalized_data: &TransferFinalizeData
) -> Result<()> {
    // Update state chain
    let mut state_chain: StateChain =
        db::get(&state.db, &claim.sub, &finalized_data.state_chain_id, &StateEntityStruct::StateChain)?
            .ok_or(SEError::DBError(NoDataForID, finalized_data.state_chain_id.clone()))?;

    state_chain.add(finalized_data.state_chain_sig.to_owned())?;

    db::insert(
        &state.db,
        &claim.sub,
        &finalized_data.state_chain_id,
        &StateEntityStruct::StateChain,
        &state_chain
    )?;

    // Create new UserSession to allow new owner to generate shared wallet
    db::insert(
        &state.db,
        &claim.sub,
        &finalized_data.new_shared_key_id,
        &StateEntityStruct::UserSession,
        &UserSession {
            id: finalized_data.new_shared_key_id.clone(),
            auth: String::from("auth"),
            proof_key: finalized_data.state_chain_sig.data.to_owned(),
            tx_backup: Some(state_chain.tx_backup.clone()),
            tx_withdraw: None,
            sig_hash: None,
            state_chain_id: Some(finalized_data.state_chain_id.to_owned()),
            s2: Some(finalized_data.s2),
            withdraw_sc_sig: None
        }
    )?;

    // Update sparse merkle tree with new StateChain entry
    let funding_txid = state_chain.tx_backup.input.get(0).unwrap().previous_output.txid.to_string();
    let proof_key = state_chain.chain.last()
        .ok_or(SEError::Generic(String::from("StateChain empty")))?
        .data.clone();

    let root = get_current_root::<Root>(&state.db)?;
    let new_root = update_statechain_smt(DB_SC_LOC, &root.value, &funding_txid, &proof_key)?;
    update_root(&state.db, new_root.unwrap())?;

    Ok(())
}


/// Request setup of a batch transfer.
///     - Verify all signatures
///     - Create TransferBatchData DB object
#[post("/transfer/batch/init", format = "json", data = "<transfer_batch_init_msg>")]
pub fn transfer_batch_init(
    state: State<Config>,
    claim: Claims,
    transfer_batch_init_msg: Json<TransferBatchInitMsg>
) -> Result<Json<()>> {
    // Ensure sigs purpose is for batch transfer
    for sig in &transfer_batch_init_msg.signatures {
        if !sig.purpose.contains("TRANSFER_BATCH") {
            return Err(SEError::Generic(String::from("Signture's purpose is not valid for batch transfer.")));
        }
    }

    let mut state_chains = HashMap::new();
    let batch_id = &transfer_batch_init_msg.signatures[0].purpose[15..];
    for sig in transfer_batch_init_msg.signatures.clone() {
        // Ensure sig is for same batch as others
        if !sig.purpose.contains(batch_id) {
            return Err(SEError::Generic(String::from("Batch id is not identical for all signtures.")));
        }

        // Verify sig
        let state_chain: StateChain =
            db::get(&state.db, &claim.sub, &sig.data, &StateEntityStruct::StateChain)?
                .ok_or(SEError::DBError(NoDataForID, sig.data.clone()))?;
        let proof_key = state_chain.get_tip()?.data;
        sig.verify(&proof_key)?;

        // Add to TransferBatchData object
        state_chains.insert(
            sig.data,
            false
        );
    }

    // Create new TransferBatchData and add to DB
    db::insert(
        &state.db,
        &claim.sub,
        &transfer_batch_init_msg.batch_id,
        &StateEntityStruct::TransferBatchData,
        &TransferBatchData {
            id: transfer_batch_init_msg.batch_id.clone(),
            state_chains,
            finalized_data: vec!()
        }
    )?;

    Ok(Json(()))
}

/// User request withdraw:
///     - Check StateChainSig validity
///     - Mark user as authorised to withdraw
#[post("/withdraw/init", format = "json", data = "<withdraw_msg1>")]
pub fn withdraw_init(
    state: State<Config>,
    claim: Claims,
    withdraw_msg1: Json<WithdrawMsg1>,
) -> Result<Json<()>> {
    // Auth user
    check_user_auth(&state, &claim, &withdraw_msg1.shared_key_id)?;

    // Get UserSession data
    let mut user_session: UserSession =
        db::get(&state.db, &claim.sub, &withdraw_msg1.shared_key_id, &StateEntityStruct::UserSession)?
            .ok_or(SEError::DBError(NoDataForID, withdraw_msg1.shared_key_id.clone()))?;

    // Get statechain
    let state_chain_id = user_session.state_chain_id.clone()
        .ok_or(SEError::Generic(String::from("No state chain session found for this user.")))?;
    let state_chain: StateChain =
        db::get(&state.db, &claim.sub, &state_chain_id.to_owned(), &StateEntityStruct::StateChain)?
            .ok_or(SEError::DBError(NoDataForID, state_chain_id.to_owned()))?;

    // Verify new StateChainSig
    let prev_proof_key = state_chain.get_tip()?.data;
    withdraw_msg1.state_chain_sig.verify(&prev_proof_key)?;

    // Mark UserSession as authorised for withdrawal
    user_session.withdraw_sc_sig = Some(withdraw_msg1.state_chain_sig.clone());
    db::insert(
        &state.db,
        &claim.sub,
        &withdraw_msg1.shared_key_id,
        &StateEntityStruct::UserSession,
        &user_session
    )?;

    debug!("Withdraw: Authorised. State Chain: {}",state_chain_id);

    Ok(Json(()))
}

/// Finish withdrawal:
///     - Ensure withdraw tx has been signed
///     - Update UserSession, StateChain and Sparse merkle tree
///     - Return withdraw tx signature
#[post("/withdraw/confirm", format = "json", data = "<withdraw_msg2>")]
pub fn withdraw_confirm(
    state: State<Config>,
    claim: Claims,
    withdraw_msg2: Json<WithdrawMsg2>,
) -> Result<Json<Vec<Vec<u8>>>> {
    // Get UserSession data
    let mut user_session: UserSession =
        db::get(&state.db, &claim.sub, &withdraw_msg2.shared_key_id, &StateEntityStruct::UserSession)?
            .ok_or(SEError::DBError(NoDataForID, withdraw_msg2.shared_key_id.clone()))?;
    // Check withdraw tx and statechain signature exists
    if user_session.tx_withdraw.is_none() {
        return Err(SEError::Generic(String::from("Withdraw Error: No withdraw tx has been signed.")));
    }
    if user_session.withdraw_sc_sig.is_none() {
        return Err(SEError::Generic(String::from("Withdraw Error: No state chain signature exists for this user.")));
    }

    // Get statechain and update with final StateChainSig
    let state_chain_id = user_session.state_chain_id
        .ok_or(SEError::Generic(String::from("No state chain session found for this user.")))?;
    let mut state_chain: StateChain =
        db::get(&state.db, &claim.sub, &state_chain_id.to_owned(), &StateEntityStruct::StateChain)?
            .ok_or(SEError::DBError(NoDataForID, state_chain_id.to_owned()))?;

    state_chain.add(user_session.withdraw_sc_sig.to_owned().unwrap())?;
    state_chain.amount = 0;     // signals withdrawn funds
    db::insert(
        &state.db,
        &claim.sub,
        &state_chain_id,
        &StateEntityStruct::StateChain,
        &state_chain
    )?;

    // Remove state_chain_id from user session to signal end of session
    user_session.state_chain_id = None;
    db::insert(
        &state.db,
        &claim.sub,
        &withdraw_msg2.shared_key_id,
        &StateEntityStruct::UserSession,
        &user_session
    )?;

    // Update sparse merkle tree
    let tx_withdraw = user_session.tx_withdraw.unwrap();
    let funding_txid = tx_withdraw.input.get(0).unwrap().previous_output.txid.to_string();

    let root = get_current_root::<Root>(&state.db)?;
    let new_root = update_statechain_smt(DB_SC_LOC, &root.value, &funding_txid, &withdraw_msg2.address)?;
    update_root(&state.db, new_root.unwrap())?;

    debug!("Withdraw: Complete. State Chain: {}",state_chain_id);

    Ok(Json(tx_withdraw.input[0].clone().witness))
}
