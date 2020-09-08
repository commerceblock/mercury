//! Conductor
//!
//! Conductor swap protocol trait and implementation. Full protocol descritpion can be found in Conductor Trait.

pub use super::super::Result;
use crate::error::SEError;
use shared_lib::{structs::*, util::keygen::Message, Verifiable};
extern crate shared_lib;
use crate::server::StateChainEntity;

use bitcoin::{
    hashes::{sha256d, Hash},
    secp256k1::{Secp256k1, Signature,PublicKey, SecretKey},
};
use rocket::State;
use rocket_contrib::json::Json;
use uuid::Uuid;
use mockall::predicate::*;
use mockall::*;
use cfg_if::cfg_if;
use std::collections::HashMap;
use bisetmap::BisetMap;
use crate::protocol::withdraw::Withdraw;
use crate::Database;
#[cfg(test)]
use std::sync::{Mutex, Arc};


static DEFAULT_TIMEOUT: u64 = 100; 

//Generics cannot be used in Rocket State, therefore we define the concrete
//type of StateChainEntity here
cfg_if! {
    if #[cfg(any(test,feature="mockdb"))]{
        use crate::MockDatabase;
        type SCE = StateChainEntity::<MockDatabase>;
    } else {
        use crate::PGDatabase;
        type SCE = StateChainEntity::<PGDatabase>;
    }
}

/// Conductor protocol trait. Comments explain client and server side of swap protocol.
#[automock]
pub trait Conductor {
    /// API: Poll Conductor to check for status of registered utxo. Return Ok if still waiting
    /// or swap_id if swap round has begun.
    fn poll_utxo(&self, state_chain_id: &Uuid) -> Result<Option<Uuid>>;

    /// API: Poll Conductor to check for status of swap.
    fn poll_swap(&self, swap_id: &Uuid) -> Result<Option<SwapStatus>>;

    /// API: Get information about a swap.
    fn get_swap_info(&self, swap_id: &Uuid) -> Result<Option<SwapInfo>>;

    /// API: Phase 0:
    ///     - Alert Conductor of desire to take part in a swap. Provide StateChainSig to prove
    ///         ownership of StateChain
    fn register_utxo(&self, register_utxo_msg: &RegisterUtxo) -> Result<()>;

    // Phase 1: Conductor waits until there is a large enough pool of registered UTXOs of the same size, when
    // such a pool is found Conductor generates a SwapToken and marks each UTXO as "in phase 1 of swap with id: x".
    // When a participant calls poll_utxo they see that their UTXO is involved in a swap. When they call
    // poll_swap they receive the SwapStatus and SwapToken for the swap. They now move on to phase 1.

    /// API: Phase 1:
    ///    - Participants signal agreement to Swap parameters by signing the SwapToken and
    ///         providing a fresh SCE_Address
    fn swap_first_message(&self, swap_msg1: &SwapMsg1) -> Result<()>;

    // Phase 2: Iff all participants have successfuly carried out Phase 1 then Conductor generates a blinded token
    // for each participant and marks each UTXO as "in phase 2 of swap with id: x". Upon polling the
    // participants receive 1 blinded token each.

    //get the blinded spend token required for second message
    //only possible after the first message
    fn get_blinded_spend_token(&self, swap_id: &Uuid, statechain_id: &Uuid) -> Result<BlindedSpendToken>;


    /// API: Phase 3:
    ///    - Participants create a new Tor identity and "spend" their blinded token to receive one
    //         of the SCEAddress' input in phase 1.
    fn swap_second_message(&self, swap_msg2: &SwapMsg2) -> Result<SCEAddress>;

    fn get_address_from_blinded_spend_token(&self, bst: &BlindedSpendToken) -> Result<SCEAddress>;

    // Phase 3: Participants carry out transfer_sender() and signal that this transfer is a part of
    // swap with id: x. Participants carry out corresponding transfer_receiver() and provide their
    // commitment Comm(state_chain_id, nonce), to be used later as proof of completeing the protocol
    // if the swap fails.

    // Phase 4: The protocol is now complete for honest and live participants. If all transfers are
    // completed before swap_token.time_out time has passed since the first transfer_sender() is performed
    // then the swap is considered complete and all transfers are finalized.
    //
    // On the other hand if swap_token.time_out time passes before all transfers are complete then all
    // transfers are rewound and no state chains involved in the swap have been transferred.
    // The coordinator can now publish the list of signatures which signal the participants' commitment
    // to the batch transfer. This can be included in the SCE public API so that all clients can access a
    // list of those StateChains that have caused recent failures. Participants that completed their
    // transfers can reveal the nonce to the their Comm(state_chain_id, nonce) and thus prove which
    // StateChain they own and should not take any responsibility for the failure.
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub enum SwapStatus {
    Phase1,
    Phase2,
    Phase3,
}

/// Struct defines a Swap. This is signed by each participant as agreement to take part in the swap.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SwapToken {
    id: Uuid,
    amount: u64,
    time_out: u64,
    state_chain_ids: Vec<Uuid>,
}

impl SwapToken {
    /// Create message to be signed
    fn to_message(&self) -> Result<Message> {
        let mut str = self.amount.to_string();
        str.push_str(&self.time_out.to_string());
        str.push_str(&format!("{:?}", self.state_chain_ids));
        let hash = sha256d::Hash::hash(&str.as_bytes());
        Ok(Message::from_slice(&hash)?)
    }

    /// Generate Signature for change of state chain ownership
    pub fn sign(&self, proof_key_priv: &SecretKey) -> Result<Signature> {
        let secp = Secp256k1::new();
        let message = self.to_message()?;
        Ok(secp.sign(&message, &proof_key_priv))
    }

    /// Verify self's signature for transfer or withdraw
    pub fn verify_sig(&self, pk: &PublicKey, sig: Signature) -> Result<()> {
        match sig.verify(pk,&self.to_message()?) {
            Ok(_) => Ok(()),
            Err(e) => Err(SEError::SwapError(format!("signature does not sign for token: {}",e)))
        }
    }
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SwapInfo {
    status: SwapStatus,
    swap_token: SwapToken,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Scheduler {
    //State chain id to requested swap size map
    statechain_swap_size_map: BisetMap<Uuid, u64>,
    //A map of state chain registereds for swap to amount
    statechain_amount_map: BisetMap<Uuid, u64>,
    //A map of state chain id to swap id
    swap_id_map: HashMap<Uuid, Uuid>,
    //A map of swap id to swap info
    swap_info_map: HashMap<Uuid, SwapInfo>,
    //swap id to swap status
    status_map: BisetMap<Uuid, SwapStatus>,
    //swap id to time out
    time_out_map: BisetMap<Uuid, u64>,
    //output addresses per swap
    out_addr_map: BisetMap<Uuid, SCEAddress>,
    //map of swap_id to map of state chain id to blinded_spend token
    bst_map: HashMap<Uuid, HashMap<Uuid, BlindedSpendToken>>,
}

impl Scheduler {
    pub fn new() -> Self {
        //let amount_set = HashSet::<Uuid>::new();
        //let amount_map_inv = 
        Self {
            statechain_swap_size_map: BisetMap::<Uuid, u64>::new(),
            statechain_amount_map: BisetMap::<Uuid, u64>::new(),
            swap_id_map: HashMap::<Uuid, Uuid>::new(), 
            swap_info_map: HashMap::<Uuid, SwapInfo>::new(),
            status_map: BisetMap::<Uuid, SwapStatus>::new(),
            time_out_map: BisetMap::<Uuid, u64>::new(),
            out_addr_map: BisetMap::new(),
            bst_map: HashMap::new(),
        }
    }

    pub fn get_swap_id(&self, state_chain_id: &Uuid) -> Option<Uuid> {
        self.swap_id_map.get(state_chain_id).cloned()
    }

    pub fn register_amount_swap_size(&mut self, state_chain_id: &Uuid, amount: u64, swap_size: u64) {
        //If there was an amout already registered for this state chain id then 
        //remove it from the inverse table before updating
        self.statechain_amount_map.insert(state_chain_id.to_owned(), amount);
        self.statechain_swap_size_map.insert(state_chain_id.to_owned(), swap_size);
    }

    pub fn get_statechain_ids_by_amount(&self, amount: &u64) -> Vec<Uuid> {
        self.statechain_amount_map.rev_get(amount)
    }

    fn register_swap_id(&mut self, state_chain_id: &Uuid, swap_id: &Uuid) -> Option<Uuid> {
        self.swap_id_map.insert(state_chain_id.to_owned(), swap_id.to_owned())
    }

    fn deregister_swap_id(&mut self, state_chain_id: &Uuid) -> Option<Uuid> {
        self.swap_id_map.remove(state_chain_id)
    }

    pub fn insert_swap_info(&mut self, swap_info: &SwapInfo){
        let swap_id = &swap_info.swap_token.id;
        self.swap_info_map.insert(swap_id.to_owned(), swap_info.to_owned());
        for id in &swap_info.swap_token.state_chain_ids {
            self.register_swap_id(id, swap_id);
        }
        self.status_map.insert(swap_id.to_owned(), swap_info.status.to_owned());
        self.time_out_map.insert(swap_id.to_owned(), swap_info.swap_token.time_out);
    }

    pub fn remove_swap_info(&mut self, swap_id: &Uuid) -> Option<SwapInfo>{
        match self.get_swap_info(swap_id) {
            Some(i) => {
                for id in i.to_owned().swap_token.state_chain_ids {
                    self.deregister_swap_id(&id);
                }
                let swap_id = &i.swap_token.id;
                self.swap_info_map.remove(swap_id);
                self.out_addr_map.delete(swap_id);
                self.status_map.insert(swap_id.to_owned(), i.status);
                self.time_out_map.insert(swap_id.to_owned(), i.swap_token.time_out);
                Some(i)
            },
            None => None
        }
    }

    pub fn get_swap_info(&self, swap_id: & Uuid) -> Option<SwapInfo> {
        self.swap_info_map.get(swap_id).cloned()     
    }

    pub fn get_swap_status(&self, swap_id: & Uuid) -> Option<SwapStatus> {
        match self.swap_info_map.get(swap_id) {
            None => None,
            Some(i) => Some(i.status.clone()),
        }
    }

    //Attempt to create swap tokens from the swap requests
    //For each amount, the algorithm attempts to collect state chains together into
    //the requested minimum swap size, beginning with the largest, for each requested 
    //swap size
    pub fn update_swap_requests(&mut self) {
        //Get amount to sc id map
        let amount_collect: Vec<(u64, Vec<Uuid>)> = self.statechain_amount_map.rev().collect();
        for (amount, sc_id_vec) in amount_collect {
            let mut n_remaining = sc_id_vec.len();
            //Get a reduced swap size map containing items of this amount
            let swap_size_map = BisetMap::<Uuid, u64>::new();
            for id in &sc_id_vec{
                let swap_size = self.statechain_swap_size_map.get(id);
                if(!swap_size.is_empty()){
                    swap_size_map.insert(id.to_owned(), swap_size[0]);
                }
            }

            let swap_size_map = swap_size_map.rev();

            //Loop through swap sizes in descending order
            let mut swap_size_collect = swap_size_map.collect();
            swap_size_collect.sort();
            let swap_size_vec : Vec::<usize> = swap_size_collect.iter().map(|x|x.0 as usize).collect();
            let swap_size_max = swap_size_vec.last().expect("expected non-empty vector").to_owned() as usize;
            let mut ids_for_swap = Vec::<Uuid>::new();
            while (!swap_size_collect.is_empty()) {
                //Remove from the back of the vector, which will be the largest swap_size
                let (swap_size, mut sc_ids) = swap_size_collect.pop().unwrap();
                if (n_remaining + ids_for_swap.len() >= swap_size as usize) {
                    //Collect some ids together for a swap
                    while(!sc_ids.is_empty() && ids_for_swap.len() < swap_size_max){
                        let id = sc_ids.pop().unwrap();
                        ids_for_swap.push(id);
                        n_remaining = n_remaining - 1;
                    }
                } else {
                    break;
                }
                //Create a swap token with these ids and clear temporary vector of sc ids
                if (ids_for_swap.len() == swap_size_max || n_remaining == 0){
                    let id = Uuid::new_v4();

                    let swap_token = SwapToken{
                        id: id.clone(), 
                        amount,
                        time_out: DEFAULT_TIMEOUT,
                        state_chain_ids: ids_for_swap.clone()};

                    let si = SwapInfo {
                        status: SwapStatus::Phase1,
                        swap_token,
                    };
                    //Add the swap info to the map of swap infos
                    self.insert_swap_info(&si);
                    //Remove the ids from the request lists
                    while (!ids_for_swap.is_empty()){
                        let id = ids_for_swap.pop().unwrap();
                        //Assert that the number of values that were removed was 1
                        //as a coherence check
                        assert!(self.statechain_swap_size_map.delete(&id).len() == 1);
                        assert!(self.statechain_amount_map.delete(&id).len() == 1);
                    }
                }

                //Push back the remaining sc_ids if there are enough remaining scs for them 
                //to be included in a swap
                if(!sc_id_vec.is_empty() && swap_size as usize <= n_remaining){
                    swap_size_collect.push((swap_size, sc_ids));
                }
            }
        }
    }

    //Update the swap info based on the rersults of user first/second messages
    pub fn update_swaps(&mut self) {
        for (id, swap_info) in self.swap_info_map.iter_mut() {
            match swap_info.status {
                //Phase 1 - check if all state chain addresses have been received, if so move to phase 2
                SwapStatus::Phase1 => {
                    if (swap_info.swap_token.state_chain_ids.len() == self.out_addr_map.get(&id).len()){
                        //All output addresses received. 
                        //Generate a list of blinded spend tokens and proceed to phase 2.
                        let mut scid_bst_map = HashMap::<Uuid, BlindedSpendToken>::new();
                        for sc_id in swap_info.swap_token.state_chain_ids.clone() {
                            let data = "some bst".to_string();
                            let bst = BlindedSpendToken::from_string(data);
                            scid_bst_map.insert(sc_id.clone(), bst);
                        }
                        self.bst_map.insert(swap_info.swap_token.id.clone(), scid_bst_map);
                        swap_info.status = SwapStatus::Phase2;
                    }   
                },
                SwapStatus::Phase2 => {

                },
                SwapStatus::Phase3 => {

                },
            };
        }
    }

    pub fn update_swap_info(&mut self) {
        self.update_swap_requests();
        self.update_swaps();
    }

    pub fn get_blinded_spend_token(&self, swap_id: &Uuid, statechain_id: &Uuid) -> Result<BlindedSpendToken>{
        match self.get_swap_status(swap_id) {
            Some(SwapStatus::Phase1) => Err(SEError::SwapError("in phase 1, token not available".to_string())),
            None => Err(SEError::SwapError("unknown swap id when getting swap status".to_string())),
            _ => {
                match self.bst_map.get(swap_id) {
                    Some(m) => match m.get(statechain_id) {
                        Some(bst) => Ok(bst.clone()),
                        None => Err(SEError::SwapError("unknown statechain id".to_string())),
                    },
                    None => Err(SEError::SwapError("unknown swap id when getting blind spending token".to_string())),
                }
            }
        }
    }
}


impl Conductor for SCE {
    fn poll_utxo(&self, state_chain_id: &Uuid) -> Result<Option<Uuid>> {
        let guard = self.scheduler.lock()?;
        Ok(guard.get_swap_id(state_chain_id))
    }
    fn poll_swap(&self, swap_id: &Uuid) -> Result<Option<SwapStatus>> {
        let guard = self.scheduler.lock()?;
        Ok(guard.get_swap_status(swap_id))
    }
    fn get_swap_info(&self, swap_id: &Uuid) -> Result<Option<SwapInfo>> {
        let guard = self.scheduler.lock()?;
        Ok(guard.get_swap_info(swap_id))
    }

    fn get_blinded_spend_token(&self, swap_id: &Uuid, statechain_id: &Uuid) -> Result<BlindedSpendToken> {
        let guard = self.scheduler.lock()?;
        Ok(guard.get_blinded_spend_token(swap_id, statechain_id)?)
    }

    fn register_utxo(&self, register_utxo_msg: &RegisterUtxo) -> Result<()> {
        let sig = &register_utxo_msg.signature;
        let key_id = &register_utxo_msg.state_chain_id;
        let swap_size = &register_utxo_msg.swap_size;
        //Verify the signature
        let _ = self.verify_statechain_sig(key_id, sig, None)?;
        let sc_amount = self.database.get_statechain_amount(*key_id)?;
        let amount :u64 = sc_amount.amount as u64;
        let mut guard = self.scheduler.lock()?;
        let _ = guard.register_amount_swap_size(key_id, amount, *swap_size);
        Ok(())
    }

    fn swap_first_message(&self, swap_msg1: &SwapMsg1) -> Result<()> {
        let proof_key = &swap_msg1.address.proof_key;
        //Find the correct swap token and verify
        let guard = self.scheduler.lock()?;
        let swap_id = &swap_msg1.swap_id;
        match guard.get_swap_info(swap_id){
            Some(i) => {
                i.swap_token.verify_sig(proof_key,swap_msg1.swap_token_sig)?;
                //Signature ok. Add the SCEAddress to the list.
                guard.out_addr_map.insert(swap_id.to_owned(),swap_msg1.address.clone());
                Ok(())
            },
            None => Err(SEError::SwapError(format!("no swap with id {}",&swap_msg1.swap_token_sig)))
        }  
    }

    fn swap_second_message(&self, swap_msg2: &SwapMsg2) -> Result<SCEAddress> {
        let swap_id = &swap_msg2.swap_id;
        let swap_info = match self.get_swap_info(swap_id)? {
            Some(i) => i,
            None =>  return Err(SEError::SwapError(format!("swap_second_message: no swap with id {}",swap_id))),
        };
        let _swap_token = &swap_info.swap_token;
        let addr = self.get_address_from_blinded_spend_token(&swap_msg2.blinded_spend_token)?;
        Ok(addr)
    }

    fn get_address_from_blinded_spend_token(&self, _bst: &BlindedSpendToken) -> Result<SCEAddress>{
        todo!()
    }
}

#[post("/swap/poll/utxo", format = "json", data = "<state_chain_id>")]
pub fn poll_utxo(sc_entity: State<SCE>, state_chain_id: Json<Uuid>) -> Result<Json<Option<Uuid>>> {
    match sc_entity.poll_utxo(&state_chain_id.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/swap/poll/swap", format = "json", data = "<swap_id>")]
pub fn poll_swap(sc_entity: State<SCE>, swap_id: Json<Uuid>) -> Result<Json<Option<SwapStatus>>> {
    match sc_entity.poll_swap(&swap_id.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/swap/info", format = "json", data = "<swap_id>")]
pub fn get_swap_info(sc_entity: State<SCE>, swap_id: Json<Uuid>) -> Result<Json<Option<SwapInfo>>> {
    match sc_entity.get_swap_info(&swap_id.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/swap/blinded-spend-token", format = "json", data = "<bst_msg>")]
pub fn get_blinded_spend_token(sc_entity: State<SCE>, bst_msg: Json<BSTMsg>) -> Result<Json<BlindedSpendToken>> {
    let bst_msg = bst_msg.into_inner();
    sc_entity.get_blinded_spend_token(&bst_msg.swap_id, &bst_msg.state_chain_id).map(|x| Json(x))
}

#[post("/swap/register-utxo", format = "json", data = "<register_utxo_msg>")]
pub fn register_utxo(
    sc_entity: State<SCE>,
    register_utxo_msg: Json<RegisterUtxo>,
) -> Result<Json<()>> {
    match sc_entity.register_utxo(&register_utxo_msg.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/swap/first", format = "json", data = "<swap_msg1>")]
pub fn swap_first_message(sc_entity: State<SCE>, swap_msg1: Json<SwapMsg1>) -> Result<Json<()>> {
    match sc_entity.swap_first_message(&swap_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/swap/second", format = "json", data = "<swap_msg2>")]
pub fn swap_second_message(
    sc_entity: State<SCE>,
    swap_msg2: Json<SwapMsg2>,
) -> Result<Json<(SCEAddress)>> {
    match sc_entity.swap_second_message(&swap_msg2.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[allow(dead_code)]
#[cfg(test)]
mod tests {
    use bitcoin::Address;
    use shared_lib::state_chain::StateChain;
use super::*;
    use mockall::predicate;
    use shared_lib::state_chain::StateChainSig;
    use std::str::FromStr;
    use std::{thread, time::Duration};
    use crate::protocol::util::tests::test_sc_entity;
    use std::collections::HashSet;
    use crate::structs::{StateChainOwner, StateChainAmount};
    use shared_lib::state_chain::State as SCState;

    #[test]
    fn test_swap_token_sig_verify() {
        let swap_token = SwapToken {
            id: Uuid::from_str("637203c9-37ab-46f9-abda-0678c891b2d3").unwrap(),
            amount: 1,
            time_out: DEFAULT_TIMEOUT,
            state_chain_ids: vec![Uuid::from_str("001203c9-93f0-46f9-abda-0678c891b2d3").unwrap()],
        };
        let proof_key_priv = SecretKey::from_slice(&[1; 32]).unwrap(); // Proof key priv part
        let proof_key = PublicKey::from_secret_key(&Secp256k1::new(), &proof_key_priv); // proof key

        assert_eq!(
            swap_token.to_message().unwrap(), 
            Message::from_slice(
                hex::decode("023a63469c4b87fc88b9137d99a10cce19b0a3778c2cd4257ccf7b323247d270").unwrap().as_slice()).unwrap(),
        );
        let sig = swap_token.sign(&proof_key_priv).unwrap();
        assert!(swap_token.verify_sig(&proof_key, sig).is_ok());
    }

    //get a scheduler preset with requests
    fn get_scheduler(swap_size_amounts: Vec<(u64, u64)>) -> Scheduler {
        let statechain_swap_size_map = BisetMap::new();
        let statechain_amount_map = BisetMap::new();

        for (swap_size, amount) in swap_size_amounts {
            let id = Uuid::new_v4();
            statechain_swap_size_map.insert(id, swap_size);
            statechain_amount_map.insert(id, amount);
        }

        Scheduler {
            statechain_swap_size_map,
            statechain_amount_map,
            swap_id_map: HashMap::<Uuid, Uuid>::new(),
            swap_info_map: HashMap::<Uuid, SwapInfo>::new(),
            status_map: BisetMap::<Uuid, SwapStatus>::new(),
            time_out_map: BisetMap::<Uuid, u64>::new(),
            out_addr_map: BisetMap::new(),
            bst_map: HashMap::new(),
        }
    }

    #[test]
    fn test_scheduler() {
        let mut scheduler = get_scheduler(
            vec![(3,10),(3,10),(3,10),(4,9),(4,9),(4,9),(4,9),(5,5),(5,5),(5,5),(5,5)]
        );

        scheduler.update_swap_info();
        assert_eq!(scheduler.swap_id_map.len(),7);
        assert_eq!(scheduler.swap_info_map.len(), 2);
        assert_eq!(scheduler.status_map.len(), 2);
        assert_eq!(scheduler.time_out_map.len(), 2);

        //Regsiter a new request for the amount 5, but require 6 to be in the swap
        scheduler.register_amount_swap_size(&Uuid::new_v4(), 5, 6);
        //Not enough participants to create swap
        scheduler.update_swap_info();
        assert_eq!(scheduler.swap_id_map.len(),7);
        assert_eq!(scheduler.swap_info_map.len(), 2);
        assert_eq!(scheduler.status_map.len(), 2);
        assert_eq!(scheduler.time_out_map.len(), 2);

        //Regsiter a new request for the amount 5, but require 6 to be in the swap
        let sc_id = Uuid::new_v4();
        scheduler.register_amount_swap_size(&sc_id, 5, 6);
        //Now there are enough participants: new swap created
        scheduler.update_swap_info();
        assert_eq!(scheduler.swap_id_map.len(),13);
        assert_eq!(scheduler.swap_info_map.len(), 3);
        assert_eq!(scheduler.status_map.len(), 3);
        assert_eq!(scheduler.time_out_map.len(), 3);

        //Look up the swap for sc_id
        let swap_id = scheduler.get_swap_id(&sc_id).expect("expected swap id");
        let swap_info = scheduler.get_swap_info(&swap_id).expect("expected swap info");
        assert_eq!(swap_info.status, SwapStatus::Phase1, "expected phase1");
        assert_eq!(swap_info.swap_token.amount, 5, "expected amount 5");
        assert_eq!(swap_info.swap_token.time_out, DEFAULT_TIMEOUT, "expected default timeout");
        let mut id_set = HashSet::new();
        for id in swap_info.swap_token.state_chain_ids {
            id_set.insert(id);
        }
        assert_eq!(id_set.len(), 6, "expected 6 unique state chain ids in the swap token");
    }

    #[test]
    fn test_poll_utxo() {
        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        let mut sc_entity = test_sc_entity(db);
        sc_entity.scheduler = Arc::new(Mutex::new(get_scheduler(
            vec![(3,10),(3,10),(3,10)]
        )));

        let uxto_waiting_for_swap = Uuid::from_str("00000000-93f0-46f9-abda-0678c891b2d3").unwrap();
        
        let mut guard = sc_entity.scheduler.lock().unwrap();
        guard.update_swap_info();
        let utxo_invited_to_swap = guard.swap_id_map.iter().next().unwrap().0.to_owned();
        drop(guard);
        //let uxto_invited_to_swap = Uuid::from_str("11111111-93f0-46f9-abda-0678c891b2d3").unwrap();
        match sc_entity.poll_utxo(&uxto_waiting_for_swap)
        {
            Ok(no_swap_id) => assert!(no_swap_id.is_none()),
            Err(_) => assert!(false, "Expected Ok(())."),
        }
        match sc_entity.poll_utxo(&utxo_invited_to_swap)
        {
            Ok(swap_id) => assert!(swap_id.is_some()),
            Err(_) => assert!(false, "Expected Ok((swap_id))."),
        }
    }

    #[test]
    fn test_get_swap_info() {
        let swap_id_doesnt_exist = Uuid::from_str("deadb33f-93f0-46f9-abda-0678c891b2d3").unwrap();

        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        let mut sc_entity = test_sc_entity(db);
        sc_entity.scheduler = Arc::new(Mutex::new(get_scheduler(
            vec![(3,10),(3,10),(3,10)]
        )));
        let mut guard = sc_entity.scheduler.lock().unwrap();
        guard.update_swap_info();
        //let swap_id_valid = Uuid::from_str("11111111-93f0-46f9-abda-0678c891b2d3").unwrap();
        let swap_id_valid = guard.swap_id_map.iter().next().unwrap().1.to_owned();
        drop(guard);

        match sc_entity.poll_swap(&swap_id_doesnt_exist)
        {
            Ok(None) => assert!(true),
            _ => assert!(false, "Expected failure."),
        }

        assert_eq!(sc_entity.poll_swap(&swap_id_valid).unwrap().unwrap(),SwapStatus::Phase1);

        match sc_entity.get_swap_info(&swap_id_valid)
        {
            Ok(Some(swap_info)) => {
                assert_eq!(swap_info.status, SwapStatus::Phase1);
                assert_eq!(swap_info.swap_token.id, swap_id_valid);
                assert!(swap_info.swap_token.time_out == DEFAULT_TIMEOUT);
                assert!(swap_info.swap_token.state_chain_ids.len() == 3);
            },
            _ => assert!(false, "Expected Ok(Some(swap_info))."),
        }
    }

    #[test]
    fn test_register_utxo() {
        // Check signature verified correctly
        let state_chain_id = Uuid::from_str("00000000-93f0-46f9-abda-0678c891b2d3").unwrap();
        let proof_key_priv = SecretKey::from_slice(&[1; 32]).unwrap(); // Proof key priv part
        let proof_key = PublicKey::from_secret_key(&Secp256k1::new(), &proof_key_priv); // proof key
        let invalid_proof_key_priv = SecretKey::from_slice(&[2; 32]).unwrap();
 
        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));

        let mut chain = Vec::<SCState>::new();

        pub struct State {
            pub data: String,                      // proof key or address
            pub next_state: Option<StateChainSig>, // signature representing passing of ownership
        }

        chain.push(SCState{
            data: proof_key.to_string(),
            next_state: None,
        });

        let statechain = StateChain{chain: chain.clone()};
        let statechain_2 = statechain.clone();

        db.expect_get_statechain_owner().returning(move |_| Ok(StateChainOwner{locked_until: chrono::prelude::Utc::now().naive_utc(), 
                                                                        owner_id: Uuid::new_v4(),
                                                                        chain: statechain.clone(),
                                                                    }));

        let statechain_amount = StateChainAmount{chain: statechain_2.clone(), amount: 10};

        db.expect_get_statechain_amount().returning(move |_| Ok(statechain_amount.clone()));

        let mut sc_entity = test_sc_entity(db);
        sc_entity.scheduler = Arc::new(Mutex::new(get_scheduler(
            vec![(3,10),(3,10),(3,10)]
        )));


        // Try invalid signature for proof key
        let invalid_signature =
            StateChainSig::new(&invalid_proof_key_priv, &"SWAP".to_string(), &proof_key.to_string()).unwrap();
        match sc_entity.register_utxo(&RegisterUtxo {
            state_chain_id,
            signature: invalid_signature,
            swap_size: 10,
        }){
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("signature failed verification"), e.to_string()),
        }
        // Valid signature for proof key
        let signature =
            StateChainSig::new(&proof_key_priv, &"SWAP".to_string(), &proof_key.to_string()).unwrap();
        assert!(sc_entity.register_utxo(&RegisterUtxo {
            state_chain_id,
            signature: signature,
            swap_size: 10,
        }).is_ok());
    }

    #[test]
    fn test_swap_first_message() {
        let invalid_swap_id = Uuid::from_str("deadb33f-37ab-46f9-abda-0678c891b2d3").unwrap();
        let proof_key_priv_invalid = SecretKey::from_slice(&[99; 32]).unwrap(); // Proof key priv part
        let mut proof_key_vec = Vec::<PublicKey>::new();
        let mut proof_key_priv_vec = Vec::<SecretKey>::new();
        let mut sce_addresses = Vec::<SCEAddress>::new();
        for i in 1..4 {
            proof_key_priv_vec.push(SecretKey::from_slice(&[i; 32]).unwrap());
            proof_key_vec.push(PublicKey::from_secret_key(&Secp256k1::new(), &proof_key_priv_vec.last().unwrap()));
            sce_addresses.push(
                SCEAddress {
                    tx_backup_addr: Address::from_str("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").unwrap(),
                    proof_key: proof_key_vec.last().unwrap().clone(),
                }
            )
        }

        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        let mut sc_entity = test_sc_entity(db);
        sc_entity.scheduler = Arc::new(Mutex::new(get_scheduler(
            vec![(3,10),(3,10),(3,10)]
        )));
        let mut guard = sc_entity.scheduler.lock().unwrap();
        guard.update_swap_info();
        //let swap_id_valid = Uuid::from_str("11111111-93f0-46f9-abda-0678c891b2d3").unwrap();
        let swap_id = guard.swap_id_map.iter().next().unwrap().1.to_owned();
        // Sign swap token with no state_chain_ids
        let swap_token = guard.get_swap_info(&swap_id).unwrap().swap_token;
        drop(guard);

        let mut swap_token_no_sc = swap_token.clone();
        swap_token_no_sc.state_chain_ids = Vec::new();

        let swap_token_sig = swap_token_no_sc.sign(&proof_key_priv_vec[0]).unwrap();
        let mut swap_msg_1 = SwapMsg1 {
            swap_id,
            swap_token_sig,
            address: sce_addresses[0].clone()
        };
        match sc_entity.swap_first_message(&swap_msg_1){
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("Swap Error: signature does not sign for token"), e.to_string()),
        }

        swap_msg_1.swap_token_sig = swap_token.sign(&proof_key_priv_invalid).unwrap();
        
        match sc_entity.swap_first_message(&swap_msg_1){
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("Swap Error: signature does not sign for token"), e.to_string()),
        }

        // Sign swap token with invalid swap_id
        swap_msg_1.swap_id = invalid_swap_id;
        swap_msg_1.swap_token_sig = swap_token.sign(&proof_key_priv_vec[0]).unwrap();
        
        match sc_entity.swap_first_message(&swap_msg_1){
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("Swap Error: no swap with id"),e.to_string()),
        }

        //Should be in phase1 now as not enough valid first messages have been sent
        assert_eq!(sc_entity.poll_swap(&swap_id).unwrap().unwrap(),SwapStatus::Phase1);


        for i in 0..proof_key_vec.len(){
            let swap_msg_1 = SwapMsg1 {
                swap_id,
                swap_token_sig: swap_token.sign(&proof_key_priv_vec[i]).unwrap(),
                address: sce_addresses[i].clone()
            };
            // Valid inputs
            match sc_entity.swap_first_message(&swap_msg_1) {
                Ok(_) => assert!(true),
                Err(e) => assert!(false, e.to_string())
            };
        }
        //Scheduler updates swap info to move swap to phase 2
        let mut guard = sc_entity.scheduler.lock().unwrap();
        guard.update_swap_info();
        drop(guard);
        //Should be in phase 2 now as all participants have sent first message
        assert_eq!(sc_entity.poll_swap(&swap_id).unwrap().unwrap(),SwapStatus::Phase2);

        //There should be a blinded spend token for each of the sce addresses
        let guard = sc_entity.scheduler.lock().unwrap();
        assert_eq!(guard.bst_map.get(&swap_id).unwrap().len(), 
            guard.swap_info_map.get(&swap_id).unwrap().swap_token.state_chain_ids.len());
        drop(guard);
    }

    #[test]
    fn test_get_blinded_spend_token(){
        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        let mut sc_entity = test_sc_entity(db);
        sc_entity.scheduler = Arc::new(Mutex::new(get_scheduler(
            vec![(3,10),(3,10),(3,10)]
        )));
        let mut guard = sc_entity.scheduler.lock().unwrap();
        guard.update_swap_info();
        //let swap_id_valid = Uuid::from_str("11111111-93f0-46f9-abda-0678c891b2d3").unwrap();
        let swap_id = guard.swap_id_map.iter().next().unwrap().1.to_owned();
        // Sign swap token with no state_chain_ids
        let mut swap_info = guard.get_swap_info(&swap_id).unwrap();
        swap_info.status=SwapStatus::Phase2;
        guard.swap_info_map.insert(swap_id, swap_info.clone());
        let swap_token = swap_info.swap_token;
        let state_chain_id = swap_token.state_chain_ids[0];

        let mut id_bst_map = HashMap::<Uuid, BlindedSpendToken>::new();
        let mut i = 0;
        for id in swap_token.state_chain_ids {
            id_bst_map.insert(id, BlindedSpendToken::from_string(format!("bst {}", i)));
            i = i+1;
        }
        guard.bst_map.insert(swap_id.clone(), id_bst_map);
        drop(guard);

        sc_entity.get_blinded_spend_token(&swap_id, &state_chain_id).unwrap();

        assert!(sc_entity.get_blinded_spend_token(&swap_id, &state_chain_id).is_ok());
        let expected_err = SEError::SwapError("unknown swap id when getting swap status".to_string());
        match sc_entity.get_blinded_spend_token(&Uuid::default(), &state_chain_id){
            Err(e) => assert_eq!(e.to_string(), expected_err.to_string(), "expected Err({}), got Err({})", expected_err, e),
            Ok(v) => assert!(false, "expected Err({}), got Ok({:?})", expected_err, v)
        };

         let expected_err = SEError::SwapError("unknown statechain id".to_string());
        match sc_entity.get_blinded_spend_token(&swap_id, &Uuid::default()){
            Err(e) => assert_eq!(e.to_string(), expected_err.to_string(), "expected Err({}), got Err({})", expected_err, e),
            Ok(v) => assert!(false, "expected Err({}), got Ok({:?})", expected_err, v)
        };
    }
  

    //#[test]
    fn test_swap_second_message() {
        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        let sc_entity = test_sc_entity(db);
        
        let swap_id = Uuid::new_v4();
        // Blinded token invalid
        match sc_entity.swap_second_message(&SwapMsg2 {
            swap_id,
            blinded_spend_token: BlindedSpendToken::from_str("valid token with no record of issuance")
        }){
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("Error: Blinded Token: Invalid. Token not issued by this Conductor.")),
        }
        match sc_entity.swap_second_message(&SwapMsg2 {
            swap_id,
            blinded_spend_token: BlindedSpendToken::from_str("invalid token")
        }){
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("Error: Blinded Token: Invalid format.")),
        }

        // Connection made through clear net
        match sc_entity.swap_second_message(&SwapMsg2 {
            swap_id,
            blinded_spend_token: BlindedSpendToken::from_str("valid token")
        }){
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("Error: Swap Token: Signature does not sign for all data in token.")),
        }

        // Valid inputs
        assert!(sc_entity.swap_second_message(&SwapMsg2 {
            swap_id,
            blinded_spend_token: BlindedSpendToken::from_str("valid token")
        }).is_ok());
    }


    // Test examples flow of Conductor with Client. Uncomment #[test] below to view test.
    // #[test]
    fn conductor_mock() {
        let state_chain_id = Uuid::from_str("001203c9-93f0-46f9-abda-0678c891b2d3").unwrap();
        let swap_id = Uuid::from_str("637203c9-37ab-46f9-abda-0678c891b2d3").unwrap();
        let conductor = create_mock_conductor(state_chain_id, swap_id);

        // Client Registers utxo with Condutor
        // First sign StateChain to prove ownership of proof key
        let proof_key_priv = SecretKey::from_slice(&[1; 32]).unwrap(); // Proof key priv part
        let proof_key = PublicKey::from_secret_key(&Secp256k1::new(), &proof_key_priv); // proof key
        let signature =
            StateChainSig::new(&proof_key_priv, &"SWAP".to_string(), &proof_key.to_string())
                .unwrap();
        let swap_size : u64 = 10;
        let _ = conductor.register_utxo(&RegisterUtxo {
            state_chain_id,
            signature,
            swap_size,
        });

        // Poll status of UTXO until a swap_id is returned signaling that utxo is involved in a swap.
        let swap_id: Uuid;
        println!("\nBegin polling of UTXO:");
        loop {
            println!("\nSleeping for 3 seconds..");
            thread::sleep(Duration::from_secs(3));
            let poll_utxo_res = conductor.poll_utxo(&state_chain_id);
            println!("poll_utxo result: {:?}", poll_utxo_res);
            if let Ok(Some(v)) = poll_utxo_res {
                println!("\nSwap began!");
                swap_id = v;
                println!("Swap id: {}", swap_id);

                break;
            }
        }

        // Now that client knows they are in swap, use swap_id to poll for swap Information
        let poll_swap_res = conductor.poll_swap(&swap_id);
        assert!(poll_swap_res.is_ok());

        let mut phase_1_complete = false;
        let mut phase_2_complete = false;

        let mut blinded_spend_token = BlindedSpendToken::from_string(String::default());

        // Poll Status of swap and perform necessary actions for each phase.
        println!("\nBegin polling of Swap:");
        loop {
            println!("\nSleeping for 3 seconds..");
            thread::sleep(Duration::from_secs(3));
            let poll_swap_res: SwapInfo = conductor.get_swap_info(&swap_id).unwrap().unwrap();
            println!("Swap status: {:?}", poll_swap_res);
            match poll_swap_res.status {
                SwapStatus::Phase1 => {
                    if phase_1_complete {
                        continue;
                    }
                    println!("\nEnter phase1:");
                    // Sign swap token
                    let swap_token = poll_swap_res.swap_token;
                    let signature = swap_token.sign(&proof_key_priv).unwrap();
                    println!("Swap token signature: {:?}", signature);
                    // Generate an SCE-address
                    let sce_address = SCEAddress {
                        tx_backup_addr: Address::from_str("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").unwrap(),
                        proof_key: proof_key,
                    };
                    println!("SCE-Address: {:?}", sce_address);
                    println!("Sending swap token signature and SCE address.");
                    // Send to Conductor
                    let first_msg_resp = conductor.swap_first_message(&SwapMsg1 {
                        swap_id: swap_token.id.clone(),
                        swap_token_sig: signature,
                        address: sce_address,
                    });
                    println!("Server response: {:?}", first_msg_resp);
                    phase_1_complete = true;
                }
                SwapStatus::Phase2 => {
                    if phase_2_complete {
                        continue;
                    }
                    println!("\nEnter phase2:");
                    println!("Blinded spend token received: {:?}", blinded_spend_token);
                    phase_2_complete = true;
                }
                SwapStatus::Phase3 => {
                    println!("\nEnter phase3:");
                    println!("Connect to Conductor via new Tor identity and present Blinded spend token.");
                    let second_msg_resp = conductor.swap_second_message(&SwapMsg2 {
                        swap_id,
                        blinded_spend_token,
                    });
                    println!("Server responds with SCE-Address: {:?}", second_msg_resp);
                    break; // end poll swap loop
                }
            }
        }
        println!("\nPolling of Swap loop ended. Client now has SCE-Address to transfer to. This is the end of our Client's interaction with Conductor.");
    }

    fn create_mock_conductor(state_chain_id: Uuid, swap_id: Uuid) -> MockConductor {
        //Create a new mock conductor
        let mut conductor = MockConductor::new();
        // Set the expectations

        conductor.expect_register_utxo().returning(|_| Ok(())); // Register UTXO with Conductor
        conductor
            .expect_poll_utxo() // utxo not yet involved
            .with(predicate::eq(state_chain_id))
            .times(2)
            .returning(|_| Ok(None));
        conductor
            .expect_poll_utxo() // utxo involved in swap
            .with(predicate::eq(state_chain_id))
            .returning(move |_| Ok(Some(swap_id)));
        conductor
            .expect_get_swap_info() // get swap status return phase 1. x3
            .with(predicate::eq(swap_id))
            .times(3)
            .returning(move |_| {
                Ok(Some(SwapInfo {
                    status: SwapStatus::Phase1,
                    swap_token: SwapToken {
                        id: swap_id,
                        amount: 1,
                        time_out: DEFAULT_TIMEOUT,
                        state_chain_ids: vec![state_chain_id, state_chain_id],
                    },
                }))
            });
        conductor.expect_swap_first_message().returning(|_| Ok(())); // First message
        conductor
            .expect_get_swap_info() // get swap status return phase 2. x2
            .with(predicate::eq(swap_id))
            .times(2)
            .returning(move |_| {
                Ok(Some(SwapInfo {
                    status: SwapStatus::Phase2,
                    swap_token: SwapToken {
                        id: swap_id,
                        amount: 1,
                        time_out: DEFAULT_TIMEOUT,
                        state_chain_ids: vec![state_chain_id, state_chain_id],
                    },
                }))
            });
        conductor
            .expect_get_swap_info() // get swap status return phase 3. x2
            .with(predicate::eq(swap_id))
            .times(1)
            .returning(move |_| {
                Ok(Some(SwapInfo {
                    status: SwapStatus::Phase3,
                    swap_token: SwapToken {
                        id: swap_id,
                        amount: 1,
                        time_out: DEFAULT_TIMEOUT,
                        state_chain_ids: vec![state_chain_id, state_chain_id],
                    },
                }))
            });
        conductor.expect_swap_second_message().returning(|_| {
            Ok(SCEAddress {
                // Second message
                tx_backup_addr: Address::from_str("bc13rgtzzwf6e0sr5mdq3lydnw9re5r7xfkvy5l649").unwrap(),
                proof_key: PublicKey::from_str("65aab40995d3ed5d03a0567b04819ff12641b84c17f5e9d5dd075571e183469c8f").unwrap(),
            })
        });
        conductor
    }


}
