//! Conductor
//!
//! Conductor swap protocol trait and implementation. Full protocol descritpion can be found in Conductor Trait.

pub use super::super::Result;
use crate::error::SEError;
use crate::server::REG_SWAP_UTXOS;
use shared_lib::{
    blinded_token::{
        BSTSenderData, BlindedSpendSignature, BlindedSpendToken, BlindedSpentTokenMessage,
    },
    state_chain::StateChainSig,
    structs::*,
    swap_data::*,
};
extern crate shared_lib;
use crate::server::StateChainEntity;
use crate::config::ConductorConfig;
use crate::protocol::transfer_batch::BatchTransfer;
use crate::protocol::withdraw::Withdraw;
use crate::storage::Storage;
use crate::Database;
use bisetmap::BisetMap;
use cfg_if::cfg_if;
use curv::FE;
use mockall::predicate::*;
use mockall::*;
use rocket::State;
use rocket_contrib::json::Json;
use std::collections::{HashMap, HashSet, LinkedList};
use std::iter::FromIterator;
use std::str::FromStr;
#[cfg(test)]
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use rocket_okapi::openapi;
use rocket_okapi::JsonSchema;
use schemars;
use bitcoin::secp256k1::Signature;
use chrono::{NaiveDateTime, Utc, Duration,Timelike};
use crate::protocol::util::RateLimiter;
use versions::Versioning;

const MIN_AMOUNT: u64 = 100000; // bitcoin tx nlocktime cutoff
const SECONDS_DAY: u32 = 86400;

#[derive(JsonSchema)]
#[schemars(remote = "Uuid")]
pub struct UuidDef(String);

//Generics cannot be used in Rocket State, therefore we define the concrete
//type of StateChainEntity here
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

/// Conductor protocol trait. Comments explain client and server side of swap protocol.
#[automock]
pub trait Conductor {
    /// API: Poll Conductor to check for status of registered utxo. Return Ok(None) if still waiting
    /// or swap_id if swap round has begun.
    fn poll_utxo(&self, statechain_id: &Uuid) -> Result<SwapID>;

    /// API: Poll Conductor to check for status of swap.
    fn poll_swap(&self, swap_id: &Uuid) -> Result<Option<SwapStatus>>;

    /// API: Get information about a swap.
    fn get_swap_info(&self, swap_id: &Uuid) -> Result<Option<SwapInfo>>;

    /// API: Phase 0:
    ///     - Alert Conductor of desire to take part in a swap. Provide StateChainSig to prove
    ///         ownership of StateChain
    fn register_utxo(&self, register_utxo_msg: &RegisterUtxo) -> Result<()>;
    fn deregister_utxo(&self, statechain_id: &Uuid) -> Result<()>;

    // Phase 1: Conductor waits until there is a large enough pool of registered UTXOs of the same size, when
    // such a pool is found Conductor generates a SwapToken and marks each UTXO as "in phase 1 of swap with id: x".
    // When a participant calls poll_utxo they see that their UTXO is involved in a swap. When they call
    // poll_swap they receive the SwapStatus and SwapToken for the swap. They now move on to phase 1.

    /// API: Phase 1:
    ///    - Participants signal agreement to Swap parameters by signing the SwapToken. They also provide
    ///         a fresh SCE_Address and e_prime for blind spend token.
    fn swap_first_message(&self, swap_msg1: &SwapMsg1) -> Result<()>;

    // Phase 2:
    //      Iff all participants have successfuly carried out Phase 1 then Conductor generates a blinded token
    //      for each participant and marks each UTXO as "in phase 2 of swap with id: x". Upon polling the
    //      participants receive 1 blinded token each.

    /// API:
    ///    get the blinded spend token required for second message only possible after the first message
    fn get_blinded_spend_signature(
        &self,
        swap_id: &Uuid,
        statechain_id: &Uuid,
    ) -> Result<BlindedSpendSignature>;

    /// API:
    ///    Participants create a new Tor identity and "spend" their blinded token to receive one
    //     of the SCEAddress' input in phase 1.
    fn swap_second_message(&self, swap_msg2: &SwapMsg2) -> Result<SCEAddress>;
    /// API:
    ///    After completing swap_second_message this fn can be used to get the SCEAddress assigned to this BST
    fn get_address_from_blinded_spend_token(&self, bst: &BlindedSpendToken) -> Result<SCEAddress>;

    // Phase 3: Participants carry out transfer_sender() and signal that this transfer is a part of
    // swap with id: x. Participants carry out corresponding transfer_receiver() and provide their
    // commitment Comm(statechain_id, nonce), to be used later as proof of completeing the protocol
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
    // transfers can reveal the nonce to the their Comm(statechain_id, nonce) and thus prove which
    // StateChain they own and should not take any responsibility for the failure.

    // Get map of values/sizes to registrations
    fn get_group_info(&self) -> Result<HashMap<SwapGroup,GroupStatus>>;

    fn update_swap_info(&self) -> Result<bool>;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Scheduler {
    //Timeout for poll utx
    utxo_timeout: u32,
    //Timeout for swap group to complete
    group_timeout: u32,
    //Time to initiate swap after group first joined
    daily_epochs: u32,
    //init swap group size,
    max_swap_size: u32,
    //minimum wallet version number
    wallet_requirement: String,
    //punishment timeout
    punishment_timeout: u32,
    //punished coins with expiry time
    punishment_map: HashMap<Uuid, NaiveDateTime>,
    //permitted swap size groups
    permitted_groups: Vec<u64>,
    //State chain id to requested swap size map
    statechain_swap_size_map: BisetMap<Uuid, u64>,
    //A map of state chain registereds for swap to amount
    statechain_amount_map: BisetMap<Uuid, u64>,
    //A map of swap groups to registrations
    group_info_map: HashMap<SwapGroup, GroupStatus>,
    //A map of state chain id to swap id
    swap_id_map: HashMap<Uuid, Uuid>,
    //A map of swap id to swap info
    swap_info_map: HashMap<Uuid, SwapInfo>,
    //A map of state chain id to poll_utxo timeout
    poll_timeout_map: HashMap<Uuid, NaiveDateTime>,
    //A map of state swap id to swap timeout
    swap_timeout_map: HashMap<Uuid, NaiveDateTime>,
    //map of swap_id to output addresses and claimed_nonces
    out_addr_map: HashMap<Uuid, BisetMap<SCEAddress, Option<Uuid>>>,
    //map of swap_id to map of state chain id to bst_e_prime values
    bst_e_prime_map: HashMap<Uuid, HashMap<Uuid, FE>>,
    //map of swap_id to map of state chain id to blinded spend signatures
    bst_sig_map: HashMap<Uuid, HashMap<Uuid, BlindedSpendSignature>>,
    //map of swap_id to transfer batch sigs
    tb_sig_map: HashMap<Uuid, HashSet<StateChainSig>>,
    shutdown_requested: bool,
}

impl Scheduler {
    pub fn new(config: &ConductorConfig) -> Self {
        let permitted_groups_vec: Vec<&str> = config.permitted_groups.split(",").collect();
        let mut permitted_groups_int: Vec<u64> = vec![];
        for group_string in permitted_groups_vec {
            let group_int: u64 = group_string.to_string().parse().unwrap();
            permitted_groups_int.push(group_int);
        }

        Self {
            utxo_timeout: config.utxo_timeout.clone(),
            #[cfg(not(test))]
            group_timeout: config.group_timeout.clone(),
            #[cfg(test)]
            group_timeout: 8,
            daily_epochs: config.daily_epochs.clone(),
            max_swap_size: config.max_swap_size.clone(),
            wallet_requirement: config.swap_wallet_version.clone(),
            #[cfg(not(test))]
            punishment_timeout: config.punishment_duration.clone() as u32,
            #[cfg(test)]
            punishment_timeout: 24, 
            punishment_map: HashMap::<Uuid, NaiveDateTime>::new(),
            permitted_groups: permitted_groups_int,
            statechain_swap_size_map: BisetMap::<Uuid, u64>::new(),
            statechain_amount_map: BisetMap::<Uuid, u64>::new(),
            group_info_map: HashMap::<SwapGroup, GroupStatus>::new(),
            swap_id_map: HashMap::<Uuid, Uuid>::new(),
            swap_info_map: HashMap::<Uuid, SwapInfo>::new(),
            poll_timeout_map: HashMap::<Uuid, NaiveDateTime>::new(),
            swap_timeout_map: HashMap::<Uuid, NaiveDateTime>::new(),
            out_addr_map: HashMap::new(),
            bst_e_prime_map: HashMap::new(),
            bst_sig_map: HashMap::new(),
            tb_sig_map: HashMap::new(),
            shutdown_requested: false,
        }
    }

    pub fn init_group_info_map(&mut self) -> Result<()> {
        let epcoh_interval = SECONDS_DAY / self.daily_epochs as u32;

        let now: NaiveDateTime = Utc::now().naive_utc();
        let mn = now.num_seconds_from_midnight();
        let next = (now.timestamp() as u32) - mn + epcoh_interval * (mn / epcoh_interval + 1);
        let next_time = NaiveDateTime::from_timestamp(next.into(),0);
        let status = GroupStatus { number: 0, time: next_time.clone() };

        // update any expired epoch times
        for value in self.group_info_map.values_mut() {
            if value.time < now {
                value.time = next_time.clone();
            }
        }

        let group = SwapGroup { amount: MIN_AMOUNT, size: self.max_swap_size as u64 };
        self.group_info_map.entry(group).or_insert(status.clone());

        let group = SwapGroup { amount: MIN_AMOUNT*10, size: self.max_swap_size as u64 };
        self.group_info_map.entry(group).or_insert(status.clone());

        let group = SwapGroup { amount: MIN_AMOUNT*100, size: self.max_swap_size as u64 };
        self.group_info_map.entry(group).or_insert(status.clone());

        let group = SwapGroup { amount: MIN_AMOUNT*1000, size: self.max_swap_size as u64 };
        self.group_info_map.entry(group).or_insert(status);

        Ok(())
    }

    pub fn get_swap_id(&self, statechain_id: &Uuid) -> Option<Uuid> {
        self.swap_id_map.get(statechain_id).cloned()
    }

    pub fn reset_poll_utxo_timeout(&mut self, statechain_id: &Uuid, init: bool) -> bool{
        let now: NaiveDateTime = Utc::now().naive_utc();
        let t = now + Duration::seconds(self.utxo_timeout as i64);
        if !init &! self.poll_timeout_map.contains_key(statechain_id) { return false; }
        match self.poll_timeout_map.insert(*statechain_id, t){
            Some(t_prev) => {
                if t_prev <= now {
                        self.poll_timeout_map.remove(statechain_id);
                        false
                    } else {
                        true
                    }
            },
            None => true
        }
    }

    pub fn get_poll_utxo_timeout(&self, statechain_id: &Uuid) -> Option<bool> {
        let now: NaiveDateTime = Utc::now().naive_utc();
        match self.poll_timeout_map.get(statechain_id){
            Some(t) => {
                Some(&now < t)
            },
            None => None
        }
    }

    pub fn reset_swap_timeout(&mut self, swap_id: &Uuid, init: bool) -> bool{
        let now: NaiveDateTime = Utc::now().naive_utc();
        let t = now + Duration::seconds(self.group_timeout as i64);
        match self.swap_timeout_map.insert(*swap_id, t){
            Some(t_prev) => {
                if t_prev <= now {
                        self.swap_timeout_map.remove(swap_id);
                        false
                    } else {
                        true
                    }
            },
            None => {
                if init {
                    true
                } else {
                    self.swap_timeout_map.remove(swap_id);
                    false
                }
            },
        }
    }

    pub fn get_swap_timeout(swap_timeout_map: &HashMap<Uuid, NaiveDateTime>, swap_id: &Uuid) -> Option<bool> {
        let now: NaiveDateTime = Utc::now().naive_utc();
        match swap_timeout_map.get(swap_id){
            Some(t) => {
                Some(&now < t)
            },
            None => None
        }
    }

    pub fn register_amount_swap_size(
        &mut self,
        statechain_id: &Uuid,
        amount: u64,
        swap_size: u64,
    ) -> Result<()> {
        self.reset_poll_utxo_timeout(statechain_id, true);
        //Only register if id not already in swap map
        let in_swap = self.swap_id_map.get(&statechain_id);
        if (!in_swap.is_none()) {
            let swap_timeout = self.swap_timeout_map.get(in_swap.unwrap());
            let now: NaiveDateTime = Utc::now().naive_utc();
            let seconds_remaining = swap_timeout.unwrap().timestamp() - now.timestamp();
            return Err(SEError::SwapError(format!("Coin in active swap. Seconds remaining: {:?}", &seconds_remaining)));
        };

        // check and update punishment list
        if self.punishment_map.contains_key(&statechain_id) {
            let now: NaiveDateTime = Utc::now().naive_utc();
            if self.punishment_map.get(&statechain_id).unwrap() < &now {
                self.punishment_map.remove(&statechain_id);
            } else {
                let seconds_remaining = self.punishment_map.get(&statechain_id).unwrap().timestamp() - now.timestamp();
                return Err(SEError::SwapError(format!("In punishment list. Seconds remaining: {:?}", &seconds_remaining)));
            }
        }

        //If there was an amout already registered for this state chain id then
        //remove it from the inverse table before updating
        if (!self.statechain_amount_map.contains(&statechain_id,&amount)) {
            self.statechain_amount_map
                .insert(statechain_id.to_owned(), amount);
            self.statechain_swap_size_map
                .insert(statechain_id.to_owned(), swap_size);

            let epcoh_interval = SECONDS_DAY / self.daily_epochs as u32;
            let now: NaiveDateTime = Utc::now().naive_utc();
            let mn = now.num_seconds_from_midnight();
            let next = (now.timestamp() as u32) - mn + epcoh_interval * (mn / epcoh_interval + 1);
            let status = GroupStatus { number: 0, time: NaiveDateTime::from_timestamp(next.into(),0) };

            let group = SwapGroup { amount: amount, size: swap_size};
            let count = self.group_info_map.entry(group)
                .or_insert(status);
            count.number += 1;

            //metrics
            REG_SWAP_UTXOS.with_label_values(&[&swap_size.clone().to_string(),&amount.clone().to_string()]).inc();
        } else {
            return Err(SEError::SwapError(format!("Statecoin already registered: {}", statechain_id)));
        }
        Ok(())
    }

    pub fn get_statechain_ids_by_amount(&self, amount: &u64) -> Vec<Uuid> {
        self.statechain_amount_map.rev_get(amount)
    }

    fn register_swap_id(&mut self, statechain_id: &Uuid, swap_id: &Uuid) -> Option<Uuid> {
        self.swap_id_map
            .insert(statechain_id.to_owned(), swap_id.to_owned())
    }

    fn deregister_swap_id(&mut self, statechain_id: &Uuid) -> Option<Uuid> {
        self.swap_id_map.remove(statechain_id)
    }

    pub fn insert_swap_info(&mut self, swap_info: &SwapInfo) {
        let swap_id = &swap_info.swap_token.id;
        self.swap_info_map
            .insert(swap_id.to_owned(), swap_info.to_owned());
        for id in &swap_info.swap_token.statechain_ids {
            self.register_swap_id(id, swap_id);
        }
    }

    pub fn remove_swap_info(&mut self, swap_id: &Uuid) -> Option<SwapInfo> {
        match self.get_swap_info(swap_id) {
            Some(i) => {
                for id in i.to_owned().swap_token.statechain_ids {
                    self.deregister_swap_id(&id);
                    self.poll_timeout_map.remove(&id);
                }
                let swap_id = &i.swap_token.id;
                self.swap_info_map.remove(swap_id);
                self.out_addr_map.remove(swap_id);
                self.bst_e_prime_map.remove(swap_id);
                self.bst_sig_map.remove(swap_id);
                self.swap_timeout_map.remove(swap_id);
                Some(i)
            }
            None => None,
        }
    }

    //Remove the "registered" statechain info that exists before a swap group has been formed
    pub fn remove_statechain_info(&mut self, statechain_id: &Uuid) {
        let swap_size = self.statechain_swap_size_map.get(statechain_id);
        if (swap_size.len()==0) { return }
        self.statechain_swap_size_map.remove(statechain_id, &swap_size[0]);
        let amount = self.statechain_amount_map.get(statechain_id);
        if (self.statechain_amount_map.contains(&statechain_id,&amount[0])) {
            let group = SwapGroup { amount: amount[0], size: swap_size[0]};

            match self.group_info_map.get_mut(&group) {
                Some(count) => {
                    if count.number > 0 {
                        count.number -= 1;
                    }
                }
                _ => ()
            }
        }
        self.statechain_amount_map.remove(statechain_id, &amount[0]);
        self.poll_timeout_map.remove(statechain_id);
    }

    pub fn get_swap_info(&self, swap_id: &Uuid) -> Option<SwapInfo> {
        self.swap_info_map.get(swap_id).cloned()
    }

    pub fn get_swap_status(&self, swap_id: &Uuid) -> Option<SwapStatus> {
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
        for (amount, mut sc_id_vec) in amount_collect {
            //Get a reduced swap size map containing items of this amount
            let swap_size_map = BisetMap::<Uuid, u64>::new();
            sc_id_vec.retain(|id|{
                match self.get_poll_utxo_timeout(id) {
                    Some(true) => {
                        let swap_size = self.statechain_swap_size_map.get(id);
                        if (!swap_size.is_empty()) {
                            swap_size_map.insert(id.to_owned(), swap_size[0]);
                        }
                        true
                    },
                    _ => {
                        self.remove_statechain_info(id);
                        false
                    }
                }
            });
            let mut n_remaining = sc_id_vec.len();

            if n_remaining == 0 {continue};

            let swap_size_map = swap_size_map.rev();

            //Loop through swap sizes in descending order
            let mut swap_size_collect = swap_size_map.collect();
            swap_size_collect.sort();
            let swap_size_vec: Vec<usize> =
                swap_size_collect.iter().map(|x| x.0 as usize).collect();
            let swap_size_max = swap_size_vec
                .last()
                .expect("expected non-empty vector")
                .to_owned() as usize;
            let mut ids_for_swap = Vec::<Uuid>::new();
            while (!swap_size_collect.is_empty()) {

                //Remove from the back of the vector, which will be the largest swap_size
                let (mut swap_size, mut sc_ids) = swap_size_collect.pop().unwrap();

                let group = SwapGroup { amount: amount.clone(), size: swap_size.clone() };
                let now: NaiveDateTime = Utc::now().naive_utc();

                // if either group size has been met or that the countdown time has been reached with at least two registrations
                // if countdown reached with > 1 coin, then use current group size
                match self.group_info_map.get(&group.clone()) {
                    Some(count) => {
                        if (sc_ids.len() >= 2 && now >= count.time) {
                            swap_size = (sc_ids.len() as u64)
                        }
                    }
                    _ => ()
                }

                if (n_remaining + ids_for_swap.len() >= swap_size as usize) {
                    //Collect some ids together for a swap
                    while (!sc_ids.is_empty() && ids_for_swap.len() < swap_size_max) {
                        let id = sc_ids.pop().unwrap();
                        ids_for_swap.push(id);
                        n_remaining = n_remaining - 1;
                    }
                }
                else {
                    break;
                }

                //Create a swap token with these ids and clear temporary vector of sc ids
                if (ids_for_swap.len() == swap_size_max || n_remaining == 0) {
                    let swap_id = Uuid::new_v4();

                    let swap_token = SwapToken {
                        id: swap_id.clone(),
                        amount,
                        time_out: self.group_timeout as u64,
                        statechain_ids: ids_for_swap.clone(),
                    };

                    let si = SwapInfo {
                        status: SwapStatus::Phase1,
                        swap_token,
                        bst_sender_data: BSTSenderData::setup(),
                    };
                    //Initialize the swap timeout
                    self.reset_swap_timeout(&swap_id, true);
                    //Add the swap info to the map of swap infos
                    self.insert_swap_info(&si);
                    //Remove the ids from the request lists
                    while (!ids_for_swap.is_empty()) {
                        let id = ids_for_swap.pop().unwrap();
                        //Assert that the number of values that were removed was 1
                        //as a coherence check
                        assert!(self.statechain_swap_size_map.delete(&id).len() == 1);
                        assert!(self.statechain_amount_map.delete(&id).len() == 1);
                    }

                    // update the time to the next interval
                    let epcoh_interval = SECONDS_DAY / self.daily_epochs as u32;
                    let now2: NaiveDateTime = Utc::now().naive_utc();
                    let mn = now2.num_seconds_from_midnight();
                    let next = (now2.timestamp() as u32) - mn + epcoh_interval * (mn / epcoh_interval + 1);
                    let status = GroupStatus { number: 0, time: NaiveDateTime::from_timestamp(next.into(),0) };

                    self.group_info_map.insert(group,status);

                    info!("SCHEDULER: Created Swap ID: {}", swap_id);
                    debug!("SCHEDULER: Swap Info: {:?}", si);
                }

                //Push back the remaining sc_ids if there are enough remaining scs for them
                //to be included in a swap
                if (!sc_id_vec.is_empty() && swap_size as usize <= n_remaining) {
                    swap_size_collect.push((swap_size, sc_ids));
                }
            }
        }
    }

    /*
    pub fn update_swap_timeouts(&mut self) -> Result<()> {
        let remove_list: LinkedList<Uuid> = LinkedList::new();
        for (swap_id, swap_info) in self.swap_info_map.iter_mut() {
            match self.get_swap_timeout(&swap_info.swap_token.id) {
                Some(true) => (),
                _ => {
                    remove_list.push_back(swap_info.swap_token.id);
                    continue;
                }
        };
    }
*/

    //Update the swap info based on the results of user first/second messages
    pub fn update_swaps(&mut self) -> Result<()> {
        let mut remove_list: LinkedList<Uuid> = LinkedList::new();
        for (swap_id, swap_info) in self.swap_info_map.iter_mut() {
                match Self::get_swap_timeout(&self.swap_timeout_map, &swap_info.swap_token.id) {
                    Some(true) => (),
                    _ => {
                        // swap phase 1/2 timeout
                        // get e_prime_map for swap_id
                        let e_prime_map = self.bst_e_prime_map.get_mut(swap_id);

                        // check if each sc_id completed
                        if !e_prime_map.is_none() {
                            for sc_id in &swap_info.swap_token.statechain_ids {
                                println!("{:?}", sc_id);
                                if !e_prime_map.as_ref().unwrap().contains_key(&sc_id) {
                                    info!("SCHEDULER: Statchain ID: {} punished in Swap ID: {} for failure to complete phase1/2", sc_id, swap_id);
                                    let now: NaiveDateTime = Utc::now().naive_utc();
                                    let t = now + Duration::seconds(self.punishment_timeout as i64);
                                    self.punishment_map.insert(*sc_id,t);
                                }
                            }
                        }

                        remove_list.push_back(swap_info.swap_token.id);
                        continue;
                    }
                };

                match swap_info.status {
                        //Phase 1 - check if all state chain addresses have been received, if so:
                        //    - Generate a Blind Spend Tokens for each participant
                        //    - Move swap to phase 2
                        SwapStatus::Phase1 => {
                            let out_addr_map: &BisetMap<SCEAddress, Option<Uuid>> =
                                match self.out_addr_map.get(&swap_id) {
                                    Some(out_addr_map) => out_addr_map,
                                    None => return Ok(()), // BisetMap not yet created means no participants have completed swap_msg_1 yet
                                };
                            if (swap_info.swap_token.statechain_ids.len() == out_addr_map.len()) {
                                //All output addresses received.
                                //Generate a list of blinded spend tokens and proceed to phase 2.
                                let swap_id = swap_info.swap_token.id;
                                let scid_bst_map = generate_blind_spend_signatures(
                                    &swap_info,
                                    self.bst_e_prime_map.get(&swap_id),
                                )?;
                                self.bst_sig_map.insert(swap_id, scid_bst_map);
                                swap_info.status = SwapStatus::Phase2;
                                info!("SCHEDULER: Swap ID: {} moved on to Phase2", swap_id);
                            }
                        }
                        SwapStatus::Phase2 => {
                            //Phase 2 - Return BST and SCEAddresses for corresponding valid signtures
                            //Signature ok. Add the SCEAddress to the list.
                            let sce_addr_list = match self.out_addr_map.get(swap_id) {
                                Some(sce_addr_list) => sce_addr_list,
                                None => {
                                    return Err(SEError::SwapError(
                                        "In phase 2 but no SCEAddress<->claimed_nonce map found"
                                            .to_string(),
                                    ))
                                }
                            };
                            // Check if there are any unclaimed SCEAddresses
                            if sce_addr_list.rev_get(&None).len() == 0 {
                                swap_info.status = SwapStatus::Phase3;
                            }
                            info!("SCHEDULER: Swap ID: {} moved on to Phase3", swap_id);
                        }
                        _ => {}
                };
        };

        for swap_id in remove_list.iter(){
            self.remove_swap_info(swap_id);
        }
        
        Ok(())
    }

    pub fn transfer_started(&mut self, id: &Uuid) -> Result<()> {
        match self.swap_info_map.get_mut(id) {
            Some(i) => match i.status {
                SwapStatus::Phase3 => {
                    i.status = SwapStatus::Phase4;
                    info!("SCHEDULER: Swap ID: {} moved to Phase4", id);
                }
                SwapStatus::Phase4 => {
                    return Err(SEError::SwapError(
                        "Sheduler: transfer_started: swap already started".to_string(),
                    ))
                }
                SwapStatus::End => {
                    return Err(SEError::SwapError(
                        "Sheduler: transfer_started: swap already ended".to_string(),
                    ))
                }
                _ => {
                    return Err(SEError::SwapError(
                        "Sheduler: transfer_started: swap not yet in phase 3".to_string(),
                    ))
                }
            },
            None => {
                return Err(SEError::SwapError(format!(
                    "Sheduler: transfer_started: swap id not found: {}",
                    id
                )))
            }
        };
        Ok(())
    }

    pub fn transfer_ended(&mut self, id: &Uuid) -> Result<()> {
        match self.swap_info_map.get_mut(id) {
            Some(i) => match i.status {
                SwapStatus::Phase4 => {
                    i.status = SwapStatus::End;
                    info!("SCHEDULER: Swap ID: {} moved to phase End", id);
                }
                SwapStatus::End => {
                    return Err(SEError::SwapError(
                        "Sheduler: transfer_ended: swap already ended".to_string(),
                    ))
                }
                _ => {
                    return Err(SEError::SwapError(
                        "Sheduler: transfer_ended: swap not yet in transfer phase".to_string(),
                    ))
                }
            },
            None => {
                return Err(SEError::SwapError(format!(
                    "Sheduler: transfer_ended: swap id not found: {}",
                    id
                )))
            }
        };

        self.remove_swap_info(id);
        Ok(())
    }

    pub fn update_swap_info(&mut self) -> Result<()> {
        self.update_swap_requests();
        self.init_group_info_map()?;
        self.update_swaps()
    }

    pub fn request_shutdown(&mut self) {
        self.shutdown_requested = true;
    }

    pub fn shutdown_ready(&self) -> bool {
       self.shutdown_requested && !self.swaps_ongoing()
    }

    pub fn swaps_ongoing(&self) -> bool {
        for value in self.swap_info_map.values() {
            if value.status != SwapStatus::End {
                return true;
            }
        }
        false
    }

    pub fn get_blinded_spend_signature(
        &self,
        swap_id: &Uuid,
        statechain_id: &Uuid,
    ) -> Result<BlindedSpendSignature> {
        match self.get_swap_status(swap_id) {
            Some(SwapStatus::Phase1) => Err(SEError::SwapError(
                "in phase 1, token not available".to_string(),
            )),
            None => Err(SEError::SwapError(
                "unknown swap id when getting swap status".to_string(),
            )),
            _ => match self.bst_sig_map.get(swap_id) {
                Some(m) => match m.get(statechain_id) {
                    Some(bst) => Ok(bst.clone()),
                    None => Err(SEError::SwapError("unknown statechain id".to_string())),
                },
                None => Err(SEError::SwapError(
                    "unknown swap id when getting blind spending token".to_string(),
                )),
            },
        }
    }

    fn register_bst(&mut self, swap_msg1: &SwapMsg1) -> Result<()> {
        let base_err = "blind spend token e_prime already registered for statechain id";
        // Add bst_e_prime value to list. If a BST has already been registered for the
        // statechain_id, return an error.
        let swap_id = &swap_msg1.swap_id;
        let statechain_id = &swap_msg1.statechain_id;

        // Create a new e_prime map if one does not exist, and assign it to a mutable
        // reference
        let e_prime_map = match self.bst_e_prime_map.get_mut(swap_id){
            Some(m) => m,
            None => {
                let m = HashMap::<Uuid, FE>::new();
                self.bst_e_prime_map
                        .insert(swap_id.to_owned(), m);                
                self.bst_e_prime_map
                        .get_mut(swap_id).unwrap()
            }
        };
            
        match e_prime_map.get(statechain_id){
            Some(bst_e_prime) => {
                // The e_prime is already registered - if the data in the request match
                // the registered data then return the existing blind spend token data.
                // If not, return an error.
                           
                // 1. Check the user BST e_prime matches the registered one
                // 2. Check the transfer batch sig is in the set
                // 3. Check the address is in the list
                           
                if bst_e_prime != &swap_msg1.bst_e_prime {
                    return Err(SEError::SwapError(
                            format!("{} {}, but does not match the requested bst_e_prime",
                            base_err,
                            statechain_id)
                            ))
                }

                let tbs_set = self.tb_sig_map.get_mut(swap_id);
                if tbs_set.is_none() || !tbs_set.unwrap().contains(&swap_msg1.transfer_batch_sig) {
                    return Err(SEError::SwapError(
                                format!("{} {}, but transfer batch signature not found",
                                base_err,
                                statechain_id)
                            )
                    )
                }

                let sce_address_list = self.out_addr_map.get_mut(swap_id);
                if sce_address_list.is_none() || !sce_address_list.unwrap().key_exists(&swap_msg1.address){
                    return Err(SEError::SwapError(
                                format!("{} {}, but address not found",
                                    base_err,
                                    statechain_id)
                                )
                        )
                }

            },
            None => {
                e_prime_map.insert(swap_msg1.statechain_id, swap_msg1.bst_e_prime);

                //Add the transfer batch signature to the list. If it doesn't exist, make a new one.
                match self.tb_sig_map.get_mut(swap_id) {
                    Some(v) => {
                        v.insert(swap_msg1.transfer_batch_sig.clone());
                    }
                    None => {
                        let mut tbs_set = HashSet::<StateChainSig>::new();
                        tbs_set.insert(swap_msg1.transfer_batch_sig.clone());
                        self.tb_sig_map.insert(swap_id.to_owned(), tbs_set);
                    }
                }

                //Add the SCEAddress to the list.
                match self.out_addr_map.get_mut(swap_id) {
                    Some(sce_address_list) => {
                        sce_address_list.insert(swap_msg1.address.clone(), None);
                    }
                    None => {
                        let sce_address_list = BisetMap::<SCEAddress, Option<Uuid>>::new(); // create new sce_address_list if none exists
                        sce_address_list.insert(swap_msg1.address.clone(), None);
                        self
                            .out_addr_map
                            .insert(swap_id.to_owned(), sce_address_list);
                    }
                };

            }
        };
        Ok(())        
    }
                  

    
}

/// Generate A Blind Spend Token for each e_prime value provided
pub fn generate_blind_spend_signatures(
    swap_info: &SwapInfo,
    bst_e_prime_map: Option<&HashMap<Uuid, FE>>,
) -> Result<HashMap<Uuid, BlindedSpendSignature>> {
    let bst_e_prime_map: &HashMap<Uuid, FE> = bst_e_prime_map.ok_or(SEError::SwapError(
        "Cannot generate BSTs - e_prime values not found for swap.".to_string(),
    ))?;
    let swap_size = &swap_info.swap_token.statechain_ids.len();
    let e_prime_map_size = &bst_e_prime_map.len();
    if swap_size != e_prime_map_size {
        return Err(SEError::SwapError(
            format!("Cannot generate BSTs - swap size = {}, e_prime map size = {}",swap_size, e_prime_map_size)
        ))
    }

    let mut scid_bst_sig_map = HashMap::<Uuid, BlindedSpendSignature>::new();
    for (sc_id, e_prime) in bst_e_prime_map {
        let sig = swap_info
            .bst_sender_data
            .gen_blind_signature(e_prime.clone());
        scid_bst_sig_map.insert(sc_id.clone(), sig);
    }
    Ok(scid_bst_sig_map)
}

impl Conductor for SCE {
    fn poll_utxo(&self, statechain_id: &Uuid) -> Result<SwapID> {
        let mut guard = self.scheduler.as_ref().expect("scheduler is None").lock()?;
        let result = match guard.reset_poll_utxo_timeout(statechain_id, false){
            true => Ok(SwapID { id: guard.get_swap_id(statechain_id) } ),
            false => Err(SEError::SwapError(format!("statechain timed out or has not been requested for swap: {}", statechain_id))),
        };
        drop(guard);
        result
    }

    fn poll_swap(&self, swap_id: &Uuid) -> Result<Option<SwapStatus>> {
        let mut guard = self.scheduler.as_ref().expect("scheduler is None").lock()?;
        let status = guard.get_swap_status(swap_id);
        // If in the batch transfer phase, poll the status of the transfer
        match status {
            Some(v) => match v {
                SwapStatus::Phase3 => {
                    let signatures = match guard.tb_sig_map.get(&swap_id).cloned() {
                        Some(s) => Vec::from_iter(s),
                        None => {
                            return Err(SEError::SwapError(
                                "batch transfer signatures not found".to_string(),
                            ))
                        }
                    };
                    let msg = TransferBatchInitMsg {
                        id: swap_id.to_owned(),
                        signatures,
                    };
                    self.transfer_batch_init(msg)?;
                    let _ = guard.transfer_started(swap_id)?;
                }
                SwapStatus::Phase4 => match self.get_transfer_batch_status(swap_id.to_owned()) {
                    Ok(res) => {
                        if res.finalized {
                            let _ = guard.transfer_ended(swap_id)?;
                        }
                    }
                    Err(e) => match e {
                        SEError::TransferBatchEnded(_) => {
                            let _ = guard.transfer_ended(swap_id)?;
                        }
                        _ => (),
                    },
                },
                SwapStatus::End => (),
                _ => (),
            },
            None => (),
        }
        Ok(status)
    }

    fn get_swap_info(&self, swap_id: &Uuid) -> Result<Option<SwapInfo>> {
        let _ = self.poll_swap(swap_id)?;
        let guard = self.scheduler.as_ref().expect("scheduler is None").lock()?;
        Ok(guard.get_swap_info(swap_id))
    }

    fn get_blinded_spend_signature(
        &self,
        swap_id: &Uuid,
        statechain_id: &Uuid,
    ) -> Result<BlindedSpendSignature> {
        let guard = self.scheduler.as_ref().expect("scheduler is None").lock()?;
        Ok(guard.get_blinded_spend_signature(swap_id, statechain_id)?)
    }

    fn register_utxo(&self, register_utxo_msg: &RegisterUtxo) -> Result<()> {
        let mut guard = self.scheduler.as_ref().expect("scheduler is None").lock()?;
        if guard.shutdown_requested {
            return Err(SEError::SwapError(String::from("unable to register for swap - conductor is shutting down - please try later")));
        }
        let sig = &register_utxo_msg.signature;
        let key_id = &register_utxo_msg.statechain_id;
        let swap_size = &register_utxo_msg.swap_size;

        let wall_version = Versioning::new(&register_utxo_msg.wallet_version).expect("invalid wallet version number");
        let req_version = Versioning::new(&guard.wallet_requirement).expect("invalid wallet version number");

        if wall_version < req_version {
            return Err(SEError::SwapError(String::from("Incompatible wallet version: please upgrade to latest version")));
        }

        //Verify the signature
        let _ = self.verify_statechain_sig(key_id, sig, None)?;

        let sc_amount = self.database.get_statechain_amount(*key_id)?;
        let amount: u64 = sc_amount.amount.clone() as u64;

        // check if amount permitted
        if !guard.permitted_groups.contains(&amount) {
            return Err(SEError::SwapError(format!("Invalid coin amount for swap registration: {}. Permitted amounts: {:#?}",&amount,&guard.permitted_groups)));
        }

        if !self.database.is_confirmed(&key_id)? {
            self.verify_tx_confirmed(&key_id)?;
            self.database.set_confirmed(&key_id)?;
            // add to histogram
            let mut guard = self.coin_value_info.as_ref().lock()?;
            guard.increment(&sc_amount.amount);
        }

        let _res = match guard.register_amount_swap_size(key_id, amount, *swap_size) {
            Ok(_res) => return Ok(()),
            Err(err) => return Err(err),
        };
    }

    fn deregister_utxo(&self, statechain_id: &Uuid) -> Result<()> {
        let mut guard = self.scheduler.as_ref().expect("scheduler is None").lock()?;
        guard.remove_statechain_info(statechain_id);
        Ok(())
    }

    fn get_group_info(&self) -> Result<HashMap<SwapGroup,GroupStatus>> {
        let guard = self.scheduler.as_ref().expect("scheduler is None").lock()?;
        Ok(guard.group_info_map.clone())
    }

    fn update_swap_info(&self) -> Result<bool>{
        if self.check_rate_slow("update_swap_info").is_ok() {
            let mut guard = self.scheduler.as_ref().expect("scheduler is None").lock().unwrap();
            guard.update_swap_info()?;
            drop(guard);
            return Ok(true)
        }
        return Ok(false)
    }
    
    fn swap_first_message(&self, swap_msg1: &SwapMsg1) -> Result<()> {
        let state_chain = self.get_statechain(swap_msg1.statechain_id)?;
        let proof_key_str = &state_chain.get_tip().data;
        let proof_key = bitcoin::secp256k1::PublicKey::from_str(&proof_key_str)?;

        //let proof_key = &swap_msg1.address.proof_key;
        //Find the correct swap token and verify
        let mut guard = self.scheduler.as_ref().expect("scheduler is None").lock()?;
        let swap_id = &swap_msg1.swap_id;
        match guard.get_swap_info(swap_id) {
            Some(i) => {
                i.swap_token
                    .verify_sig(&proof_key, Signature::from_str(&swap_msg1.swap_token_sig)?)?;

                //Swap token signature ok
                //Verify purpose and data of batch transfer signature
                if !swap_msg1
                    .transfer_batch_sig
                    .is_transfer_batch(Some(swap_id))
                {
                    return Err(SEError::SwapError(
                        format!("swap_first_message: signature is not transfer batch: {:?}", swap_msg1
                        .transfer_batch_sig)
                    ));
                }

                if swap_msg1.statechain_id.to_string() != swap_msg1.transfer_batch_sig.data {
                    return Err(SEError::SwapError(
                        "swap first message: state chain id does not match signature data"
                            .to_string(),
                    ));
                }

                let _ = self.verify_statechain_sig(
                    &swap_msg1.statechain_id,
                    &swap_msg1.transfer_batch_sig,
                    None,
                )?;

                guard.register_bst(&swap_msg1)?;                

                info!(
                    "CONDUTOR: swap_first_message complete for StateChain ID {} of Swap ID: {}",
                    swap_msg1.statechain_id, swap_id
                );
                Ok(())
            }
            None => Err(SEError::SwapError(format!(
                "no swap with id {}",
                &swap_msg1.swap_token_sig
            ))),
        }
    }

    fn swap_second_message(&self, swap_msg2: &SwapMsg2) -> Result<SCEAddress> {
        // Get message that is signed
        let bst_msg: BlindedSpentTokenMessage =
            match serde_json::from_str(&swap_msg2.blinded_spend_token.get_msg()) {
                Ok(v) => v,
                Err(_) => {
                    return Err(SEError::SwapError(
                        "swap_second_message: Failed to deserialize message.".to_string(),
                    ))
                }
            };

        // Ensure swap_ids match
        match Uuid::from_str(&bst_msg.swap_id) {
            Ok(id) => {
                if id != swap_msg2.swap_id {
                    return Err(SEError::SwapError(
                        "swap_second_message: swap_ids do not match.".to_string(),
                    ));
                }
            },
            Err(err) => return Err(SEError::SwapError(
                format!("BlindedSpendTokenMessage - invalid swap id: {}", err)
            )),
        };

        let swap_id = &swap_msg2.swap_id;
        let mut guard = self.scheduler.as_ref().expect("scheduler is None").lock()?;
        let swap_info = match guard.get_swap_info(&swap_id) {
            Some(i) => i,
            None => {
                return Err(SEError::SwapError(format!(
                    "swap_second_message: no swap with id {}",
                    swap_id
                )))
            }
        };

        // Verify BlindSpentToken
        if swap_info
            .bst_sender_data
            .verify_blind_spend_token(swap_msg2.blinded_spend_token.clone())?
        {
            // Get BisetMap of SCEAddress to Option<calimed_nonce> for this swap id
            let sce_address_bisetmap =
                guard
                    .out_addr_map
                    .get_mut(&swap_id)
                    .ok_or(SEError::SwapError(format!(
                        "swap_second_message: no swap with id {}",
                        swap_id
                    )))?;

            // First check if claimed_nonce is already assigned to a SCEAddress
            let claimed_nonce = match Uuid::from_str(&bst_msg.nonce){
                Ok(nonce) => Some(nonce),
                Err(err) => return Err(SEError::SwapError(format!("invalid nonce: {}", err)))
            };
            let claimed_nonce_sce_addrs_vec = sce_address_bisetmap.rev_get(&claimed_nonce);
            let claimed_nonce_assignments_num = claimed_nonce_sce_addrs_vec.len();
            if claimed_nonce_assignments_num > 1 {
                error!("claimed_nonce assigned to more than one SCEAddress. Nonce: {:?}. Swap ID: {:?}", claimed_nonce, swap_id);
                return Err(SEError::SwapError(
                    "swap_second_message: claimed_nonce assigned to more than one SCEAddress"
                        .to_string(),
                ));
            } else if claimed_nonce_assignments_num == 1 {
                // SCEAddress already claimed for this nonce. Return the address.
                info!("CONDUTOR: swap_second_message re-completed for claimed nonce {:?} of Swap ID: {}", claimed_nonce, swap_id);
                return Ok(claimed_nonce_sce_addrs_vec.get(0).
                    ok_or(SEError::SwapError(
                    "swap_second_message: claimed_nonce_sce_addrs_vec is empty".to_string()))?
                    .clone());
            }
            // Otherwise add to the first SCEAddress in sce_address_bisetmap without a claimed_nonce
            let unclaimed_addr_list = sce_address_bisetmap.rev_get(&None); // get list all SCEAddress's without a claimed_nonce
            if unclaimed_addr_list.len() == 0 {
                return Err(SEError::SwapError(
                    "swap_second_message: All SCEAddresses have been claimed.".to_string(),
                ));
            }
            let addr = unclaimed_addr_list.get(0).
                unwrap().
                clone();
            sce_address_bisetmap.insert(addr.clone(), claimed_nonce);
            sce_address_bisetmap.remove(&addr, &None);

            info!(
                "CONDUTOR: swap_second_message completed for claimed nonce {:?} of Swap ID: {}",
                claimed_nonce, swap_id
            );
            Ok(addr)
        } else {
            return Err(SEError::SwapError(
                "swap_second_message: Blind Spent Token signature verification failed.".to_string(),
            ));
        }
    }

    fn get_address_from_blinded_spend_token(&self, bst: &BlindedSpendToken) -> Result<SCEAddress> {
        let bst_msg: BlindedSpentTokenMessage = match serde_json::from_str(&bst.get_msg()) {
            Ok(v) => v,
            Err(_) => {
                return Err(SEError::SwapError(
                    "Failed to deserialize message.".to_string(),
                ))
            }
        };

        let bst_swap_id = match Uuid::from_str(&bst_msg.swap_id){
            Ok(id) => id,
            Err(err) => return Err(SEError::SwapError(format!("invalid swap id: {}", err)))
        };

        let mut guard = self.scheduler.as_ref().expect("scheduler is None").lock()?;
        let sce_address_bisetmap =
            guard
                .out_addr_map
                .get_mut(&bst_swap_id)
                .ok_or(SEError::SwapError(format!(
                    "No swap with id {}",
                    bst_msg.swap_id
                )))?;

        let claimed_nonce = match Uuid::from_str(&bst_msg.nonce){
            Ok(nonce) => Some(nonce),
            Err(err) => return Err(SEError::SwapError(format!("invalid nonce: {}", err)))
        };

        let claimed_nonce_sce_addrs_vec = sce_address_bisetmap.rev_get(&claimed_nonce);
        let claimed_nonce_assignments_num = claimed_nonce_sce_addrs_vec.len();
        if claimed_nonce_assignments_num > 1 {
            error!(
                "claimed_nonce assigned to more than one SCEAddress. Nonce: {:?}. Swap ID: {:?}",
                claimed_nonce, bst_msg.swap_id
            );
            return Err(SEError::SwapError("get_address_from_blinded_spend_token: claimed_nonce assigned to more than one SCEAddress".to_string()));
        } else if claimed_nonce_assignments_num == 1 {
            // Return the address.
            return Ok(claimed_nonce_sce_addrs_vec.get(0).
                        ok_or(SEError::SwapError(
                            "get_address_from_blinded_spend_token: 
                            claimed_nonce_sce_addrs_vec is empty".to_string()))?.
                    clone());
        }
        return Err(SEError::SwapError(
            "No SCEAddress claimed for this Blinded Spent Token.".to_string(),
        ));
    }
}

#[openapi]
/// # Poll conductor for the status of a specified registered statecoin ID
#[post("/swap/poll/utxo", format = "json", data = "<statechain_id>")]
pub fn poll_utxo(sc_entity: State<SCE>, statechain_id: Json<StatechainID>) -> Result<Json<SwapID>> {
    sc_entity.check_rate_fast("swap")?;
    sc_entity.update_swap_info()?;
    match sc_entity.poll_utxo(&statechain_id.id) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Poll conductor for the status of a specified swap ID
#[post("/swap/poll/swap", format = "json", data = "<swap_id>")]
pub fn poll_swap(sc_entity: State<SCE>, swap_id: Json<SwapID>) -> Result<Json<Option<SwapStatus>>> {
    sc_entity.check_rate_fast("swap")?;
    sc_entity.update_swap_info()?;
    match sc_entity.poll_swap(&swap_id.id.ok_or("poll_swap: swap_id.id is None".to_string())?) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Get information a specified swap ID
#[post("/swap/info", format = "json", data = "<swap_id>")]
pub fn get_swap_info(sc_entity: State<SCE>, swap_id: Json<SwapID>) -> Result<Json<Option<SwapInfo>>> {
    sc_entity.check_rate_fast("swap")?;
    sc_entity.update_swap_info()?;
    match sc_entity.get_swap_info(
        &swap_id.id.ok_or("poll_swap: swap_id.id is None".to_string())?) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Get blinded spend token required for second message
#[post("/swap/blinded-spend-signature", format = "json", data = "<bst_msg>")]
pub fn get_blinded_spend_signature(
    sc_entity: State<SCE>,
    bst_msg: Json<BSTMsg>,
) -> Result<Json<BlindedSpendSignature>> {
    sc_entity.check_rate_fast("swap")?;
    let bst_msg = bst_msg.into_inner();
    let swap_uuid = &Uuid::from_str(&bst_msg.swap_id)?;
    let statechain_uuid = &Uuid::from_str(&bst_msg.statechain_id)?;
    let result = sc_entity
        .get_blinded_spend_signature(swap_uuid, statechain_uuid)
        .map(|x| Json(x));
    let _ = sc_entity.update_swap_info();
    return result
}

#[openapi]
/// # Phase 0 of coinswap: Notify conductor of desire to take part in a swap with signature to prove ownership of statecoin.
#[post("/swap/register-utxo", format = "json", data = "<register_utxo_msg>")]
pub fn register_utxo(
    sc_entity: State<SCE>,
    register_utxo_msg: Json<RegisterUtxo>,
) -> Result<Json<()>> {
    sc_entity.check_rate_fast("swap")?;
    match sc_entity.register_utxo(&register_utxo_msg.into_inner()) {
        Ok(res) => {
            let _ = sc_entity.update_swap_info();
            return Ok(Json(res))
        },
        Err(e) => return Err(e),
    }
}

#[openapi]
/// Remove coin from awaiting in swap pool
#[post("/swap/deregister-utxo", format = "json", data = "<statechain_id>")]
pub fn deregister_utxo(
    sc_entity: State<SCE>,
    statechain_id: Json<StatechainID>,
) -> Result<Json<()>> {
    sc_entity.check_rate_fast("swap")?;
    match sc_entity.deregister_utxo(&statechain_id.id) {
        Ok(res) => {
            let _ = sc_entity.update_swap_info();
            return Ok(Json(res))
        },
        Err(e) => return Err(e),
    }
}



#[openapi]
/// # Phase 1 of coinswap: Participants sign SwapToken and provide a statechain address and e_prime for blind spend token.
#[post("/swap/first", format = "json", data = "<swap_msg1>")]
pub fn swap_first_message(sc_entity: State<SCE>, swap_msg1: Json<SwapMsg1>) -> Result<Json<()>> {
    sc_entity.check_rate_fast("swap")?;
    match sc_entity.swap_first_message(&swap_msg1.into_inner()) {
        Ok(res) => {
            let _ = sc_entity.update_swap_info();    
            return Ok(Json(res))
        },
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Phase 2 of coinswap: Participants provide blind spend token and recieve address.
#[post("/swap/second", format = "json", data = "<swap_msg2>")]
pub fn swap_second_message(
    sc_entity: State<SCE>,
    swap_msg2: Json<SwapMsg2>,
) -> Result<Json<(SCEAddress)>> {
    sc_entity.check_rate_fast("swap")?;
    match sc_entity.swap_second_message(&swap_msg2.into_inner()) {
        Ok(res) => {
            let _ = sc_entity.update_swap_info();
            return Ok(Json(res))
        },
        Err(e) => return Err(e),
    }
}

#[openapi]
/// # Get information on current group registrations
#[get("/swap/groupinfo", format = "json")]
pub fn get_group_info(
    sc_entity: State<SCE>,
    ) -> Result<Json<(HashMap<SwapGroup,GroupStatus>)>> {
    sc_entity.check_rate_fast("swap")?;
    sc_entity.update_swap_info()?;
    match sc_entity.get_group_info() {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[allow(dead_code)]
#[cfg(test)]
mod tests {
    const GROUP_TIMEOUT: u64=8;
    use super::*;
    use crate::protocol::util::tests::test_sc_entity;
    use crate::structs::{StateChainAmount, StateChainOwner};
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use bitcoin::Address;
    use curv::{elliptic::curves::traits::ECScalar, FE};
    use mockall::predicate;
    use shared_lib::{
        blinded_token::{BSTRequestorData, BlindedSpendToken},
        state_chain::{State as SCState, StateChain, StateChainSig},
        util::keygen::Message,
    };
    use std::collections::HashSet;
    use std::str::FromStr;
    use std::{thread, time::Duration};
    use std::convert::TryInto;

    #[test]
    fn test_swap_token_sig_verify() {
        let swap_token = SwapToken {
            id: Uuid::from_str("637203c9-37ab-46f9-abda-0678c891b2d3").unwrap(),
            amount: 1,
            time_out: 100,
            statechain_ids: vec![Uuid::from_str("001203c9-93f0-46f9-abda-0678c891b2d3").unwrap()],
        };
        let proof_key_priv = SecretKey::from_slice(&[1; 32]).unwrap(); // Proof key priv part
        let proof_key = PublicKey::from_secret_key(&Secp256k1::new(), &proof_key_priv); // proof key

        assert_eq!(
            swap_token.to_message().unwrap(),
            Message::from_slice(
                hex::decode("6d4574375a0dea62b40f418c0974049f41487fe56f8201c1eca841b80b9e7d1e")
                    .unwrap()
                    .as_slice()
            )
            .unwrap(),
        );
        println!("{:?}", swap_token);
        println!("{:?}", proof_key_priv.to_string());
        println!("{:?}", proof_key.to_string());
        let sig = swap_token.sign(&proof_key_priv).unwrap();
        println!("{:?}", sig);
        assert!(swap_token.verify_sig(&proof_key, sig).is_ok());
        let proof_key_err = PublicKey::from_str("038914b26a8c9821803a34f801e0e651eb53b8b5280d134dba37be0ebcd3e48608").unwrap();
        assert!(swap_token.verify_sig(&proof_key_err, sig).is_err());

        let swap_token = SwapToken {
            id: Uuid::from_str("927271f3-a43a-42e7-89d5-424b0c0b946f").unwrap(),
            amount: 1000,
            time_out: 100,
            statechain_ids: vec![Uuid::from_str("f8a3129c-7aa3-4142-8ff2-491e5e98a47a").unwrap(),
            Uuid::from_str("ac0d59ea-6316-4357-852e-fa63ffa72ccc").unwrap(),
            Uuid::from_str("0143bee3-1273-47b0-bedc-973ef6f477b7").unwrap()
            ],
        };

        println!("{:?}", swap_token);


        let message_expected = Message::from_slice(&hex::decode("932f880741335b0fb6a91fe9c95247e99e682ea748f1f536a4a898bfd13f6e55").unwrap()).unwrap();
        let message = swap_token.to_message().unwrap();
        assert_eq!(message, message_expected);

    }

    //get a scheduler preset with requests
    fn get_scheduler(swap_size_amounts: Vec<(u64, u64)>) -> Scheduler {
        let utxo_timeout: u32 = 6;
        let punishment_timeout: u32 = 6;
        let group_timeout: u32 = 8;
        let daily_epochs: u32 = 1;
        let max_swap_size: u32 = 3;
        let now: NaiveDateTime = Utc::now().naive_utc();
        let t = now + chrono::Duration::seconds(utxo_timeout as i64);
        let t_swap = now + chrono::Duration::seconds(group_timeout as i64);
        let wallet_requirement: String = "0.6.0".to_string();
        let permitted_groups: Vec<u64> = vec![10,100000];

        let statechain_swap_size_map = BisetMap::new();
        let statechain_amount_map = BisetMap::new();
        let mut poll_timeout_map = HashMap::<Uuid, NaiveDateTime>::new();
        let mut swap_timeout_map = HashMap::<Uuid, NaiveDateTime>::new();
        let punishment_map = HashMap::<Uuid, NaiveDateTime>::new();

        for (swap_size, amount) in swap_size_amounts {
            let id = Uuid::new_v4();
            statechain_swap_size_map.insert(id, swap_size);
            statechain_amount_map.insert(id, amount);
            poll_timeout_map.insert(id,t);
            swap_timeout_map.insert(id,t_swap);
        }

        Scheduler {
            utxo_timeout,
            group_timeout,
            daily_epochs,
            max_swap_size,
            wallet_requirement,
            punishment_map,
            punishment_timeout,
            permitted_groups,
            statechain_swap_size_map,
            statechain_amount_map,
            group_info_map: HashMap::<SwapGroup,GroupStatus>::new(),
            swap_id_map: HashMap::<Uuid, Uuid>::new(),
            swap_info_map: HashMap::<Uuid, SwapInfo>::new(),
            poll_timeout_map,
            swap_timeout_map,
            out_addr_map: HashMap::new(),
            bst_e_prime_map: HashMap::new(),
            bst_sig_map: HashMap::new(),
            tb_sig_map: HashMap::new(),
            shutdown_requested: false,
        }
    }

    #[test]
    fn test_scheduler() {
        let mut scheduler = get_scheduler(vec![
            (3, 10),
            (3, 10),
            (3, 10),
            (4, 9),
            (4, 9),
            (4, 9),
            (4, 9),
            (5, 5),
            (5, 5),
            (5, 5),
            (5, 5),
        ]);

        scheduler.update_swap_info().unwrap();
        assert_eq!(scheduler.swap_id_map.len(), 7);
        assert_eq!(scheduler.swap_info_map.len(), 2);

        //Regsiter a new request for the amount 5, but require 6 to be in the swap
        scheduler.register_amount_swap_size(&Uuid::new_v4(), 5, 6).unwrap();
        //Not enough participants to create swap
        scheduler.update_swap_info().unwrap();
        assert_eq!(scheduler.swap_id_map.len(), 7);
        assert_eq!(scheduler.swap_info_map.len(), 2);
        assert_eq!(scheduler.statechain_amount_map.len(),5);

        //Wait for newly registered statechains to time out
        thread::sleep(Duration::from_secs(7));
        scheduler.update_swap_info().unwrap();
        //Unpolled statechain ids should have been removed from memory
        assert_eq!(scheduler.statechain_amount_map.len(),0);

        //Replace the timed out requests
        scheduler.register_amount_swap_size(&Uuid::new_v4(), 5, 5).unwrap();
        scheduler.register_amount_swap_size(&Uuid::new_v4(), 5, 5).unwrap();
        scheduler.register_amount_swap_size(&Uuid::new_v4(), 5, 5).unwrap();
        scheduler.register_amount_swap_size(&Uuid::new_v4(), 5, 5).unwrap();
        scheduler.register_amount_swap_size(&Uuid::new_v4(), 5, 6).unwrap();
        scheduler.update_swap_info().unwrap();
        assert_eq!(scheduler.statechain_amount_map.len(),5);

        //Regsiter a new request for the amount 5, but require 6 to be in the swap
        let sc_id = Uuid::new_v4();
        scheduler.register_amount_swap_size(&sc_id, 5, 6).unwrap();
        //Now there are enough participants: new swap created
        scheduler.update_swap_info().unwrap();
        assert_eq!(scheduler.swap_id_map.len(), 13);
        assert_eq!(scheduler.swap_info_map.len(), 3);

        //Look up the swap for sc_id
        let swap_id = scheduler.get_swap_id(&sc_id).expect("expected swap id");
        let swap_info = scheduler
            .get_swap_info(&swap_id)
            .expect("expected swap info");
        assert_eq!(swap_info.status, SwapStatus::Phase1, "expected phase1");
        assert_eq!(swap_info.swap_token.amount, 5, "expected amount 5");
        assert_eq!(
            swap_info.swap_token.time_out, GROUP_TIMEOUT,
            "expected default timeout"
        );
        let mut id_set = HashSet::new();
        for id in swap_info.swap_token.statechain_ids {
            id_set.insert(id);
        }
        assert_eq!(
            id_set.len(),
            6,
            "expected 6 unique state chain ids in the swap token"
        );

        //Wait for swaps to time out
        thread::sleep(Duration::from_secs(9));

        scheduler.update_swap_info().unwrap();

        let swap_info = scheduler
            .get_swap_info(&swap_id);
            
        assert!(swap_info.is_none(), "expected swap_info to be None ater swap timeout")

    }

    #[test]
    fn test_poll_utxo() {
        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        let mut sc_entity = test_sc_entity(db, None, None, None, None);
        sc_entity.scheduler = Some(Arc::new(Mutex::new(get_scheduler(vec![(3, 10), (3, 10), (3, 10)]))));

        let utxo_not_in_swap = Uuid::from_str("00000000-93f0-46f9-abda-0678c891b2d4").unwrap();
        let utxo_waiting_for_swap = Uuid::from_str("00000000-93f0-46f9-abda-0678c891b2d3").unwrap();

        let mut guard = sc_entity.scheduler.as_ref().expect("scheduler is None").lock().unwrap();
        guard.reset_poll_utxo_timeout(&utxo_waiting_for_swap, true);
        guard.update_swap_info().unwrap();
        let utxo_invited_to_swap = guard.swap_id_map.iter().next().unwrap().0.to_owned();
        drop(guard);
        //let uxto_invited_to_swap = Uuid::from_str("11111111-93f0-46f9-abda-0678c891b2d3").unwrap();
        let err_expected = SEError::SwapError(format!("statechain timed out or has not been requested for swap: {}", utxo_not_in_swap));
        match sc_entity.poll_utxo(&utxo_not_in_swap) {
            Ok(v) => assert!(false, "Expected error: {} - got Ok({:?})", err_expected, v),
            Err(e) => {
                assert_eq!(e.to_string(), err_expected.to_string());
            }
        }
        match sc_entity.poll_utxo(&utxo_waiting_for_swap) {
            Ok(no_swap_id) => assert!(no_swap_id.id.is_none()),
            Err(e) => assert!(false, "Expected Ok(()), got {}", e),
        }
        match sc_entity.poll_utxo(&utxo_invited_to_swap) {
            Ok(swap_id) => assert!(swap_id.id.is_some()),
            Err(_) => assert!(false, "Expected Ok((swap_id))."),
        }
    }

    #[test]
    fn test_get_swap_info() {
        let swap_id_doesnt_exist = Uuid::from_str("deadb33f-93f0-46f9-abda-0678c891b2d3").unwrap();

        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        let mut sc_entity = test_sc_entity(db, None, None, None, None);
        sc_entity.scheduler = Some(Arc::new(Mutex::new(get_scheduler(vec![(3, 10), (3, 10), (3, 10)]))));
        let mut guard = sc_entity.scheduler.as_ref().expect("scheduler is None").lock().unwrap();
        guard.update_swap_info().unwrap();
        //let swap_id_valid = Uuid::from_str("11111111-93f0-46f9-abda-0678c891b2d3").unwrap();
        let swap_id_valid = guard.swap_id_map.iter().next().unwrap().1.to_owned();
        drop(guard);

        match sc_entity.poll_swap(&swap_id_doesnt_exist) {
            Ok(None) => assert!(true),
            _ => assert!(false, "Expected Ok(None)"),
        }

        assert_eq!(
            sc_entity.poll_swap(&swap_id_valid).unwrap().unwrap(),
            SwapStatus::Phase1
        );

        match sc_entity.get_swap_info(&swap_id_valid) {
            Ok(Some(swap_info)) => {
                assert_eq!(swap_info.status, SwapStatus::Phase1);
                assert_eq!(swap_info.swap_token.id, swap_id_valid);
                assert!(swap_info.swap_token.time_out == GROUP_TIMEOUT);
                assert!(swap_info.swap_token.statechain_ids.len() == 3);
            }
            _ => assert!(false, "Expected Ok(Some(swap_info))."),
        }
    }

    #[test]
    fn test_register_utxo() {
        // Check signature verified correctly
        let statechain_id = Uuid::from_str("00000000-93f0-46f9-abda-0678c891b2d3").unwrap();
        let statechain_id_2 = Uuid::from_str("20000000-93f0-46f9-abda-0678c891b2d3").unwrap();
        let proof_key_priv = SecretKey::from_slice(&[1; 32]).unwrap(); // Proof key priv part
        let proof_key = PublicKey::from_secret_key(&Secp256k1::new(), &proof_key_priv); // proof key
        let invalid_proof_key_priv = SecretKey::from_slice(&[2; 32]).unwrap();

        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));

        let mut chain = Vec::<SCState>::new();

        chain.push(SCState {
            data: proof_key.to_string(),
            next_state: None,
        });

        let statechain: StateChain = chain.try_into().expect("expected Vec<State> to convert to StateChain");
        let statechain_2 = statechain.clone();

        db.expect_get_statechain_owner().returning(move |_| {
            Ok(StateChainOwner {
                locked_until: chrono::prelude::Utc::now().naive_utc(),
                owner_id: Uuid::new_v4(),
                chain: statechain.clone(),
            })
        });

        let statechain_amount = StateChainAmount {
            chain: statechain_2.clone(),
            amount: 100000,
        };

        let statechain_amount_2 = StateChainAmount {
            chain: statechain_2.clone(),
            amount: 123456,
        };

        db.expect_is_confirmed()
            .with(predicate::eq(statechain_id))
            .returning(|_| Ok(true));
        db.expect_is_confirmed()
            .with(predicate::eq(statechain_id_2))
            .returning(|_| Ok(true));
        db.expect_get_statechain_amount()
            .with(predicate::eq(statechain_id))
            .returning(move |_| Ok(statechain_amount.clone()));

        db.expect_get_statechain_amount()
            .with(predicate::eq(statechain_id_2))
            .returning(move |_| Ok(statechain_amount_2.clone()));            

        let mut sc_entity = test_sc_entity(db, None, None, None, None);
        sc_entity.scheduler = Some(Arc::new(Mutex::new(get_scheduler(vec![(3, 10), (3, 10), (3, 10)]))));

        // Try invalid signature for proof key
        let invalid_signature = StateChainSig::new(
            &invalid_proof_key_priv,
            &"SWAP".to_string(),
            &proof_key.to_string(),
        )
        .unwrap();
        match sc_entity.register_utxo(&RegisterUtxo {
            statechain_id,
            signature: invalid_signature,
            swap_size: 10,
            wallet_version: "0.6.0".to_string()
        }) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(
                e.to_string().contains("signature failed verification"),
                "{}", e.to_string()
            ),
        }

        // Try not permitted amount
        let signature =
            StateChainSig::new(&proof_key_priv, &"SWAP".to_string(), &proof_key.to_string())
                .unwrap();
        match sc_entity.register_utxo(&RegisterUtxo {
                statechain_id: statechain_id_2,
                signature: signature.clone(),
                swap_size: 10,
                wallet_version: "0.6.0".to_string()
            }) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(
                e.to_string().contains("Invalid coin amount"),
                "{}", e.to_string()
            ),
        }
            
        // Valid signature for proof key
        assert!(sc_entity
            .register_utxo(&RegisterUtxo {
                statechain_id,
                signature: signature.clone(),
                swap_size: 10,
                wallet_version: "0.6.0".to_string()
            })
            .is_ok());

        let swap_group = SwapGroup { amount: 100000, size: 10 };
        let groupinfo = sc_entity.get_group_info().unwrap();

        assert_eq!(groupinfo.get(&swap_group).unwrap().number,1);
    }

    #[test]
    fn test_swap_first_message() {
        let invalid_swap_id = Uuid::from_str("deadb33f-37ab-46f9-abda-0678c891b2d3").unwrap();
        let proof_key_priv_invalid = SecretKey::from_slice(&[99; 32]).unwrap(); // Proof key priv part
        let mut proof_key_vec = Vec::<PublicKey>::new();
        let mut proof_key_priv_vec = Vec::<SecretKey>::new();
        let mut sce_addresses = Vec::<SCEAddress>::new();

        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));

        let mut scheduler = get_scheduler(vec![(3, 10), (3, 10), (3, 10)]);
        scheduler.update_swap_info().unwrap();
        //let swap_id_valid = Uuid::from_str("11111111-93f0-46f9-abda-0678c891b2d3").unwrap();
        let swap_id = scheduler.swap_id_map.iter().next().unwrap().1.to_owned();
        // Sign swap token with no statechain_ids
        let swap_token = scheduler.get_swap_info(&swap_id).unwrap().swap_token;
        let statechain_ids = swap_token.statechain_ids.clone();

        for i in 0..3 {
            proof_key_priv_vec.push(SecretKey::from_slice(&[i + 1; 32]).unwrap());
            proof_key_vec.push(PublicKey::from_secret_key(
                &Secp256k1::new(),
                &proof_key_priv_vec.last().unwrap(),
            ));
            sce_addresses.push(SCEAddress {
                tx_backup_addr: None,
                proof_key: proof_key_vec.last().unwrap().clone(),
            });

            //Mock database responses
            let mut chain = Vec::<SCState>::new();
            chain.push(SCState {
                data: proof_key_vec.last().unwrap().to_string(),
                next_state: None,
            });
            let statechain: StateChain = chain.try_into().expect("expected Vec<State> to convert to StateChain");
            let statechain2 = statechain.clone();

            db.expect_get_statechain_owner()
                .times(1)
                .returning(move |_| {
                    Ok(StateChainOwner {
                        locked_until: chrono::prelude::Utc::now().naive_utc(),
                        owner_id: Uuid::new_v4(),
                        chain: statechain.clone(),
                    })
                });

            db.expect_get_statechain()
                .with(eq(statechain_ids[i as usize]))
                .returning(move |_| Ok(statechain2.clone()));
        }

        let mut sc_entity = test_sc_entity(db, None, None, None, None);
        sc_entity.scheduler = Some(Arc::new(Mutex::new(scheduler)));

        let mut swap_token_no_sc = swap_token.clone();
        swap_token_no_sc.statechain_ids = Vec::new();

        let swap_token_sig = swap_token_no_sc.sign(&proof_key_priv_vec[0]).unwrap().to_string();
        let statechain_id = statechain_ids[0];
        let transfer_batch_sig = StateChainSig::new_transfer_batch_sig(
            &proof_key_priv_vec[0],
            &swap_id,
            &statechain_id,
        )
        .unwrap();

        let mut swap_msg_1 = SwapMsg1 {
            statechain_id,
            swap_id,
            swap_token_sig,
            transfer_batch_sig,
            address: sce_addresses[0].clone(),
            bst_e_prime: FE::zero(),
        };

        match sc_entity.swap_first_message(&swap_msg_1) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(
                e.to_string()
                    .contains("Swap Error: swap token signature does not sign for token"),
                "{}", e.to_string()
            ),
        }

        swap_msg_1.swap_token_sig = swap_token.sign(&proof_key_priv_invalid).unwrap().to_string();

        match sc_entity.swap_first_message(&swap_msg_1) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(
                e.to_string()
                    .contains("Swap Error: swap token signature does not sign for token"),
                "{}", e.to_string()
            ),
        }

        // Sign swap token with invalid swap_id
        swap_msg_1.swap_id = invalid_swap_id;
        swap_msg_1.swap_token_sig = swap_token.sign(&proof_key_priv_vec[0]).unwrap().to_string();

        match sc_entity.swap_first_message(&swap_msg_1) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(
                e.to_string().contains("Swap Error: no swap with id"),
                "{}", e.to_string()
            ),
        }

        //Should be in phase1 now as not enough valid first messages have been sent
        assert_eq!(
            sc_entity.poll_swap(&swap_id).unwrap().unwrap(),
            SwapStatus::Phase1
        );

        let mut swap_msgs = vec![];
        //Send valid first messages for all participants
        for i in 0..proof_key_vec.len() {
            let transfer_batch_sig = StateChainSig::new_transfer_batch_sig(
                &proof_key_priv_vec[i],
                &swap_id,
                &statechain_ids[i],
            )
            .unwrap();
            transfer_batch_sig
                .verify(&proof_key_vec[i].to_string())
                .unwrap();
            let swap_msg_1 = SwapMsg1 {
                statechain_id: statechain_ids[i],
                swap_id,
                swap_token_sig: swap_token.sign(&proof_key_priv_vec[i]).unwrap().to_string(),
                transfer_batch_sig,
                address: sce_addresses[i].clone(),
                bst_e_prime: FE::new_random(),
            };
            swap_msgs.push(swap_msg_1.clone());
            // Valid inputs
            match sc_entity.swap_first_message(&swap_msg_1) {
                Ok(_) => assert!(true),
                Err(e) => assert!(false, "{}", e.to_string()),
            };
        }


        //Test repeated calls to swap_first_message
        //Add mock expectations
        //Mock database responses
        let mut chain = Vec::<SCState>::new();
            chain.push(SCState {
            data: proof_key_vec[0].to_string(),
            next_state: None,
        });
        let statechain: StateChain = chain.try_into().expect("expected Vec<State> to convert to StateChain");
        let statechain2 = statechain.clone();

        sc_entity.database.expect_get_statechain_owner()
        .times(3)
        .returning(move |_| {
          Ok(StateChainOwner {
              locked_until: chrono::prelude::Utc::now().naive_utc(),
              owner_id: Uuid::new_v4(),
              chain: statechain.clone(),
          })
        });

        let swap_msg_1 = swap_msgs[0].clone();

        sc_entity.database.expect_get_statechain()
            .with(eq(statechain_ids[0]))
            .returning(move |_| Ok(statechain2.clone()));

        
        // Expect Ok when repeating swap_first_message with the same input
        match sc_entity.swap_first_message(&swap_msg_1) {
            Ok(_) => assert!(true),
            Err(e) => assert!(false, "{}", e.to_string()),
        };

        // Repeat attempts return the appropriate error
        let expected_error_base = format!("Swap Error: blind spend token e_prime already registered for statechain id {}", 
            &swap_msg_1.statechain_id);


        // Expect Error when repeating swap_first_message with a different input
        let mut swap_msg_1_diff_bst = swap_msg_1.clone();
        while(swap_msg_1.bst_e_prime == swap_msg_1_diff_bst.bst_e_prime){
                swap_msg_1_diff_bst.bst_e_prime = FE::new_random();
            }

        let mut expected_error = format!("{}, but does not match the requested bst_e_prime", expected_error_base);
        match sc_entity.swap_first_message(&swap_msg_1_diff_bst) {
                Ok(_) => assert!(false, "expected error: {}", expected_error),
                Err(e) => {
                    assert_eq!(expected_error, e.to_string())
                },
        };

            let mut swap_msg_1_diff_address = swap_msg_1.clone();
            let priv_key = SecretKey::from_slice(&[5 as u8; 32]).unwrap();
            let pub_key = PublicKey::from_secret_key(
                &Secp256k1::new(),
                &priv_key,
            );
            swap_msg_1_diff_address.address = SCEAddress {
                tx_backup_addr: None,
                proof_key: pub_key,
            };
            assert!(swap_msg_1_diff_address.address != swap_msg_1.address);

            let mut chain_diff = Vec::<SCState>::new();
            chain_diff.push(SCState {
                data: pub_key.to_string(),
                next_state: None,
             });
            let statechain_diff: StateChain = chain_diff.try_into().expect("expected Vec<State> to convert to StateChain");
            let statechain_diff2 = statechain_diff.clone();

            sc_entity.database.expect_get_statechain_owner()
            .times(1)
            .returning(move |_| {
              Ok(StateChainOwner {
                  locked_until: chrono::prelude::Utc::now().naive_utc(),
                  owner_id: Uuid::new_v4(),
                  chain: statechain_diff.clone(),
              })
            });

            sc_entity.database.expect_get_statechain()
            .with(eq(statechain_ids[0]))
            .returning(move |_| Ok(statechain_diff2.clone()));

            expected_error = format!("{}, but address not found", expected_error_base);
            match sc_entity.swap_first_message(&swap_msg_1_diff_address) {
                Ok(_) => assert!(false, "exected error: {}", expected_error),
                Err(e) => {
                    assert_eq!(expected_error, e.to_string())
                },
            };

            let mut swap_msg_1_diff_sig = swap_msg_1.clone();
            swap_msg_1_diff_sig.transfer_batch_sig = StateChainSig::new_transfer_batch_sig(
                &priv_key,
                &swap_id,
                &statechain_id,
            ).unwrap();
            expected_error = format!("{}, but transfer batch signature not found", expected_error_base);
            match sc_entity.swap_first_message(&swap_msg_1_diff_sig) {
                Ok(_) => assert!(false, "exected error: {}", expected_error),
                Err(e) => {
                    assert_eq!(expected_error, e.to_string())
                },
            };
        



        //Scheduler updates swap info to move swap to phase 2
        let mut guard = sc_entity.scheduler.as_ref().expect("scheduler is None").lock().unwrap();
        guard.update_swap_info().unwrap();
        drop(guard);
        assert_eq!(
            sc_entity.poll_swap(&swap_id).unwrap().unwrap(),
            SwapStatus::Phase2
        );

        //There should be a blinded spend signature for each of the sce addresses
        let guard = sc_entity.scheduler.as_ref().expect("scheduler is None").lock().unwrap();
        assert_eq!(
            guard.bst_sig_map.get(&swap_id).unwrap().len(),
            guard
                .swap_info_map
                .get(&swap_id)
                .unwrap()
                .swap_token
                .statechain_ids
                .len()
        );
        drop(guard);
    }

    #[test]
    fn test_get_blinded_spend_token() {
        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        let mut sc_entity = test_sc_entity(db, None, None, None, None);
        sc_entity.scheduler = Some(Arc::new(Mutex::new(get_scheduler(vec![(3, 10), (3, 10), (3, 10)]))));
        let mut guard = sc_entity.scheduler.as_ref().expect("scheduler is None").lock().unwrap();
        guard.update_swap_info().unwrap();

        let swap_id = guard.swap_id_map.iter().next().unwrap().1.to_owned();
        let mut swap_info = guard.get_swap_info(&swap_id).unwrap();
        // Sign swap token with no statechain_ids
        swap_info.status = SwapStatus::Phase2;
        guard.swap_info_map.insert(swap_id, swap_info.clone());
        let swap_token = swap_info.swap_token;
        let statechain_id = swap_token.statechain_ids[0];

        // Dummy signature for each statechain_id
        let mut id_bst_map = HashMap::<Uuid, BlindedSpendSignature>::new();
        for id in swap_token.statechain_ids {
            id_bst_map.insert(id, BlindedSpendSignature::default());
        }
        guard.bst_sig_map.insert(swap_id.clone(), id_bst_map);
        drop(guard);

        sc_entity
            .get_blinded_spend_signature(&swap_id, &statechain_id)
            .unwrap();

        assert!(sc_entity
            .get_blinded_spend_signature(&swap_id, &statechain_id)
            .is_ok());
        let expected_err =
            SEError::SwapError("unknown swap id when getting swap status".to_string());
        match sc_entity.get_blinded_spend_signature(&Uuid::default(), &statechain_id) {
            Err(e) => assert_eq!(
                e.to_string(),
                expected_err.to_string(),
                "expected Err({}), got Err({})",
                expected_err,
                e
            ),
            Ok(v) => assert!(false, "expected Err({}), got Ok({:?})", expected_err, v),
        };

        let expected_err = SEError::SwapError("unknown statechain id".to_string());
        match sc_entity.get_blinded_spend_signature(&swap_id, &Uuid::default()) {
            Err(e) => assert_eq!(
                e.to_string(),
                expected_err.to_string(),
                "expected Err({}), got Err({})",
                expected_err,
                e
            ),
            Ok(v) => assert!(false, "expected Err({}), got Ok({:?})", expected_err, v),
        };
    }

    // from a BSTSenderData instance, generate a BSTRequestorData and build a BlindedSpendToken
    fn make_valid_blinded_spend_token(
        bst_sender: &BSTSenderData,
        msg: &String,
    ) -> (BSTRequestorData, BlindedSpendToken) {
        let bst_requestor = BSTRequestorData::setup(bst_sender.get_r_prime(), msg).unwrap();
        let blind_sig = bst_sender.gen_blind_signature(bst_requestor.get_e_prime());
        let unblind_sig = bst_requestor.unblind_signature(blind_sig);
        let blind_spend_token = bst_requestor.make_blind_spend_token(unblind_sig);
        (bst_requestor, blind_spend_token)
    }

    #[test]
    fn test_swap_second_message() {
        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        let mut sc_entity = test_sc_entity(db, None, None, None, None);
        sc_entity.scheduler = Some(Arc::new(Mutex::new(get_scheduler(vec![(3, 10), (3, 10), (3, 10)]))));
        let mut guard = sc_entity.scheduler.as_ref().expect("scheduler is None").lock().unwrap();
        guard.update_swap_info().unwrap();

        let swap_id = guard.swap_id_map.iter().next().unwrap().1.to_owned();
        drop(guard);

        let mut swap_msg_2 = SwapMsg2 {
            swap_id,
            blinded_spend_token: BlindedSpendToken::new_random(),
        };

        // Blinded token signs for invalid message
        match sc_entity.swap_second_message(&swap_msg_2) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(
                e.to_string().contains("Failed to deserialize message."),
                "{}", e.to_string()
            ),
        }
        // Blind token invalid message swapid
        swap_msg_2.blinded_spend_token.set_msg(
            serde_json::to_string(&BlindedSpentTokenMessage::new(Uuid::new_v4())).unwrap(),
        );
        match sc_entity.swap_second_message(&swap_msg_2) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("swap_ids do not match")),
        }
        // Blinded token verification fails
        let msg = serde_json::to_string(&BlindedSpentTokenMessage::new(swap_id)).unwrap();
        swap_msg_2.blinded_spend_token.set_msg(msg.clone());
        match sc_entity.swap_second_message(&swap_msg_2) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(
                e.to_string()
                    .contains("Blind Spent Token signature verification failed."),
                "{}", e.to_string()
            ),
        }
        // Connection made through clear net
        // match sc_entity.swap_second_message(&SwapMsg2 {
        //     swap_id,
        //     blinded_spend_token: blinded_spend_token.clone()
        // }){
        //     Ok(_) => assert!(false, "Expected failure."),
        //     Err(e) => assert!(e.to_string().contains("Swap Error: Connection made via clearnet!")),
        // }

        // Create a valid BlindSpentToken
        let mut guard = sc_entity.scheduler.as_ref().expect("scheduler is None").lock().unwrap();
        let mut swap_info = guard.get_swap_info(&swap_id).unwrap();
        swap_info.status = SwapStatus::Phase2;
        guard.swap_info_map.insert(swap_id, swap_info.clone());
        let (_, blind_spend_token) =
            make_valid_blinded_spend_token(&swap_info.bst_sender_data, &msg);

        // Add swap to scheduler
        guard
            .out_addr_map
            .insert(swap_id, BisetMap::<SCEAddress, Option<Uuid>>::new());
        drop(guard);

        // No SCEAddresses added at the moment so we can test for all claimed here since there are no unassigned SCEAddresses.
        swap_msg_2.blinded_spend_token = blind_spend_token;
        match sc_entity.swap_second_message(&swap_msg_2) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e
                .to_string()
                .contains("All SCEAddresses have been claimed.")),
        }

        // Add SCEAddress and check it gets claimed by this blinded_spend_token's nonce
        let mut guard = sc_entity.scheduler.as_ref().expect("scheduler is None").lock().unwrap();
        let sce_addr_biset_map = guard.out_addr_map.get_mut(&swap_id).unwrap();
        let sce_addr = SCEAddress {
            tx_backup_addr: Some(
                Address::from_str("tb1q7gjz7dnzpz06svq7v3z2wpt33erx086x66jgtn").unwrap(),
            ),
            proof_key: PublicKey::from_str(
                "03b97f69f86f42c65787bfcaebc9c717993fec405973f6368b3d158cb79aa27791",
            )
            .unwrap(),
        };
        sce_addr_biset_map.insert(sce_addr.clone(), None);
        drop(guard);

        let _ = sc_entity.swap_second_message(&swap_msg_2);

        let mut guard = sc_entity.scheduler.as_ref().expect("scheduler is None").lock().unwrap();
        let sce_addr_biset_map = guard.out_addr_map.get_mut(&swap_id).unwrap();
        assert_eq!(sce_addr_biset_map.len(), 1);
        let nonce = Uuid::from_str(&serde_json::from_str::<BlindedSpentTokenMessage>(
            &swap_msg_2.blinded_spend_token.get_msg(),
        )
        .unwrap()
        .nonce).unwrap();

        assert_eq!(
            sce_addr_biset_map.get(&sce_addr).get(0).unwrap().unwrap(),
            nonce
        );
        drop(guard);

        // Call swap_message_2 again and ensure SCEAddress is already assigned and returned sce_addr
        let assigned_sce_addr = sc_entity.swap_second_message(&swap_msg_2).unwrap();
        assert_eq!(assigned_sce_addr, sce_addr);

        // Call with a different valid BlindedSpendToken
        let msg = serde_json::to_string(&BlindedSpentTokenMessage::new(swap_id)).unwrap();
        let (_, blind_spend_token) =
            make_valid_blinded_spend_token(&swap_info.bst_sender_data, &msg);
        swap_msg_2.blinded_spend_token = blind_spend_token;
        match sc_entity.swap_second_message(&swap_msg_2) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(
                e.to_string()
                    .contains("All SCEAddresses have been claimed."),
                "{}", e.to_string()
            ),
        }

        // update swaps and check phase is updated
        let mut guard = sc_entity.scheduler.as_ref().expect("scheduler is None").lock().unwrap();
        let _ = guard.update_swap_info();
        let swap_info = guard.get_swap_info(&swap_id).unwrap();
        assert_eq!(swap_info.status, SwapStatus::Phase3);
    }

    #[test]
    fn test_get_address_from_blinded_spend_token() {
        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        let mut sc_entity = test_sc_entity(db, None, None, None, None);
        sc_entity.scheduler = Some(Arc::new(Mutex::new(get_scheduler(vec![(3, 10), (3, 10), (3, 10)]))));
        let mut guard = sc_entity.scheduler.as_ref().expect("scheduler is None").lock().unwrap();
        guard.update_swap_info().unwrap();

        let swap_id = guard.swap_id_map.iter().next().unwrap().1.to_owned();
        let msg = serde_json::to_string(&BlindedSpentTokenMessage::new(swap_id)).unwrap();
        let swap_info = guard.get_swap_info(&swap_id).unwrap();
        // make a valid blind spend token for this swap_id (initially an invalid swap_id)
        let (_, blinded_spend_token) =
            make_valid_blinded_spend_token(&swap_info.bst_sender_data, &msg);
        // Add swap to scheduler
        guard
            .out_addr_map
            .insert(swap_id, BisetMap::<SCEAddress, Option<Uuid>>::new());
        drop(guard);

        // Blind token invalid message swapid
        let (_, invalid_swap_id_bst) = make_valid_blinded_spend_token(
            &swap_info.bst_sender_data,
            &serde_json::to_string(&BlindedSpentTokenMessage::new(Uuid::new_v4())).unwrap(),
        );
        match sc_entity.get_address_from_blinded_spend_token(&invalid_swap_id_bst) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e.to_string().contains("No swap with id")),
        }

        // Valid blind token but swap_message_2 not yet called
        match sc_entity.get_address_from_blinded_spend_token(&blinded_spend_token) {
            Ok(_) => assert!(false, "Expected failure."),
            Err(e) => assert!(e
                .to_string()
                .contains("No SCEAddress claimed for this Blinded Spent Token.")),
        }

        // Add SCEAddress and check it gets claimed by this blinded_spend_token's nonce
        let mut guard = sc_entity.scheduler.as_ref().expect("scheduler is None").lock().unwrap();
        let sce_addr_biset_map = guard.out_addr_map.get_mut(&swap_id).unwrap();
        let sce_addr = SCEAddress {
            tx_backup_addr: Some(
                Address::from_str("tb1q7gjz7dnzpz06svq7v3z2wpt33erx086x66jgtn").unwrap(),
            ),
            proof_key: PublicKey::from_str(
                "03b97f69f86f42c65787bfcaebc9c717993fec405973f6368b3d158cb79aa27791",
            )
            .unwrap(),
        };
        sce_addr_biset_map.insert(
            sce_addr.clone(),
            Some(
                Uuid::from_str(&serde_json::from_str::<BlindedSpentTokenMessage>(&blinded_spend_token.get_msg())
                    .unwrap()
                    .nonce).unwrap(),
            ),
        );
        drop(guard);

        // Valid blind token but swap_message_2 not yet called
        let assigned_sce_addr = sc_entity
            .get_address_from_blinded_spend_token(&blinded_spend_token)
            .unwrap();
        assert_eq!(assigned_sce_addr, sce_addr);
    }

    // Test examples flow of Conductor with Client. Uncomment #[test] below to view test.
    // #[test]
    fn conductor_mock() {
        let statechain_id = Uuid::from_str("001203c9-93f0-46f9-abda-0678c891b2d3").unwrap();
        let swap_id = Uuid::from_str("637203c9-37ab-46f9-abda-0678c891b2d3").unwrap();
        let conductor = create_mock_conductor(statechain_id, swap_id);

        // Client Registers utxo with Condutor
        // First sign StateChain to prove ownership of proof key
        let proof_key_priv = SecretKey::from_slice(&[1; 32]).unwrap(); // Proof key priv part
        let proof_key = PublicKey::from_secret_key(&Secp256k1::new(), &proof_key_priv); // proof key
        let signature =
            StateChainSig::new(&proof_key_priv, &"SWAP".to_string(), &proof_key.to_string())
                .unwrap();
        let swap_size: u64 = 10;
        let wallet_version: String = "0.6.0".to_string();
        let _ = conductor.register_utxo(&RegisterUtxo {
            statechain_id,
            signature,
            swap_size,
            wallet_version,
        });

        // Poll status of UTXO until a swap_id is returned signaling that utxo is involved in a swap.
        let swap_id: Uuid;
        println!("\nBegin polling of UTXO:");
        loop {
            println!("\nSleeping for 3 seconds..");
            thread::sleep(Duration::from_secs(3));
            let poll_utxo_res = conductor.poll_utxo(&statechain_id);
            println!("poll_utxo result: {:?}", poll_utxo_res);
            if let Some(v) = poll_utxo_res.unwrap().id {
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

        let blinded_spend_token = BlindedSpendToken::default();

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
                    let transfer_batch_sig = StateChainSig::new_transfer_batch_sig(
                        &proof_key_priv,
                        &swap_token.id,
                        &statechain_id,
                    )
                    .unwrap();
                    println!("Swap token signature: {:?}", signature);
                    // Generate an SCE-address
                    let sce_address = SCEAddress {
                        tx_backup_addr: Some(
                            Address::from_str("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
                                .unwrap(),
                        ),
                        proof_key,
                    };
                    println!("SCE-Address: {:?}", sce_address);
                    println!("Sending swap token signature and SCE address.");
                    // Send to Conductor
                    let first_msg_resp = conductor.swap_first_message(&SwapMsg1 {
                        statechain_id,
                        swap_id: swap_token.id.clone(),
                        swap_token_sig: signature.to_string(),
                        transfer_batch_sig,
                        address: sce_address,
                        bst_e_prime: FE::new_random(),
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
                _ => {}
            }
        }
        println!("\nPolling of Swap loop ended. Client now has SCE-Address to transfer to. This is the end of our Client's interaction with Conductor.");
    }

    fn create_mock_conductor(statechain_id: Uuid, swap_id: Uuid) -> MockConductor {
        //Create a new mock conductor
        let mut conductor = MockConductor::new();
        // Set the expectations

        conductor.expect_register_utxo().returning(|_| Ok(())); // Register UTXO with Conductor
        conductor
            .expect_poll_utxo() // utxo not yet involved
            .with(predicate::eq(statechain_id))
            .times(2)
            .returning(|_| Ok(SwapID{id:None}));
        conductor
            .expect_poll_utxo() // utxo involved in swap
            .with(predicate::eq(statechain_id))
            .returning(move |_| Ok(SwapID{ id: Some(swap_id)}));
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
                        time_out: GROUP_TIMEOUT,
                        statechain_ids: vec![statechain_id, statechain_id],
                    },
                    bst_sender_data: BSTSenderData::setup(),
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
                        time_out: GROUP_TIMEOUT,
                        statechain_ids: vec![statechain_id, statechain_id],
                    },
                    bst_sender_data: BSTSenderData::setup(),
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
                        time_out: GROUP_TIMEOUT,
                        statechain_ids: vec![statechain_id, statechain_id],
                    },
                    bst_sender_data: BSTSenderData::setup(),
                }))
            });
        conductor.expect_swap_second_message().returning(|_| {
            Ok(SCEAddress {
                // Second message
                tx_backup_addr: Some(
                    Address::from_str("bc13rgtzzwf6e0sr5mdq3lydnw9re5r7xfkvy5l649").unwrap(),
                ),
                proof_key: PublicKey::from_str(
                    "65aab40995d3ed5d03a0567b04819ff12641b84c17f5e9d5dd075571e183469c8f",
                )
                .unwrap(),
            })
        });
        conductor
    }

    #[test]
    fn test_get_swaps_ongoing() {
        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        let mut sc_entity = test_sc_entity(db, None, None, None, None);
        sc_entity.scheduler = Some(Arc::new(Mutex::new(get_scheduler(vec![(3, 10), (3, 10), (3, 10)]))));
        let mut guard = sc_entity.scheduler.as_ref().expect("scheduler is None").lock().unwrap();
        
        assert!(guard.swaps_ongoing() == false);
        assert!(guard.shutdown_requested == false);
        assert!(guard.shutdown_ready() == false);
        
        guard.update_swap_info().unwrap();

        assert!(guard.swaps_ongoing() == true);
        assert!(guard.shutdown_requested == false);
        assert!(guard.shutdown_ready() == false);

        guard.request_shutdown();

        assert!(guard.swaps_ongoing() == true);
        assert!(guard.shutdown_requested == true);
        assert!(guard.shutdown_ready() == false);

        for val in guard.swap_info_map.values_mut(){
            val.status = SwapStatus::End;
        }

        assert!(guard.swaps_ongoing() == false);
        assert!(guard.shutdown_requested == true);
        assert!(guard.shutdown_ready() == true);

        guard.shutdown_requested = false;
        assert!(guard.swaps_ongoing() == false);
        assert!(guard.shutdown_ready() == false);
    }
}
