//! Conductor
//!
//! Conductor swap protocol trait and implementation. Full protocol descritpion can be found in Conductor Trait.

use super::super::Result;

extern crate shared_lib;
use shared_lib::{structs::*, util::keygen::Message};

use bitcoin::{
    hashes::{sha256d, Hash},
    secp256k1::{PublicKey, Secp256k1, SecretKey, Signature},
};
use rocket::State;
use rocket_contrib::json::Json;
use uuid::Uuid;
use crate::server::StateChainEntity;

use mockall::predicate::*;
use mockall::*;

use std::str::FromStr;

/// Conductor protocol trait. Comments explain client and server side of swap protocol.
#[automock]
pub trait Conductor {
    /// API: Poll Conductor to check for status of registered utxo. Return Ok if still waiting
    /// or swap_id if swap round has begun.
    fn poll_utxo(&self, state_chain_id: Uuid) -> Result<Option<Uuid>>;

    /// API: Poll Conductor to check for status of swap.
    fn poll_swap(&self, swap_id: Uuid) -> Result<SwapInfo>;

    /// API: Phase 0:
    ///     - Alert Conductor of desire to take part in a swap. Provide StateChainSig to prove
    ///         ownership of StateChain
    fn register_utxo(&self, register_utxo_msg: RegisterUtxo) -> Result<()>;

    // Phase 1: Conductor waits until there is a large enough pool of registered UTXOs of the same size, when
    // such a pool is found Conductor generates a SwapToken and marks each UTXO as "in phase 1 of swap with id: x".
    // When a participant calls poll_utxo they see that their UTXO is involved in a swap. When they call
    // poll_swap they receive the SwapStatus and SwapToken for the swap. They now move on to phase 1.

    /// API: Phase 1:
    ///    - Participants signal agreement to Swap parameters by signing the SwapToken and
    ///         providing a fresh SCE_Address
    fn swap_first_message(&self, swap_msg1: SwapMsg1) -> Result<()>;

    // Phase 2: Iff all participants have successfuly carried out Phase 1 then Conductor generates a blinded token
    // for each participant and marks each UTXO as "in phase 1 of swap with id: x". Upon polling the
    // participants receive 1 blinded token each.

    /// API: Phase 3:
    ///    - Participants create a new Tor identity and "spend" their blinded token to receive one
    //         of the SCEAddress' input in phase 1.
    fn swap_second_message(&self, swap_msg2: SwapMsg2) -> Result<SCEAddress>;

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
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SwapStatus {
    Phase1,
    Phase2,
    Phase3,
}

/// Struct defines a Swap. This is signed by each participant as agreement to take part in the swap.
#[allow(dead_code)]
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

    /// Generate signature for change of state chain ownership
    pub fn sign(&self, proof_key_priv: &SecretKey) -> Result<Signature> {
        let secp = Secp256k1::new();
        let message = self.to_message()?;
        Ok(secp.sign(&message, &proof_key_priv))
    }

    /// Verify self's signature for transfer or withdraw
    pub fn verify_sig(&self, pk: &String, sig: Signature) -> Result<()> {
        let secp = Secp256k1::new();
        Ok(secp.verify(
            &self.to_message()?,
            &sig,
            &PublicKey::from_str(&pk).unwrap(),
        )?)
    }
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SwapInfo {
    status: SwapStatus,
    swap_token: SwapToken,
    blinded_spend_token: Option<String>, // Blinded token allowing client to claim an SCE-Address to transfer to.
}

impl Conductor for StateChainEntity {
    fn poll_utxo(&self, _state_chain_id: Uuid) -> Result<Option<Uuid>> {
        todo!()
    }
    fn poll_swap(&self, _swap_id: Uuid) -> Result<SwapInfo> {
        todo!()
    }
    fn register_utxo(&self, _register_utxo_msg: RegisterUtxo) -> Result<()> {
        todo!()
    }
    fn swap_first_message(&self, _swap_msg1: SwapMsg1) -> Result<()> {
        todo!()
    }
    fn swap_second_message(&self, _swap_msg2: SwapMsg2) -> Result<SCEAddress> {
        todo!()
    }
}

#[post("/swap/poll/utxo", format = "json", data = "<state_chain_id>")]
pub fn poll_utxo(
    sc_entity: State<StateChainEntity>,
    state_chain_id: Json<Uuid>,
) -> Result<Json<Option<Uuid>>> {
    match sc_entity.poll_utxo(state_chain_id.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/swap/poll/swap", format = "json", data = "<swap_id>")]
pub fn poll_swap(
    sc_entity: State<StateChainEntity>,
    swap_id: Json<Uuid>,
) -> Result<Json<SwapInfo>> {
    match sc_entity.poll_swap(swap_id.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/swap/register-utxo", format = "json", data = "<register_utxo_msg>")]
pub fn register_utxo(
    sc_entity: State<StateChainEntity>,
    register_utxo_msg: Json<RegisterUtxo>,
) -> Result<Json<()>> {
    match sc_entity.register_utxo(register_utxo_msg.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/swap/first", format = "json", data = "<swap_msg1>")]
pub fn swap_first_message(
    sc_entity: State<StateChainEntity>,
    swap_msg1: Json<SwapMsg1>,
) -> Result<Json<()>> {
    match sc_entity.swap_first_message(swap_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/swap/second", format = "json", data = "<swap_msg2>")]
pub fn swap_second_message(
    sc_entity: State<StateChainEntity>,
    swap_msg2: Json<SwapMsg2>,
) -> Result<Json<(SCEAddress)>> {
    match sc_entity.swap_second_message(swap_msg2.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use shared_lib::state_chain::StateChainSig;
    use std::str::FromStr;
    use std::{thread, time::Duration};

    #[test]
    fn test_swap_token_sig_verify() {
        let swap_token = SwapToken {
            id: Uuid::from_str("637203c9-37ab-46f9-abda-0678c891b2d3").unwrap(),
            amount: 1,
            time_out: 100,
            state_chain_ids: vec![Uuid::from_str("001203c9-93f0-46f9-abda-0678c891b2d3").unwrap()],
        };
        let proof_key_priv = SecretKey::from_slice(&[1; 32]).unwrap(); // Proof key priv part
        let proof_key = PublicKey::from_secret_key(&Secp256k1::new(), &proof_key_priv); // proof key

        let sig = swap_token.sign(&proof_key_priv).unwrap();
        assert!(swap_token.verify_sig(&proof_key.to_string(), sig).is_ok());
    }

    #[allow(dead_code)]
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
            StateChainSig::new(&proof_key_priv, &"Swap".to_string(), &proof_key.to_string())
                .unwrap();
        let _ = conductor.register_utxo(RegisterUtxo {
            state_chain_id,
            signature,
        });

        // Poll status of UTXO until a swap_id is returned signaling that utxo is involved in a swap.
        let swap_id: Uuid;
        println!("\nBegin polling of UTXO:");
        loop {
            println!("\nSleeping for 3 seconds..");
            thread::sleep(Duration::from_secs(3));
            let poll_utxo_res = conductor.poll_utxo(state_chain_id);
            println!("poll_utxo result: {:?}", poll_utxo_res);
            if let Ok(Some(v)) = poll_utxo_res {
                println!("\nSwap began!");
                swap_id = v;
                println!("Swap id: {}", swap_id);

                break;
            }
        }

        // Now that client knows they are in swap, use swap_id to poll for swap Information
        let poll_swap_res = conductor.poll_swap(swap_id);
        assert!(poll_swap_res.is_ok());

        let mut phase_1_complete = false;
        let mut phase_2_complete = false;

        let mut blinded_spend_token = String::default();

        // Poll Status of swap and perform necessary actions for each phase.
        println!("\nBegin polling of Swap:");
        loop {
            println!("\nSleeping for 3 seconds..");
            thread::sleep(Duration::from_secs(3));
            let poll_swap_res: SwapInfo = conductor.poll_swap(swap_id).unwrap();
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
                        tx_backup_addr: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
                        proof_key: proof_key.to_string(),
                    };
                    println!("SCE-Address: {:?}", sce_address);
                    println!("Sending swap token signature and SCE address.");
                    // Send to Conductor
                    let first_msg_resp = conductor.swap_first_message(SwapMsg1 {
                        swap_token_sig: signature.to_string(),
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
                    blinded_spend_token = poll_swap_res.blinded_spend_token.unwrap();
                    println!("Blinded spend token received: {:?}", blinded_spend_token);
                    phase_2_complete = true;
                }
                SwapStatus::Phase3 => {
                    println!("\nEnter phase3:");
                    println!("Connect to Conductor via new Tor identity and present Blinded spend token.");
                    let second_msg_resp = conductor.swap_second_message(SwapMsg2 {
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
            .expect_poll_swap() // get swap status return phase 1. x3
            .with(predicate::eq(swap_id))
            .times(3)
            .returning(move |_| {
                Ok(SwapInfo {
                    status: SwapStatus::Phase1,
                    swap_token: SwapToken {
                        id: swap_id,
                        amount: 1,
                        time_out: 100,
                        state_chain_ids: vec![state_chain_id, state_chain_id],
                    },
                    blinded_spend_token: None,
                })
            });
        conductor.expect_swap_first_message().returning(|_| Ok(())); // First message
        conductor
            .expect_poll_swap() // get swap status return phase 2. x2
            .with(predicate::eq(swap_id))
            .times(2)
            .returning(move |_| {
                Ok(SwapInfo {
                    status: SwapStatus::Phase2,
                    swap_token: SwapToken {
                        id: swap_id,
                        amount: 1,
                        time_out: 100,
                        state_chain_ids: vec![state_chain_id, state_chain_id],
                    },
                    blinded_spend_token: Some(
                        "1d02207c5167fe2973619edb07b720b038d4e724f21543ca0a429c20a67fd64a714f47aa"
                            .to_string(),
                    ),
                })
            });
        conductor
            .expect_poll_swap() // get swap status return phase 3. x2
            .with(predicate::eq(swap_id))
            .times(1)
            .returning(move |_| {
                Ok(SwapInfo {
                    status: SwapStatus::Phase3,
                    swap_token: SwapToken {
                        id: swap_id,
                        amount: 1,
                        time_out: 100,
                        state_chain_ids: vec![state_chain_id, state_chain_id],
                    },
                    blinded_spend_token: None,
                })
            });
        conductor.expect_swap_second_message().returning(|_| {
            Ok(SCEAddress {
                // Second message
                tx_backup_addr: "bc13rgtzzwf6e0sr5mdq3lydnw9re5r7xfkvy5l649".to_string(),
                proof_key: "65aab40995d3ed5d03a0567b04819ff12641b84c17f5e9d5dd075571e183469c8f"
                    .to_string(),
            })
        });
        conductor
    }
}
