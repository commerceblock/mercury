extern crate server_lib;
extern crate client_lib;
extern crate shared_lib;
extern crate bitcoin;
#[allow(unused_imports)]
use super::test::{gen_wallet, spawn_server, run_deposit};

#[cfg(test)]
mod tests {
    use super::*;

    use shared_lib::{
        structs::BatchData, state_chain::StateChainSig, commitment::{verify_commitment, make_commitment}};

    use bitcoin::PublicKey;
    use client_lib::state_entity;
    use std::time::Duration;
    use std::{thread, str::FromStr};
    use rand::random;

    /// Test batch transfer signatures
    #[test]
    fn test_batch_sigs() {
        spawn_server();
        let mut wallet = gen_wallet();
        let num_state_chains = 3;
        // make deposits
        let mut state_chain_ids = vec!();
        for _ in 0..num_state_chains {
            state_chain_ids.push(run_deposit(&mut wallet,&10000).1);
        }

        // Create new batch transfer ID
        let mut batch_id = random::<u64>().to_string();

        // Gen valid transfer-batch signatures for each state chain
        let mut transfer_sigs = vec!();
        for i in 0..num_state_chains {
            transfer_sigs.push(
                state_entity::transfer::transfer_batch_sign(
                    &mut wallet,
                    &state_chain_ids[i],
                    &batch_id
                ).unwrap()
            );
        }
        let transfer_batch_init = state_entity::transfer::transfer_batch_init(
            &wallet.client_shim,
            &transfer_sigs,
            &batch_id
        );
        assert!(transfer_batch_init.is_ok());

        // Gen sigs with one batch id different from the others
        let mut transfer_sigs = vec!();
        for i in 0..num_state_chains {
            if i == num_state_chains-1 {
                batch_id = String::from("12345");
            }
            transfer_sigs.push(
                state_entity::transfer::transfer_batch_sign(
                    &mut wallet,
                    &state_chain_ids[i],
                    &batch_id
                ).unwrap()
            );
        }
        let transfer_batch_init = state_entity::transfer::transfer_batch_init(
            &wallet.client_shim,
            &transfer_sigs,
            &batch_id
        );
        match transfer_batch_init {
            Err(e) => assert!(e.to_string().contains("Batch id is not identical for all signtures.")),
            _ => assert!(false)
        }

        // Gen sig with regular transfer message
        // First sign state chain
        let mut transfer_sigs = vec!();
        for _ in 0..1 {
            let state_chain_data = state_entity::api::get_statechain(&wallet.client_shim, &state_chain_ids[0]).unwrap();
            let state_chain = state_chain_data.chain;
            // Get proof key for signing
            let proof_key_derivation = wallet.se_proof_keys.get_key_derivation(&PublicKey::from_str(&state_chain.last().unwrap().data).unwrap());
            let state_chain_sig = StateChainSig::new(
                &proof_key_derivation.unwrap().private_key.key,
                &String::from("TRANSFER"),
                &String::from("proof key dummy")
            ).unwrap();
            transfer_sigs.push(state_chain_sig);
        }
        let transfer_batch_init = state_entity::transfer::transfer_batch_init(
            &wallet.client_shim,
            &transfer_sigs,
            &batch_id
        );
        match transfer_batch_init {
            Err(e) => assert!(e.to_string().contains("Signture's purpose is not valid for batch transfer.")),
            _ => assert!(false)
        }
    }

    // Perform batch transfer
    #[test]
    fn test_batch_transfer() {
        spawn_server();

        let num_state_chains = 3; // must be > 1
        let mut amounts = vec!();
        for i in 0..num_state_chains {
            amounts.push(u64::from_str(&format!("{}0000",i+1)).unwrap());
        }

        // Gen some wallets and deposit coins into SCE from each with amount 10000, 20000, 30000...
        let mut wallets = vec!();
        let mut deposits = vec!();
        for i in 0..num_state_chains {
            wallets.push(gen_wallet());
            for _ in 0..i { // Gen keys so different wallets have different proof keys (since wallets have the same seed)
                let _ = wallets[i].se_proof_keys.get_new_key();
            }
            deposits.push(run_deposit(&mut wallets[i],&amounts[i]));
        }

        // Check deposits exist
        for i in 0..num_state_chains {
            let (_, bals) = wallets[i].get_state_chain_balances();
            assert_eq!(bals.len(),1);
            assert_eq!(bals.last().unwrap().confirmed,amounts[i]);
        }


        // Create new batch transfer ID
        let batch_id = random::<u64>().to_string();

        // Gen transfer-batch signatures for each state chain (each wallet's SCE coins)
        let mut transfer_sigs = vec!();
        for i in 0..num_state_chains {
            transfer_sigs.push(
                state_entity::transfer::transfer_batch_sign(
                    &mut wallets[i],
                    &deposits[i].1, // state chain id
                    &batch_id
                ).unwrap()
            );
        }

        // Initiate batch-transfer protocol on SCE
        let transfer_batch_init = state_entity::transfer::transfer_batch_init(
            &wallets[0].client_shim,
            &transfer_sigs,
            &batch_id
        );
        assert!(transfer_batch_init.is_ok());

        // Check all marked false (= incomplete)
        let status_api = state_entity::api::get_transfer_batch_status(&wallets[0].client_shim, &batch_id);
        assert!(status_api.is_ok());
        let mut state_chains_copy = status_api.unwrap().state_chains;
        state_chains_copy.retain(|_, &mut v| v == false);
        assert_eq!(state_chains_copy.len(), num_state_chains);

        // Perform transfers
        let mut transfer_finalized_datas = vec!();
        let mut commitments = vec!();
        let mut nonces = vec!();
        for i in 0..num_state_chains {
            let receiver_addr = wallets[i+1%num_state_chains-1].get_new_state_entity_address(&deposits[i].2).unwrap();
            let tranfer_sender_resp =
                state_entity::transfer::transfer_sender(
                    &mut wallets[i],
                    &deposits[i].0,    // shared wallet id
                    receiver_addr.clone(),
            ).unwrap();

            // make commitment
            let (commitment, nonce) = make_commitment(&deposits[i].1);
            commitments.push(commitment.clone());
            nonces.push(nonce);

            transfer_finalized_datas.push(
                state_entity::transfer::transfer_receiver(
                    &mut wallets[i+1%num_state_chains-1],
                    &tranfer_sender_resp,
                    &Some(
                        BatchData {
                            id: batch_id.clone(),
                            commitment
                        })
                ).unwrap());
        }

        // Check commitments verify
        for i in 0..num_state_chains {
            assert!(
                verify_commitment(
                    &commitments[i],
                    &deposits[i].1,
                    &nonces[i]
                ).is_ok());
        }

        // attempt to transfer same UTXO a second time
        let receiver_addr = wallets[1].get_new_state_entity_address(&deposits[0].2).unwrap();
        match state_entity::transfer::transfer_sender(
            &mut wallets[0],
            &deposits[0].0,    // shared wallet id
            receiver_addr.clone()) {
                Err(e) => assert!(e.to_string().contains("Transfer already completed. Waiting for finalize.")),
                _ => assert!(false)
        }

        // Check all marked true (= complete)
        let status_api = state_entity::api::get_transfer_batch_status(&wallets[0].client_shim, &batch_id);
        let mut state_chains_copy = status_api.unwrap().state_chains;
        state_chains_copy.retain(|_, &mut v| v == false);
        assert_eq!(state_chains_copy.len(), 0);

        // Finalize transfers in wallets now that StateEntity has finalized the transfers
        transfer_finalized_datas.rotate_left(1); // rotate back to match with wallets vec
                                                 //(items pushed to this vec in i+1 order)
        for i in 0..num_state_chains {
            let _ = state_entity::transfer::transfer_receiver_finalize(
                &mut wallets[i],
                transfer_finalized_datas[i].clone()
            ).unwrap();
        }

        // Check amounts have correctly rotated
        amounts.rotate_left(1);
        for i in 0..num_state_chains {
            let (_, bals) = wallets[i].get_state_chain_balances();
            assert_eq!(bals.len(),1); // Only one active StateChain owned
            assert_eq!(
                bals.last().unwrap().confirmed,
                amounts[i]);
        }

        // attempt to reveal nonce when batch transfer is over
        assert!(state_entity::transfer::transfer_reveal_nonce(
            &wallets[0].client_shim,
            &transfer_sigs[0].data,
            &batch_id,
            &commitments[0],
            &nonces[0]
        ).is_err());
    }

    // Test punishments and reveals after batch transfer failure.
    // Set up batch transfer and perform 2 full transfers (wallet[0] -> wallet[1] and wallet[1] -> wallet[2]).
    // This should result in a single state chain (wallet[0]->wallet[1]) being unpunished after revealing.
    // (since both sender and receiver get punished in transfer failure)
    // Allow batch_lifetime time to pass, test punishments are set and test removal of punishment to completed transfer.
    // *** THIS TEST REQUIRES batch_lifetime SERVER SETTING TO BE SET TO < 3 ***
    #[test]
    fn test_failure_batch_transfer() {
        spawn_server();

        let num_state_chains = 3; // must be > 2
        let mut amounts = vec!();
        for i in 0..num_state_chains {
            amounts.push(u64::from_str(&format!("{}0000",i+1)).unwrap());
        }

        // Gen some wallets and deposit coins into SCE from each with amount 10000, 20000, 30000...
        let mut wallets = vec!();
        let mut deposits = vec!();
        for i in 0..num_state_chains {
            wallets.push(gen_wallet());
            for _ in 0..i { // Gen keys so different wallets have different proof keys (since wallets have the same seed)
                let _ = wallets[i].se_proof_keys.get_new_key();
            }
            deposits.push(run_deposit(&mut wallets[i],&amounts[i]));
        }
        // Check deposits exist
        for i in 0..num_state_chains {
            let (_, bals) = wallets[i].get_state_chain_balances();
            assert_eq!(bals.len(),1);
            assert_eq!(bals.last().unwrap().confirmed,amounts[i]);
        }

        // Create new batch transfer ID
        let batch_id = random::<u64>().to_string();

        // Gen transfer-batch signatures for each state chain (each wallet's SCE coins)
        let mut transfer_sigs = vec!();
        for i in 0..num_state_chains {
            transfer_sigs.push(
                state_entity::transfer::transfer_batch_sign(
                    &mut wallets[i],
                    &deposits[i].1, // state chain id
                    &batch_id
                ).unwrap()
            );
        }

        // Initiate batch-transfer protocol on SCE
        assert!(state_entity::transfer::transfer_batch_init(
            &wallets[0].client_shim,
            &transfer_sigs,
            &batch_id
        ).is_ok());

        // Check all marked false (= incomplete)
        let status_api = state_entity::api::get_transfer_batch_status(&wallets[0].client_shim, &batch_id);
        assert!(status_api.is_ok());
        let mut state_chains_copy = status_api.unwrap().state_chains;
        state_chains_copy.retain(|_, &mut v| v == false);
        assert_eq!(state_chains_copy.len(), num_state_chains);

        // We will complete 2 transfer_sender's and a 2 transfer_receiver's - yielding a single
        // fully completed state chain owned by wallet[1]
        // Perform transfers
        let receiver_addr = wallets[1].get_new_state_entity_address(&deposits[0].2).unwrap();
        let tranfer_sender_resp1 =
            state_entity::transfer::transfer_sender(
                &mut wallets[0],
                &deposits[0].0,    // shared wallet id
                receiver_addr.clone(),
        ).unwrap();
        let receiver_addr = wallets[2].get_new_state_entity_address(&deposits[1].2).unwrap();
        let tranfer_sender_resp2 =
            state_entity::transfer::transfer_sender(
                &mut wallets[1],
                &deposits[1].0,    // shared wallet id
                receiver_addr.clone(),
        ).unwrap();

        // make commitments - only need wallet[1]'s commitment
        let (commitment1, nonce1) = make_commitment(&deposits[1].1);
        let (commitment2, nonce2) = make_commitment(&deposits[2].1);

        // attempt to reveal nonce early
        assert!(state_entity::transfer::transfer_reveal_nonce(
            &wallets[0].client_shim,
            &transfer_sigs[0].data,
            &batch_id,
            &commitment1,
            &nonce1
        ).is_err());

        // complete wallet[1] and wallet[2]
        let transfer_finalized_data1 =
            state_entity::transfer::transfer_receiver(
                &mut wallets[1],
                &tranfer_sender_resp1,
                &Some(
                    BatchData {
                        id: batch_id.clone(),
                        commitment: commitment1.clone()
                    })
            ).unwrap();
        let _ =
            state_entity::transfer::transfer_receiver(
                &mut wallets[2],
                &tranfer_sender_resp2,
                &Some(
                    BatchData {
                        id: batch_id.clone(),
                        commitment: commitment2.clone()
                    })
            ).unwrap();

        // Check 2 transfers are complete
        let status_api = state_entity::api::get_transfer_batch_status(&wallets[0].client_shim, &batch_id);
        assert!(status_api.is_ok());
        let mut state_chains_copy = status_api.unwrap().state_chains;
        state_chains_copy.retain(|_, &mut v| v == true);
        assert_eq!(state_chains_copy.len(), 2);


        // Wait for batch transfer to end
        thread::sleep(Duration::from_secs(6));

        // Check ended
        match state_entity::api::get_transfer_batch_status(&wallets[0].client_shim, &batch_id) {
            Err(e) =>
                assert!(e.to_string().contains("Transfer Batch ended.")),
            _ => assert!(false)
        }

        // Check state chains are all locked by attempting to transfer + withdraw
        for i in 0..num_state_chains {
            let receiver_addr = wallets[i+1%num_state_chains-1].get_new_state_entity_address(&deposits[i].2).unwrap();
            match state_entity::transfer::transfer_sender(
                &mut wallets[i],
                &deposits[i].0,    // shared wallet id
                receiver_addr.clone(),
            ) {
                Err(e) => assert!(e.to_string().contains("State Chain locked for")),
                _ => assert!(false)
            };
            match state_entity::withdraw::withdraw(
                &mut wallets[i],
                &deposits[i].0,    // shared wallet id
            ) {
                Err(e) => assert!(e.to_string().contains("State Chain locked for")),
                _ => assert!(false)
            };
        }

        // attmept to finalize transfer - new shared key ID should not exist
        // since transfer is not finalized
        match state_entity::transfer::transfer_receiver_finalize(
            &mut wallets[0],
            transfer_finalized_data1
        ) {
            Err(e) => assert!(e.to_string().contains("User authorisation failed")),
            _ => assert!(false)
        };

        // Reveal commitments for both transfers
        assert!(state_entity::transfer::transfer_reveal_nonce(
            &wallets[1].client_shim,
            &deposits[1].1, // state chain id
            &batch_id,
            &commitment1,
            &nonce1
        ).is_ok());
        assert!(state_entity::transfer::transfer_reveal_nonce(
            &wallets[2].client_shim,
            &deposits[2].1, // state chain id
            &batch_id,
            &commitment2,
            &nonce2
        ).is_ok());

        // Now try to withdraw again.
        // Wallet[0] and wallet[2] should be locked.
        // Wallet[1] should be accessible.
        match state_entity::withdraw::withdraw(
            &mut wallets[0],
            &deposits[0].0,    // shared wallet id
        ) {
            Err(e) => assert!(e.to_string().contains("State Chain locked for")),
            _ => assert!(false)
        };

        assert!(state_entity::withdraw::withdraw(
            &mut wallets[1],
            &deposits[1].0,    // shared wallet id
        ).is_ok());

        match state_entity::withdraw::withdraw(
            &mut wallets[2],
            &deposits[2].0,    // shared wallet id
        ) {
            Err(e) => assert!(e.to_string().contains("State Chain locked for")),
            _ => assert!(false)
        };
    }
}
