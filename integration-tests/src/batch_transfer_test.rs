#[cfg(test)]
#[cfg(not(feature = "mockdb"))]
mod tests {
    use crate::*;
    extern crate bitcoin;
    extern crate client_lib;
    extern crate server_lib;
    extern crate shared_lib;

    use shared_lib::{commitment::verify_commitment, state_chain::StateChainSig};

    use bitcoin::PublicKey;
    use client_lib::state_entity;
    use std::{str::FromStr, thread, time::Duration};
    use std::thread::spawn;

    /// Test batch transfer signature generation
    #[test]
    #[serial]
    fn test_batch_sigs() {
        let _handle = start_server();
        let mut wallet = gen_wallet();
        let num_state_chains = 3;
        // make deposits
        let mut state_chain_ids = vec![];
        for _ in 0..num_state_chains {
            state_chain_ids.push(run_deposit(&mut wallet, &10000).1);
        }

        // Create new batch transfer ID
        let mut batch_id = Uuid::new_v4();

        // Gen valid transfer-batch signatures for each state chain
        let mut transfer_sigs = vec![];
        for i in 0..num_state_chains {
            transfer_sigs.push(
                state_entity::transfer::transfer_batch_sign(
                    &mut wallet,
                    &state_chain_ids[i],
                    &batch_id,
                )
                .unwrap(),
            );
        }

        let transfer_batch_init = state_entity::transfer::transfer_batch_init(
            &wallet.client_shim,
            &transfer_sigs,
            &batch_id,
        );
        assert!(transfer_batch_init.is_ok());

        // Gen sigs with one batch id different from the others
        let mut transfer_sigs = vec![];
        for i in 0..num_state_chains {
            if i == num_state_chains - 1 {
                batch_id = Uuid::new_v4();
            }
            transfer_sigs.push(
                state_entity::transfer::transfer_batch_sign(
                    &mut wallet,
                    &state_chain_ids[i],
                    &batch_id,
                )
                .unwrap(),
            );
        }
        let transfer_batch_init = state_entity::transfer::transfer_batch_init(
            &wallet.client_shim,
            &transfer_sigs,
            &batch_id,
        );
        match transfer_batch_init {
            Err(e) => assert!(e
                .to_string()
                .contains("Batch id is not identical for all signtures.")),
            _ => assert!(false),
        }

        // Gen sig with regular transfer message
        // First sign state chain
        let mut transfer_sigs = vec![];
        for _ in 0..1 {
            let state_chain_data =
                state_entity::api::get_statechain(&wallet.client_shim, &state_chain_ids[0])
                    .unwrap();
            let state_chain = state_chain_data.chain;
            // Get proof key for signing
            let proof_key_derivation = wallet.se_proof_keys.get_key_derivation(
                &PublicKey::from_str(&state_chain.last().unwrap().data).unwrap(),
            );
            let state_chain_sig = StateChainSig::new(
                &proof_key_derivation.unwrap().private_key.key,
                &String::from("TRANSFER"),
                &String::from("proof key dummy"),
            )
            .unwrap();
            transfer_sigs.push(state_chain_sig);
        }
        let transfer_batch_init = state_entity::transfer::transfer_batch_init(
            &wallet.client_shim,
            &transfer_sigs,
            &batch_id,
        );
        match transfer_batch_init {
            Err(e) => assert!(e
                .to_string()
                .contains("Signture's purpose is not valid for batch transfer.")),
            _ => assert!(false),
        }
    }

    /// Perform batch transfer with tests and checks throughout
    #[test]
    #[serial]
    fn test_batch_transfer() {
        let _handle = start_server();

        let num_state_chains = 3; // must be > 1
        let mut amounts = vec![];
        for i in 0..num_state_chains {
            amounts.push(u64::from_str(&format!("{}0000", i + 1)).unwrap());
        }

        // Gen some wallets and deposit coins into SCE from each with amount 10000, 20000, 30000...
        let mut wallets = vec![];
        let mut deposits = vec![];
        for i in 0..num_state_chains {
            wallets.push(gen_wallet());
            for _ in 0..i {
                // Gen keys so different wallets have different proof keys (since wallets have the same seed)
                let _ = wallets[i].se_proof_keys.get_new_key();
            }
            deposits.push(run_deposit(&mut wallets[i], &amounts[i]));
        }

        // Check deposits exist
        for i in 0..num_state_chains {
            let (_, _, bals) = wallets[i].get_state_chains_info().unwrap();
            assert_eq!(bals.len(), 1);
            assert_eq!(
                bals.last().expect("expected state chain info").confirmed,
                amounts[i]
            );
        }

        // Perform transfers atomically
        let swap_map = vec![(0, 1), (1, 2), (2, 0)]; // rotate state chains right: 0->1, 1->2, 2->3
        let mut funding_txids = vec![];
        let mut shared_key_ids = vec![];
        let mut state_chain_ids = vec![];
        for deposit in deposits {
            funding_txids.push(deposit.2);
            shared_key_ids.push(deposit.0);
            state_chain_ids.push(deposit.1);
        }
        let (batch_id, transfer_finalized_datas, commitments, nonces, transfer_sigs) =
            run_batch_transfer(&mut wallets, &swap_map, &funding_txids, &state_chain_ids);

        // Check commitments verify
        for i in 0..num_state_chains {
            assert!(verify_commitment(
                &commitments[i],
                &state_chain_ids[i].to_string(),
                &nonces[i]
            )
            .is_ok());
        }

        // Attempt to transfer same UTXO a second time
        let receiver_addr = wallets[1]
            .get_new_state_entity_address(&funding_txids[0])
            .expect("expected state chain entity address");
        match state_entity::transfer::transfer_sender(
            &mut wallets[0],
            &state_chain_ids[0],
            receiver_addr.clone(),
        ) {
            Err(e) => {
                assert!(e.to_string().contains("State Chain not owned by User ID:"));
            }
            _ => assert!(false),
        }

        // Check all transfers marked true (= complete)
        let status_api =
            state_entity::api::get_transfer_batch_status(&wallets[0].client_shim, &batch_id);
        let mut state_chains_copy = status_api.expect("expected status").state_chains;
        state_chains_copy.retain(|_, &mut v| v == false);
        assert_eq!(state_chains_copy.len(), 0);

        // Finalize transfers in wallets now that StateEntity has completed the transfers.
        finalize_batch_transfer(&mut wallets, &swap_map, transfer_finalized_datas);

        // Check amounts have correctly transferred
        batch_transfer_verify_amounts(&mut wallets, &amounts, &state_chain_ids, &swap_map);

        // Check each wallet has only one state chain available
        for i in 0..swap_map.len() {
            let (_, _, bals) = wallets[i].get_state_chains_info().unwrap();
            assert_eq!(bals.len(), 1); // Only one active StateChain owned
        }

        // attempt to reveal nonce when batch transfer is over
        assert!(state_entity::transfer::transfer_reveal_nonce(
            &wallets[0].client_shim,
            &Uuid::from_str(&transfer_sigs[0].data).unwrap(),
            &batch_id,
            &commitments[0],
            &nonces[0]
        )
        .is_err());
    }

    /// *** THIS TEST REQUIRES batch_lifetime SERVER SETTING TO BE SET TO 5 ***
    /// Test punishments and reveals after batch transfer failure.
    /// Set up batch transfer and perform 2 full transfers (wallet[0] -> wallet[1] and wallet[1] -> wallet[2]).
    /// This should result in a single state chain (wallet[0]->wallet[1]) being unpunished after revealing.
    /// (since both sender and receiver get punished in transfer failure)
    /// Allowing batch_lifetime time to pass, test punishments are set and test removal of punishment to completed transfer.
    // #[test]
    #[allow(dead_code)]
    fn test_failure_batch_transfer() {
        let _handle = start_server();

        let num_state_chains = 3; // must be > 2
        let mut amounts = vec![];
        for i in 0..num_state_chains {
            amounts.push(u64::from_str(&format!("{}0000", i + 1)).unwrap());
        }

        // Gen some wallets and deposit coins into SCE from each with amount 10000, 20000, 30000...
        let mut wallets = vec![];
        let mut deposits = vec![];
        for i in 0..num_state_chains {
            wallets.push(gen_wallet());
            for _ in 0..i {
                // Gen keys so different wallets have different proof keys (since wallets have the same seed)
                let _ = wallets[i].se_proof_keys.get_new_key();
            }
            deposits.push(run_deposit(&mut wallets[i], &amounts[i]));
        }
        // Check deposits exist
        for i in 0..num_state_chains {
            let (_, _, bals) = wallets[i].get_state_chains_info().unwrap();
            assert_eq!(bals.len(), 1);
            assert_eq!(bals.last().unwrap().confirmed, amounts[i]);
        }

        // Create new batch transfer ID
        let batch_id = Uuid::new_v4();

        // Gen transfer-batch signatures for each state chain (each wallet's SCE coins)
        let mut transfer_sigs = vec![];
        for i in 0..num_state_chains {
            transfer_sigs.push(
                state_entity::transfer::transfer_batch_sign(
                    &mut wallets[i],
                    &deposits[i].1, // state chain id
                    &batch_id,
                )
                .unwrap(),
            );
        }

        // Initiate batch-transfer protocol on SCE
        assert!(state_entity::transfer::transfer_batch_init(
            &wallets[0].client_shim,
            &transfer_sigs,
            &batch_id
        )
        .is_ok());

        // Check all transfers marked false (= incomplete)
        let status_api =
            state_entity::api::get_transfer_batch_status(&wallets[0].client_shim, &batch_id);
        assert!(status_api.is_ok());
        let mut state_chains_copy = status_api.unwrap().state_chains;
        state_chains_copy.retain(|_, &mut v| v == false);
        assert_eq!(state_chains_copy.len(), num_state_chains);

        // We will complete 2 transfer_sender's and a 2 transfer_receiver's - yielding a single
        // fully completed state chain owned by wallet[1]
        // Perform transfers
        let (transfer_finalized_data1, commitment1, nonce1) = run_transfer_with_commitment(
            &mut wallets,
            0,
            &deposits[0].1, // state chain id
            1,
            &deposits[1].1, // state chain id
            &deposits[0].2, // funding txid
            &batch_id,
        );
        let (_, commitment2, nonce2) = run_transfer_with_commitment(
            &mut wallets,
            1,
            &deposits[1].1, // state chain id
            2,
            &deposits[2].1, // state chain id
            &deposits[1].2, // funding txid
            &batch_id,
        );

        // Check 2 transfers are complete
        let status_api =
            state_entity::api::get_transfer_batch_status(&wallets[0].client_shim, &batch_id);
        assert!(status_api.is_ok());
        let mut state_chains_copy = status_api.unwrap().state_chains;
        state_chains_copy.retain(|_, &mut v| v == true);
        assert_eq!(state_chains_copy.len(), 2);

        // attempt to reveal nonce early
        assert!(state_entity::transfer::transfer_reveal_nonce(
            &wallets[0].client_shim,
            &Uuid::from_str(&transfer_sigs[0].data).unwrap(),
            &batch_id,
            &commitment1,
            &nonce1
        )
        .is_err());

        // Wait for batch transfer to end
        thread::sleep(Duration::from_secs(6));

        // Check ended
        match state_entity::api::get_transfer_batch_status(&wallets[0].client_shim, &batch_id) {
            Err(e) => assert!(e.to_string().contains("Batch transfer timeout")),
            _ => assert!(false),
        }

        // Check state chains are all locked by attempting to transfer + withdraw
        for i in 0..num_state_chains {
            let receiver_addr = wallets[i + 1 % num_state_chains - 1]
                .get_new_state_entity_address(&deposits[i].2)
                .unwrap();
            match state_entity::transfer::transfer_sender(
                &mut wallets[i],
                &deposits[i].1, // state chain id
                receiver_addr.clone(),
            ) {
                Err(e) => {
                    assert!(e.to_string().contains("State Chain locked for"));
                }
                _ => assert!(false),
            };
            match state_entity::withdraw::withdraw(
                &mut wallets[i],
                &deposits[i].1, // state chain id
            ) {
                Err(e) => assert!(e.to_string().contains("State Chain locked for")),
                _ => assert!(false),
            };
        }

        // Attempt to finalize transfer - new shared key ID should not exist since transfer is not finalized
        match state_entity::transfer::transfer_receiver_finalize(
            &mut wallets[0],
            transfer_finalized_data1,
        ) {
            Err(e) => assert!(e.to_string().contains("User authorisation failed")),
            _ => assert!(false),
        };

        // Reveal commitments for both transfers
        assert!(state_entity::transfer::transfer_reveal_nonce(
            &wallets[1].client_shim,
            &deposits[1].1, // state chain id
            &batch_id,
            &commitment1,
            &nonce1
        )
        .is_ok());
        assert!(state_entity::transfer::transfer_reveal_nonce(
            &wallets[2].client_shim,
            &deposits[2].1, // state chain id
            &batch_id,
            &commitment2,
            &nonce2
        )
        .is_ok());

        // Now attempt to withdraw again.
        // Wallet[0] and wallet[2] should be locked.
        // Wallet[1] should be accessible.
        match state_entity::withdraw::withdraw(
            &mut wallets[0],
            &deposits[0].1, // state chain id
        ) {
            Err(e) => assert!(e.to_string().contains("State Chain locked for")),
            _ => assert!(false),
        };

        assert!(state_entity::withdraw::withdraw(
            &mut wallets[1],
            &deposits[1].1, // state chain id
        )
        .is_ok());

        match state_entity::withdraw::withdraw(
            &mut wallets[2],
            &deposits[2].1, // state chain id
        ) {
            Err(e) => assert!(e.to_string().contains("State Chain locked for")),
            _ => assert!(false),
        };
    }


    #[test]
    #[serial]
    fn test_swap() {
        let _handle = start_server();

        let num_state_chains: u64 = 3; 
        let amount: u64 = 10000;// = u64::from_str(&format!("10000")).unwrap();
        
        // Gen some wallets and deposit coins into SCE 
        let mut wallets = vec![];
        let mut deposits = vec![];
        let mut thread_handles = vec![];

        for i in 0..num_state_chains as usize {
          
            wallets.push(gen_wallet());
            for _ in 0..i {
                // Gen keys so different wallets have different proof keys (since wallets have the same seed)
                let _ = wallets[i].se_proof_keys.get_new_key();
            }
           
            deposits.push(run_deposit(&mut wallets[i], &amount));
            let deposit = deposits.last().unwrap().clone();

            let (_shared_key_ids, wallet_sc_ids, bals) = wallets.last().unwrap().get_state_chains_info();
            println!("deposit wallet state chain ids: {:?}", wallet_sc_ids);
            println!("deposit wallet balances: {:?}", bals);

            let wallet_ser = wallets.last().unwrap().to_json();

            thread_handles.push(
                spawn(move || {
                        let mut wallet=wallet::wallet::Wallet::from_json(
                            wallet_ser,
                            ClientShim::new("http://localhost:8000".to_string(), None, None),
                            Box::new(MockElectrum::new())
                        )?;
                        state_entity::conductor::do_swap(&mut wallet, &deposit.1, &num_state_chains, false)
                    }
                )
            );
        }

        let mut i = 0;
        for handle in thread_handles {
            handle.join().unwrap().unwrap();
            i = i+1;
        }

    }
}
