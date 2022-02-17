#[cfg(test)]
#[cfg(not(feature = "mockdb"))]
mod tests {
    use crate::*;
    use bitcoin::PublicKey;
    use client_lib::state_entity;
    use shared_lib::{commitment::verify_commitment, state_chain::StateChainSig};
    use state_entity::transfer::{
        get_transfer_finalize_data_for_recovery, TransferFinalizeDataForRecovery,
    };
    use std::{collections::HashMap, thread::spawn};
    use std::{str::FromStr, thread, time::Duration};

    /// Test batch transfer signature generation
    #[test]
    #[serial]
    fn test_batch_sigs() {
        let _handle = start_server(None, None);

        let mut wallet = gen_wallet(None);
        let num_state_chains = 3;
        // make deposits
        let mut statechain_ids = vec![];
        let mut statechain_proof_keys = vec![];
        for _ in 0..num_state_chains {
            let dep_res = run_deposit(&mut wallet, &10000);
            statechain_ids.push(dep_res.1);
            statechain_proof_keys.push(dep_res.5.to_string());
        }

        // Create new batch transfer ID
        let mut batch_id = Uuid::new_v4();

        // Gen valid transfer-batch signatures for each state chain
        let mut transfer_sigs = vec![];
        for i in 0..num_state_chains {
            transfer_sigs.push(
                state_entity::transfer::transfer_batch_sign(
                    &mut wallet,
                    &statechain_ids[i],
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
                    &statechain_ids[i],
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
            let statechain_data =
                state_entity::api::get_statechain(&wallet.client_shim, &statechain_ids[0]).unwrap();
            // Get proof key for signing
            let proof_key_derivation = wallet.se_proof_keys.get_key_derivation(
                &PublicKey::from_str(&statechain_data.get_tip().unwrap().data).unwrap(),
            );
            let statechain_sig = StateChainSig::new(
                &proof_key_derivation.unwrap().private_key.key,
                &String::from("TRANSFER"),
                &String::from("proof key dummy"),
            )
            .unwrap();
            transfer_sigs.push(statechain_sig);
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
        reset_data(&wallet.client_shim).unwrap();
    }

    /// Perform batch transfer with tests and checks throughout
    #[test]
    #[serial]
    fn test_batch_transfer() {
        let _handle = start_server(None, None);

        let num_state_chains = 3; // must be > 1
        let mut amounts = vec![];
        for i in 0..num_state_chains {
            amounts.push(u64::from_str(&format!("{}0000", i + 1)).unwrap());
        }

        // Gen some wallets and deposit coins into SCE from each with amount 10000, 20000, 30000...
        let mut wallets = vec![];
        let mut deposits = vec![];
        for i in 0..num_state_chains {
            wallets.push(gen_wallet(None));
            for _ in 0..i {
                // Gen keys so different wallets have different proof keys (since wallets have the same seed)
                let _ = wallets[i].se_proof_keys.get_new_key();
            }
            deposits.push(run_deposit(&mut wallets[i], &amounts[i]));
        }

        // Check deposits exist
        for i in 0..num_state_chains {
            let (_, _, bals, _) = wallets[i].get_state_chains_info().unwrap();
            assert_eq!(bals.len(), 1);
            assert_eq!(
                bals.last().expect("expected state chain info").confirmed,
                amounts[i]
            );
        }

        let mut funding_txids = vec![];
        let mut shared_key_ids = vec![];
        let mut statechain_ids = vec![];
        for deposit in &deposits {
            funding_txids.push(deposit.2.clone());
            //shared_key_ids.push(deposit.0.clone());
            statechain_ids.push(deposit.1.clone());
        }
        // Transfer the coins to the other wallets in single transfers
        let swap_map = vec![(0, 1), (1, 2), (2, 0)]; // rotate state chains right: 0->1, 1->2, 2->0
        for (from, to) in &swap_map {
            let state_chains_info = wallets[from.to_owned()].get_state_chains_info().unwrap();
            let shared_key_id = state_chains_info.0.last().unwrap();
            let (statechain_id, funding_txid, _, _, _) = wallets[from.to_owned()]
                .get_shared_key_info(shared_key_id)
                .unwrap();

            let receiver_addr = wallets[to.to_owned()]
                .get_new_state_entity_address()
                .unwrap();

            let new_shared_key_id = run_transfer(
                &mut wallets,
                from.to_owned(),
                to.to_owned(),
                &receiver_addr,
                &statechain_id,
            );
            shared_key_ids.push(new_shared_key_id);
        }

        // Perform transfers atomically
        let (batch_id, transfer_finalized_datas, commitments, nonces, transfer_sigs) =
            run_batch_transfer(&mut wallets, &swap_map, &funding_txids, &statechain_ids);

        let mut sorted_statechain_ids = statechain_ids.clone();
        sorted_statechain_ids.sort();
        let sorted_id_str = {
            let mut result = String::new();
            for id in sorted_statechain_ids {
                result.push_str(&id.to_string());
            }
            result
        };

        // Check commitments verify
        for i in 0..num_state_chains {
            let mut commitment_data = statechain_ids[i].to_string();
            commitment_data.push_str(&sorted_id_str);
            println!(
                "test_batch_transfer - verifying commitment data for statechain {}: {}",
                statechain_ids[i], commitment_data
            );
            assert!(verify_commitment(&commitments[i], &commitment_data, &nonces[i]).is_ok());
        }

        // Attempt to transfer same UTXO a second time
        let receiver_addr = wallets[1]
            .get_new_state_entity_address()
            .expect("expected state chain entity address");
        println!("do transfer sender...");
        match state_entity::transfer::transfer_sender(
            &mut wallets[0],
            &statechain_ids[0],
            receiver_addr.clone(),
            Some(batch_id.clone()),
        ) {
            Err(e) => {
                assert!(e.to_string().contains("State Chain not owned by User ID:"));
            }
            _ => assert!(false),
        }

        println!("get batch transfer status...");
        // Check transfers complete
        let status_api =
            state_entity::api::get_transfer_batch_status(&wallets[0].client_shim, &batch_id);
        assert!(status_api.expect("expected status 1").finalized);

        // Finalize transfers in wallets now that StateEntity has completed the transfers.
        println!("finalize bach transfer...");
        finalize_batch_transfer(&mut wallets, &swap_map, transfer_finalized_datas.clone());
        println!("finished finalize bach transfer.");

        // Check amounts have correctly transferred
        batch_transfer_verify_amounts(&mut wallets, &amounts, &statechain_ids, &swap_map);

        // Check each wallet has only one state chain available
        for i in 0..swap_map.len() {
            let (_, _, bals, _) = wallets[i].get_state_chains_info().unwrap();
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

        //Test get recovery data for batch transfer
        let mut transfer_finalized_datas_recovered =
            HashMap::<Uuid, TransferFinalizeDataForRecovery>::new();

        let mut pubkey_hex_vec = vec![];

        //shared_key_ids = vec![];
        for wallet in &mut wallets {
            let state_chains_info = wallet.get_state_chains_info().unwrap();
            let mut shared_key_infos = vec![];
            for shared_key_id in state_chains_info.0 {
                shared_key_infos.push(wallet.get_shared_key_info(&shared_key_id).unwrap());
                //      shared_key_ids.push(shared_key_id);
            }
            //Get recovery data
            for ski in &shared_key_infos {
                pubkey_hex_vec.push(ski.2.clone());
            }
        }

        let recovery_data =
            state_entity::api::get_recovery_data_vec(&wallets[0].client_shim, &pubkey_hex_vec)
                .unwrap();

        for wallet in &mut wallets {
            println!("test get finalization recovery data...");
            for data in &recovery_data {
                let finalization_data = state_entity::api::get_sc_transfer_finalize_data(
                    &wallet.client_shim,
                    &data.statechain_id,
                )
                .unwrap();
                match get_transfer_finalize_data_for_recovery(
                    wallet,
                    &finalization_data,
                    &data,
                    &data.proof_key,
                ) {
                    Ok(v) => {
                        transfer_finalized_datas_recovered.insert(data.statechain_id.to_owned(), v);
                    }
                    Err(e) => println!("error get_transfer_finalize_data_for_recovery: {}", &e),
                }
            }
        }

        assert_eq!(
            &transfer_finalized_datas_recovered.len(),
            &transfer_finalized_datas.len()
        );
        //Verify the recovered finalization data
        for data in &transfer_finalized_datas {
            let statechain_id = &data.statechain_id;
            let recovered = &transfer_finalized_datas_recovered[statechain_id];
            recovered.compare(&data).unwrap();
        }

        //Rotate the orders
        /*
        let back = funding_txids.pop().unwrap();
        funding_txids.push(back);
        let back = statechain_ids.pop().unwrap();
        statechain_ids.push(back);
        assert!(shared_key_ids.len() == funding_txids.len());
        */

        reset_data(&wallets[0].client_shim).unwrap();
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
        let _handle = start_server(None, None);

        let num_state_chains = 3; // must be > 2
        let mut amounts = vec![];
        for i in 0..num_state_chains {
            amounts.push(u64::from_str(&format!("{}0000", i + 1)).unwrap());
        }

        // Gen some wallets and deposit coins into SCE from each with amount 10000, 20000, 30000...
        let mut wallets = vec![];
        let mut deposits = vec![];
        let mut participants = vec![];
        for i in 0..num_state_chains {
            wallets.push(gen_wallet(None));
            for _ in 0..i {
                // Gen keys so different wallets have different proof keys (since wallets have the same seed)
                let _ = wallets[i].se_proof_keys.get_new_key();
            }
            let deposit = run_deposit(&mut wallets[i], &amounts[i]);
            participants.push(deposit.1);
            deposits.push(deposit);
        }

        //Sort the participants vector
        participants.sort();

        // Check deposits exist
        for i in 0..num_state_chains {
            let (_, _, bals, _) = wallets[i].get_state_chains_info().unwrap();
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

        // Check incomplete
        let status_api =
            state_entity::api::get_transfer_batch_status(&wallets[0].client_shim, &batch_id)
                .expect("expected status 2");
        assert_eq!(status_api.finalized, false);

        // We will complete 2 transfer_sender's and a 2 transfer_receiver's - yielding a single
        // fully completed state chain owned by wallet[1]
        // Perform transfers
        let (transfer_finalized_data1, commitment1, nonce1) = run_transfer_with_commitment(
            &mut wallets,
            &participants,
            0,
            &deposits[0].1, // state chain id
            1,
            &deposits[1].1, // state chain id
            &deposits[0].2, // funding txid
            &batch_id,
        );
        let (_, commitment2, nonce2) = run_transfer_with_commitment(
            &mut wallets,
            &participants,
            1,
            &deposits[1].1, // state chain id
            2,
            &deposits[2].1, // state chain id
            &deposits[1].2, // funding txid
            &batch_id,
        );

        // Check complete
        let status_api =
            state_entity::api::get_transfer_batch_status(&wallets[0].client_shim, &batch_id)
                .expect("expected status 3");
        assert!(status_api.finalized);

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
                .get_new_state_entity_address()
                .unwrap();
            match state_entity::transfer::transfer_sender(
                &mut wallets[i],
                &deposits[i].1, // state chain id
                receiver_addr.clone(),
                Some(batch_id.clone()),
            ) {
                Err(e) => {
                    assert!(e.to_string().contains("State Chain locked for"));
                }
                _ => assert!(false),
            };
            match state_entity::withdraw::withdraw(
                &mut wallets[i],
                &deposits[i].1, // state chain id
                &FEE,
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
            &FEE,
        ) {
            Err(e) => assert!(e.to_string().contains("State Chain locked for")),
            _ => assert!(false),
        };

        assert!(state_entity::withdraw::withdraw(
            &mut wallets[1],
            &deposits[1].1, // state chain id
            &FEE,
        )
        .is_ok());

        match state_entity::withdraw::withdraw(
            &mut wallets[2],
            &deposits[2].1, // state chain id
            &FEE,
        ) {
            Err(e) => assert!(e.to_string().contains("State Chain locked for")),
            _ => assert!(false),
        };
        reset_data(&wallets[0].client_shim).unwrap();
    }

    #[test]
    #[serial]
    fn test_swap() {
        let _handle = start_server(None, None);

        let num_state_chains: u64 = 3;
        let amount: u64 = 100000; // = u64::from_str(&format!("10000")).unwrap();

        // Gen some wallets and deposit coins into SCE
        let mut wallets = vec![];
        let mut deposits = vec![];
        let mut thread_handles = vec![];
        let mut wallet_sers = vec![];

        for i in 0..num_state_chains as usize {
            wallets.push(gen_wallet(None));
            for _ in 0..i {
                // Gen keys so different wallets have different proof keys (since wallets have the same seed)
                let _ = wallets[i].se_proof_keys.get_new_key();
            }

            deposits.push(run_deposit(&mut wallets[i], &amount));
            let deposit = deposits.last().unwrap().clone();

            let (_shared_key_ids, _wallet_sc_ids, _bals, _locktimes) =
                wallets.last().unwrap().get_state_chains_info().unwrap();

            wallet_sers.push((wallets.last().unwrap().to_json(), deposit.1));
        }

        println!("Starting swaps...");
        let start = Instant::now();
        for (wallet_ser, deposit) in wallet_sers {
            thread_handles.push(spawn(move || {
                let mut wallet = wallet::wallet::Wallet::from_json(
                    wallet_ser,
                    ClientShim::new("http://localhost:8000".to_string(), None, None),
                    ClientShim::new("http://localhost:8000".to_string(), None, None),
                )?;

                state_entity::conductor::do_swap(&mut wallet, &deposit, &num_state_chains, false)
            }))
        }

        let mut i = 0;
        for handle in thread_handles {
            handle.join().unwrap().unwrap();
            i = i + 1;
        }
        println!("(Swaps Took: {})", TimeFormat(start.elapsed()));
        reset_data(&wallets[0].client_shim).unwrap();
    }

    #[test]
    #[serial]
    fn test_swap_punish() {
        let _handle = start_server(None, None);

        let num_state_chains: u64 = 3;
        let amount: u64 = 100000; // = u64::from_str(&format!("10000")).unwrap();

        // Gen some wallets and deposit coins into SCE
        let mut wallets = vec![];
        let mut deposits = vec![];
        let mut wallet_sers = vec![];

        for i in 0..num_state_chains as usize {
            wallets.push(gen_wallet(None));
            for _ in 0..i {
                // Gen keys so different wallets have different proof keys (since wallets have the same seed)
                let _ = wallets[i].se_proof_keys.get_new_key();
            }

            deposits.push(run_deposit(&mut wallets[i], &amount));
            let deposit = deposits.last().unwrap().clone();

            let (_shared_key_ids, _wallet_sc_ids, _bals, _locktimes) =
                wallets.last().unwrap().get_state_chains_info().unwrap();

            wallet_sers.push((wallets.last().unwrap().to_json(), deposit.1));
        }

        println!("Starting swaps...");
        for (wallet_ser, deposit) in wallet_sers.clone() {
            let mut wallet = wallet::wallet::Wallet::from_json(
                wallet_ser,
                ClientShim::new("http://localhost:8000".to_string(), None, None),
                ClientShim::new("http://localhost:8000".to_string(), None, None),
            )
            .unwrap();
            // register for swap (phase 1)
            let _ret = state_entity::conductor::swap_register_utxo(
                &mut wallet,
                &deposit,
                &num_state_chains,
            );
        }

        // attempt to register again
        thread::sleep(Duration::from_secs(10));

        let mut wallet = wallet::wallet::Wallet::from_json(
            wallet_sers[0].0.clone(),
            ClientShim::new("http://localhost:8000".to_string(), None, None),
            ClientShim::new("http://localhost:8000".to_string(), None, None),
        )
        .unwrap();

        let _poll00 =
            state_entity::conductor::swap_poll_utxo(&wallet.conductor_shim, &wallet_sers[0].1);

        let mut wallet2 = wallet::wallet::Wallet::from_json(
            wallet_sers[1].0.clone(),
            ClientShim::new("http://localhost:8000".to_string(), None, None),
            ClientShim::new("http://localhost:8000".to_string(), None, None),
        )
        .unwrap();

        let mut wallet3 = wallet::wallet::Wallet::from_json(
            wallet_sers[2].0.clone(),
            ClientShim::new("http://localhost:8000".to_string(), None, None),
            ClientShim::new("http://localhost:8000".to_string(), None, None),
        )
        .unwrap();

        let register_try = state_entity::conductor::swap_register_utxo(
            &mut wallet,
            &wallet_sers[0].1,
            &num_state_chains,
        );

        match register_try {
            Err(e) => assert!(e.to_string().contains("Coin in active swap")),
            _ => assert!(false),
        }

        // perform swap message 1 for wallets 2 and 3

        let _poll0 =
            state_entity::conductor::swap_poll_utxo(&wallet.conductor_shim, &wallet_sers[0].1);

        let swap_id =
            state_entity::conductor::swap_poll_utxo(&wallet.conductor_shim, &wallet_sers[0].1)
                .unwrap()
                .id
                .unwrap();
        let info = state_entity::conductor::swap_info(&wallet.conductor_shim, &swap_id)
            .unwrap()
            .unwrap();

        let proof_key2 = wallet2.se_proof_keys.get_new_key().unwrap();
        let proof_key2 =
            bitcoin::secp256k1::PublicKey::from_slice(&proof_key2.to_bytes().as_slice()).unwrap();
        let address2 = SCEAddress {
            tx_backup_addr: None,
            proof_key: proof_key2,
        };
        let transfer_batch_sig2 =
            state_entity::transfer::transfer_batch_sign(&mut wallet2, &wallet_sers[1].1, &swap_id)
                .unwrap();

        let _my_bst_data2 = state_entity::conductor::swap_first_message(
            &wallet2,
            &info,
            &wallet_sers[1].1,
            &transfer_batch_sig2,
            &address2,
        )
        .unwrap();

        let proof_key3 = wallet3.se_proof_keys.get_new_key().unwrap();
        let proof_key3 =
            bitcoin::secp256k1::PublicKey::from_slice(&proof_key3.to_bytes().as_slice()).unwrap();
        let address3 = SCEAddress {
            tx_backup_addr: None,
            proof_key: proof_key3,
        };
        let transfer_batch_sig3 =
            state_entity::transfer::transfer_batch_sign(&mut wallet3, &wallet_sers[2].1, &swap_id)
                .unwrap();

        let _my_bst_data3 = state_entity::conductor::swap_first_message(
            &wallet3,
            &info,
            &wallet_sers[2].1,
            &transfer_batch_sig3,
            &address3,
        )
        .unwrap();

        // after swap group timeout (60 s) attempt to register again

        thread::sleep(Duration::from_secs(60));

        let _poll1 =
            state_entity::conductor::swap_poll_utxo(&wallet.conductor_shim, &wallet_sers[0].1);
        let register_try_2 = state_entity::conductor::swap_register_utxo(
            &mut wallet,
            &wallet_sers[0].1,
            &num_state_chains,
        );

        match register_try_2 {
            Err(e) => assert!(e.to_string().contains("In punishment list")),
            _ => assert!(false),
        }

        // after punishment timeout (60 s) attempt to register again

        thread::sleep(Duration::from_secs(60));

        let _poll2 =
            state_entity::conductor::swap_poll_utxo(&wallet.conductor_shim, &wallet_sers[0].1);
        let register_try_3 = state_entity::conductor::swap_register_utxo(
            &mut wallet,
            &wallet_sers[0].1,
            &num_state_chains,
        );

        match register_try_3 {
            Err(_e) => assert!(false),
            _ => assert!(true),
        }

        reset_data(&wallets[0].client_shim).unwrap();
    }

    #[test]
    #[serial]
    fn test_register_utxo() {
        let _handle = start_server(None, None);

        let num_state_chains: u64 = 2;
        let amount: u64 = 100000; // = u64::from_str(&format!("10000")).unwrap();
        let odd_amount: u64 = 123400;

        let mut wallet1 = gen_wallet(None);
        let _ = wallet1.se_proof_keys.get_new_key();
        let deposit1 = run_deposit(&mut wallet1, &amount).clone();
        let wallet1_json = wallet1.to_json();

        let mut wallet_1 = wallet::wallet::Wallet::from_json(
            wallet1_json,
            ClientShim::new("http://localhost:8000".to_string(), None, None),
            ClientShim::new("http://localhost:8000".to_string(), None, None),
        )
        .unwrap();

        let register_try_1 = state_entity::conductor::swap_register_utxo(
            &mut wallet_1,
            &deposit1.1,
            &num_state_chains,
        );

        match register_try_1 {
            Err(_e) => assert!(false),
            _ => assert!(true),
        }

        let mut wallet2 = gen_wallet(None);
        let _ = wallet2.se_proof_keys.get_new_key();
        let deposit2 = run_deposit(&mut wallet2, &odd_amount).clone();
        let wallet2_json = wallet2.to_json();

        let mut wallet_2 = wallet::wallet::Wallet::from_json(
            wallet2_json,
            ClientShim::new("http://localhost:8000".to_string(), None, None),
            ClientShim::new("http://localhost:8000".to_string(), None, None),
        )
        .unwrap();

        let register_try_2 = state_entity::conductor::swap_register_utxo(
            &mut wallet_2,
            &deposit2.1,
            &num_state_chains,
        );

        match register_try_2 {
            Err(e) => assert!(e
                .to_string()
                .contains("Invalid coin amount for swap registration")),
            _ => assert!(false),
        }

        reset_data(&wallet1.client_shim).unwrap();
        reset_data(&wallet2.client_shim).unwrap();
    }

    #[test]
    #[serial]
    fn test_swap_seperate_conductor() {
        let merc_port: u16 = 8000;
        let conductor_port: u16 = 8001;
        let _handle = start_server(Some(merc_port), Some(String::from("core")));
        let _conductor_handle = start_server(Some(conductor_port), Some(String::from("conductor")));

        let num_state_chains: u64 = 3;
        let amount: u64 = 100000; // = u64::from_str(&format!("10000")).unwrap();

        // Gen some wallets and deposit coins into SCE
        let mut wallets = vec![];
        let mut deposits = vec![];
        let mut thread_handles = vec![];
        let mut wallet_sers = vec![];

        for i in 0..num_state_chains as usize {
            wallets.push(gen_wallet(Some(conductor_port)));
            for _ in 0..i {
                // Gen keys so different wallets have different proof keys (since wallets have the same seed)
                let _ = wallets[i].se_proof_keys.get_new_key();
            }

            deposits.push(run_deposit(&mut wallets[i], &amount));
            let deposit = deposits.last().unwrap().clone();

            let (_shared_key_ids, _wallet_sc_ids, _bals, _locktimes) =
                wallets.last().unwrap().get_state_chains_info().unwrap();

            wallet_sers.push((wallets.last().unwrap().to_json(), deposit.1));
        }

        println!("Starting swaps...");
        let start = Instant::now();
        for (wallet_ser, deposit) in wallet_sers {
            thread_handles.push(spawn(move || {
                let mut wallet = wallet::wallet::Wallet::from_json(
                    wallet_ser,
                    ClientShim::new(format!("http://localhost:{}", merc_port), None, None),
                    ClientShim::new(format!("http://localhost:{}", conductor_port), None, None),
                )?;

                state_entity::conductor::do_swap(&mut wallet, &deposit, &num_state_chains, false)
            }))
        }

        let mut i = 0;
        for handle in thread_handles {
            handle.join().unwrap().unwrap();
            i = i + 1;
        }
        println!("(Swaps Took: {})", TimeFormat(start.elapsed()));
        reset_data(&wallets[0].client_shim).unwrap();
    }
}
