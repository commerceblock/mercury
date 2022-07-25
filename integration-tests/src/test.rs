#[cfg(test)]
#[cfg(not(feature = "mockdb"))]
mod tests {
    use crate::*;
    extern crate bitcoin;
    extern crate client_lib;
    extern crate server_lib;
    extern crate shared_lib;
    extern crate time_test;
    extern crate sha3;
    extern crate digest;
    extern crate hex;

    use shared_lib::structs::Protocol;

    use curv::elliptic::curves::traits::ECScalar;
    use curv::FE;
    use self::time_test::time_test;
    use shared_lib::util::{transaction_deserialise, FEE};
    use self::sha3::Sha3_256;
    use self::digest::Digest;

    #[test]
    #[serial]
    fn test_gen_shared_key() {
        time_test!();
        let _ = start_server(None, None);
        let mut wallet = gen_wallet(None);
        let proof_key = wallet.se_proof_keys.get_new_key().unwrap();
        let init_res =
            client_lib::state_entity::deposit::session_init(&mut wallet, &proof_key.to_string());
        assert!(init_res.is_ok());

        // generate solution for the VDF challenge
        let challenge = match init_res.clone().unwrap().challenge {
            Some(c) => c,
            None => return,
        };

        let difficulty = 4 as usize;
        let mut counter = 0;
        let zeros = String::from_utf8(vec![b'0'; difficulty]).unwrap();
        let mut hasher = Sha3_256::new();
        loop {
            hasher.input(&format!("{}:{:x}", challenge, counter).as_bytes());
            let result = hex::encode(hasher.result_reset());
            if result[..difficulty] == zeros {
                break;
            };
            counter += 1
        }

        let solution = format!("{:x}", counter);

        let key_res = wallet.gen_shared_key(&init_res.unwrap().id, &1000, solution.to_string());
        assert!(key_res.is_ok());
        reset_data(&wallet.client_shim).unwrap();
    }

    #[test]
    #[serial]
    fn test_gen_shared_key_repeat_keygen() {
        time_test!();
        let _ = start_server(None, None);
        let mut wallet = gen_wallet(None);
        let proof_key = wallet.se_proof_keys.get_new_key().unwrap();
        let init_res =
            client_lib::state_entity::deposit::session_init(&mut wallet, &proof_key.to_string());
        assert!(init_res.is_ok());

        // generate solution for the VDF challenge
        let challenge = match init_res.clone().unwrap().challenge {
            Some(c) => c,
            None => return,
        };

        let difficulty = 4 as usize;
        let mut counter = 0;
        let zeros = String::from_utf8(vec![b'0'; difficulty]).unwrap();
        let mut hasher = Sha3_256::new();
        loop {
            hasher.input(&format!("{}:{:x}", challenge, counter).as_bytes());
            let result = hex::encode(hasher.result_reset());
            if result[..difficulty] == zeros {
                break;
            };
            counter += 1
        }

        let solution = format!("{:x}", counter);

        let key_res = wallet.gen_shared_key_repeat_keygen(&init_res.unwrap().id, &1000, solution.to_string(), 10);
        assert!(key_res.is_ok());
        reset_data(&wallet.client_shim).unwrap();
    }

    #[test]
    #[serial]
    fn test_failed_auth() {
        time_test!();
        let _handle = start_server(None, None);
        let client_shim = ClientShim::new("http://localhost:8000".to_string(), None, None);
        let secret_key: FE = ECScalar::new_random();
        let invalid_key = Uuid::new_v4();
        let err = ecdsa::get_master_key(
            &invalid_key,

           &client_shim,
            &secret_key,

           &1000,
            Protocol::Deposit,
            "".to_string(),
        );
        assert!(err.is_err());
        reset_data(&client_shim).unwrap();
    }

    #[test]
    #[serial]
    fn test_deposit() {
        time_test!();
        let _handle = start_server(None, None);
        let wallet = gen_wallet_with_deposit(100000);
        //handle.join().expect("The thread being joined has panicked");
        let state_chains_info = wallet.get_state_chains_info().unwrap();
        let (_, funding_txid, proof_key, _, _) = wallet
            .get_shared_key_info(state_chains_info.0.last().unwrap())
            .unwrap();

        // Get SMT inclusion proof and verify
        let root = state_entity::api::get_smt_root(&wallet.client_shim)
            .unwrap()
            .unwrap();
        let proof =
            state_entity::api::get_smt_proof(&wallet.client_shim, &root, &funding_txid).unwrap();

        // ensure wallet's shared key is updated with proof info
        let shared_key = wallet
            .get_shared_key(state_chains_info.0.last().unwrap())
            .unwrap();
        assert_eq!(shared_key.smt_proof.clone().unwrap().root, root);
        assert_eq!(shared_key.smt_proof.clone().unwrap().proof, proof);
        assert_eq!(shared_key.proof_key.clone().unwrap(), proof_key);

        let _d = state_entity::conductor::swap_register_utxo(&wallet, &wallet.shared_keys[0].statechain_id.clone().unwrap(), &5);

        let coins = state_entity::api::get_coins_info(&wallet.client_shim).unwrap();

        assert_eq!(coins.values.get(&100000).unwrap().get(),1);

        println!("Shared wallet id: {:?} ", funding_txid);
        println!("Funding txid: {:?} ", funding_txid);

        //Confirm in-ram data recovery from database
        reset_inram_data(&wallet.client_shim).unwrap();
        let coins = state_entity::api::get_coins_info(&wallet.client_shim).unwrap();
        assert_eq!(coins.values.get(&100000).unwrap().get(),1);
        //Reset data
        reset_data(&wallet.client_shim).unwrap();
    }

    // #[test]
    // #[serial]
    // fn test_confirm_proofs() {
    //     let _ = spawn_server();
    //     let mut wallet = gen_wallet_with_deposit(10000);
    //
    //     let unconfirmed = run_confirm_proofs(&mut wallet);
    //
    //     assert!(unconfirmed.len() == 1, "expected 1 unconfirmed shared key");
    // }

    #[test]
    #[serial]
    fn test_get_statechain() {
        time_test!();
        let _handle = start_server(None, None);
        let mut wallet = gen_wallet(None);

        let err = state_entity::api::get_statechain(&wallet.client_shim, &Uuid::new_v4());
        assert!(err.is_err());
        let deposit = run_deposit(&mut wallet, &10000);

        let state_chain =
            state_entity::api::get_statechain(&wallet.client_shim, &deposit.1.clone()).unwrap();
        assert_eq!(
            state_chain.get_tip().unwrap().data,
            deposit.5.to_string()
        );
        reset_data(&wallet.client_shim).unwrap();
    }

      #[test]
    #[serial]
    fn test_get_statechain_depth() {
        time_test!();
        let _handle = start_server(None, None);
        let mut wallet = gen_wallet(None);

        let err = state_entity::api::get_statechain_depth(&wallet.client_shim, &Uuid::new_v4(),&1);
        assert!(err.is_err());
        let deposit = run_deposit(&mut wallet, &10000);

        let state_chain =
            state_entity::api::get_statechain_depth(&wallet.client_shim, &deposit.1.clone(),&1).unwrap();
        assert_eq!(
            state_chain.get_tip().unwrap().data,
            deposit.5.to_string()
        );
        reset_data(&wallet.client_shim).unwrap();
    }

    #[test]
    #[serial]
    fn test_get_statecoin() {
        time_test!();
        let _handle = start_server(None, None);
        let mut wallet = gen_wallet(None);

        let err = state_entity::api::get_statecoin(&wallet.client_shim, &Uuid::new_v4());
        assert!(err.is_err());
        let deposit = run_deposit(&mut wallet, &10000);

        let state_coin =
            state_entity::api::get_statecoin(&wallet.client_shim, &deposit.1.clone()).unwrap();
        assert_eq!(
            state_coin.statecoin.data,
            deposit.5.to_string()
        );
        reset_data(&wallet.client_shim).unwrap();
    }

    #[test]
    #[serial]
    fn test_transfer() {
        time_test!();
        let _handle = start_server(None, None);
        let mut wallets = vec![];
        wallets.push(gen_wallet_with_deposit(10000)); // sender
        wallets.push(gen_wallet(None)); // receiver

        // Get state chain owned by wallet
        let state_chains_info = wallets[0].get_state_chains_info().unwrap();
        let shared_key_id = state_chains_info.0.last().unwrap();
        let (statechain_id, funding_txid, _, _, _) =
            wallets[0].get_shared_key_info(shared_key_id).unwrap();

        let receiver_addr = wallets[1]
            .get_new_state_entity_address()
            .unwrap();

        let new_shared_key_id = run_transfer(&mut wallets, 0, 1, &receiver_addr, &statechain_id);

        // check shared keys have the same master public key
        assert_eq!(
            wallets[0]
                .get_shared_key(shared_key_id)
                .unwrap()
                .share
                .public
                .q,
            wallets[1]
                .get_shared_key(&new_shared_key_id)
                .unwrap()
                .share
                .public
                .q
        );

        // check shared key is marked spent in sender and unspent in receiver
        assert!(!wallets[0].get_shared_key(shared_key_id).unwrap().unspent);
        assert!(
            wallets[1]
                .get_shared_key(&new_shared_key_id)
                .unwrap()
                .unspent
        );

        // check state chain is updated
        let state_chain =
            state_entity::api::get_statechain(&wallets[0].client_shim, &statechain_id).unwrap();
        assert_eq!(state_chain.chain.len(), 2);
        assert_eq!(
            state_chain.get_tip().unwrap().data.to_string(),
            receiver_addr.proof_key.to_string()
        );

        // Get SMT inclusion proof and verify
        let root = state_entity::api::get_smt_root(&wallets[1].client_shim)
            .unwrap()
            .unwrap();
        let proof = state_entity::api::get_smt_proof(&wallets[1].client_shim, &root, &funding_txid)
            .unwrap();
        // Ensure wallet's shared key is updated with proof info
        let shared_key = wallets[1].get_shared_key(&new_shared_key_id).unwrap();
        assert_eq!(shared_key.smt_proof.clone().unwrap().root, root);
        assert_eq!(shared_key.smt_proof.clone().unwrap().proof, proof);
        assert_eq!(
            shared_key.proof_key.clone().unwrap(),
            receiver_addr.proof_key.to_string()
        );
        reset_data(&wallets[0].client_shim).unwrap();
    }

    #[test]
    #[serial]
    fn test_transfer_repeat_keygen() {
        time_test!();
        let _handle = start_server(None, None);
        let mut wallets = vec![];
        wallets.push(gen_wallet_with_deposit(10000)); // sender
        wallets.push(gen_wallet(None)); // receiver

        // Get state chain owned by wallet
        let state_chains_info = wallets[0].get_state_chains_info().unwrap();
        let shared_key_id = state_chains_info.0.last().unwrap();
        let (statechain_id, funding_txid, _, _, _) =
            wallets[0].get_shared_key_info(shared_key_id).unwrap();

        let receiver_addr = wallets[1]
            .get_new_state_entity_address()
            .unwrap();

        let new_shared_key_id = run_transfer_repeat_keygen(&mut wallets, 0, 1, &receiver_addr, &statechain_id, 10);

        // check shared keys have the same master public key
        assert_eq!(
            wallets[0]
                .get_shared_key(shared_key_id)
                .unwrap()
                .share
                .public
                .q,
            wallets[1]
                .get_shared_key(&new_shared_key_id)
                .unwrap()
                .share
                .public
                .q
        );

        // check shared key is marked spent in sender and unspent in receiver
        assert!(!wallets[0].get_shared_key(shared_key_id).unwrap().unspent);
        assert!(
            wallets[1]
                .get_shared_key(&new_shared_key_id)
                .unwrap()
                .unspent
        );

        // check state chain is updated
        let state_chain =
            state_entity::api::get_statechain(&wallets[0].client_shim, &statechain_id).unwrap();
        assert_eq!(state_chain.chain.len(), 2);
        assert_eq!(
            state_chain.get_tip().unwrap().data.to_string(),
            receiver_addr.proof_key.to_string()
        );

        // Get SMT inclusion proof and verify
        let root = state_entity::api::get_smt_root(&wallets[1].client_shim)
            .unwrap()
            .unwrap();
        let proof = state_entity::api::get_smt_proof(&wallets[1].client_shim, &root, &funding_txid)
            .unwrap();
        // Ensure wallet's shared key is updated with proof info
        let shared_key = wallets[1].get_shared_key(&new_shared_key_id).unwrap();
        assert_eq!(shared_key.smt_proof.clone().unwrap().root, root);
        assert_eq!(shared_key.smt_proof.clone().unwrap().proof, proof);
        assert_eq!(
            shared_key.proof_key.clone().unwrap(),
            receiver_addr.proof_key.to_string()
        );
        reset_data(&wallets[0].client_shim).unwrap();
    }

    #[test]
    #[serial]
    fn test_transfer_decrement() {
        time_test!();
        let _handle = start_server(None, None);
        let mut wallets = vec![];
        wallets.push(gen_wallet_with_deposit(10000)); // sender
        wallets.push(gen_wallet(None)); // receiver

        let fee_info = state_entity::api::get_statechain_fee_info(&wallets[0].client_shim).unwrap();

        println!("{:?}", fee_info);

        // Get state chain owned by wallet
        let state_chains_info = wallets[0].get_state_chains_info().unwrap();
        let shared_key_id = state_chains_info.0.last().unwrap();
        let (statechain_id, funding_txid, _, _, _) =
            wallets[0].get_shared_key_info(shared_key_id).unwrap();

        let receiver_addr = wallets[1]
            .get_new_state_entity_address()
            .unwrap();

        let init_locktime = state_chains_info.3.last().unwrap();

        // do transfer sender
        let tranfer_sender_resp = state_entity::transfer::transfer_sender(
            &mut wallets[0],
            &statechain_id,
            receiver_addr.clone(),
            None
        )
        .unwrap();

        let backup_tx = transaction_deserialise(&tranfer_sender_resp.tx_backup_psm.tx_hex).unwrap();

        assert_eq!(backup_tx.lock_time, init_locktime - fee_info.interval);

        // do transfer sender again on the same coin
        // do transfer sender
        let mut tranfer_sender_resp_2 = state_entity::transfer::transfer_sender(
            &mut wallets[0],
            &statechain_id,
            receiver_addr.clone(),
            None
        )
        .unwrap();

        let new_backup_tx = transaction_deserialise(&tranfer_sender_resp_2.tx_backup_psm.tx_hex).unwrap();

        assert_eq!(new_backup_tx.lock_time, backup_tx.lock_time - fee_info.interval);

        let tfd = state_entity::transfer::transfer_receiver(
            &mut wallets[1],
            &mut tranfer_sender_resp_2,
            &None,
        )
        .unwrap();
        let new_shared_key_id = tfd.new_shared_key_id;

        // check shared keys have the same master public key
        assert_eq!(
            wallets[0]
                .get_shared_key(shared_key_id)
                .unwrap()
                .share
                .public
                .q,
            wallets[1]
                .get_shared_key(&new_shared_key_id)
                .unwrap()
                .share
                .public
                .q
        );

        // check shared key is marked spent in sender and unspent in receiver
        assert!(!wallets[0].get_shared_key(shared_key_id).unwrap().unspent);
        assert!(
            wallets[1]
                .get_shared_key(&new_shared_key_id)
                .unwrap()
                .unspent
        );

        // check state chain is updated
        let state_chain =
            state_entity::api::get_statechain(&wallets[0].client_shim, &statechain_id).unwrap();
        assert_eq!(state_chain.chain.len(), 2);
        assert_eq!(
            state_chain.get_tip().unwrap().data.to_string(),
            receiver_addr.proof_key.to_string()
        );

        // Get SMT inclusion proof and verify
        let root = state_entity::api::get_smt_root(&wallets[1].client_shim)
            .unwrap()
            .unwrap();
        let proof = state_entity::api::get_smt_proof(&wallets[1].client_shim, &root, &funding_txid)
            .unwrap();
        // Ensure wallet's shared key is updated with proof info
        let shared_key = wallets[1].get_shared_key(&new_shared_key_id).unwrap();
        assert_eq!(shared_key.smt_proof.clone().unwrap().root, root);
        assert_eq!(shared_key.smt_proof.clone().unwrap().proof, proof);
        assert_eq!(
            shared_key.proof_key.clone().unwrap(),
            receiver_addr.proof_key.to_string()
        );
        reset_data(&wallets[0].client_shim).unwrap();
    }

    #[test]
    #[serial]
    fn test_double_transfer() {
        time_test!();
        let _handle = start_server(None, None);
        let mut wallets = vec![];
        wallets.push(gen_wallet_with_deposit(10000)); // sender
        wallets.push(gen_wallet(None)); // receiver1
        wallets.push(gen_wallet(None)); // receiver2

        // Get state chain owned by wallets[0] info
        let state_chains_info = wallets[0].get_state_chains_info().unwrap();
        assert_eq!(state_chains_info.0.len(), 1);
        let statechain_id = state_chains_info.1.last().unwrap();
        let funding_txid: String;
        let shared_key_id0: Uuid;
        {
            let shared_key = wallets[0]
                .get_shared_key_by_statechain_id(statechain_id)
                .unwrap();
            funding_txid = shared_key.funding_txid.to_owned();
            shared_key_id0 = shared_key.id.to_owned();
        }

        // Transfer 1
        let receiver1_addr = wallets[1]
            .get_new_state_entity_address()
            .unwrap();

        let new_shared_key_id1 = run_transfer(&mut wallets, 0, 1, &receiver1_addr, statechain_id);

        // Get state chain owned by wallets[1]
        let state_chains_info = wallets[0].get_state_chains_info().unwrap();
        assert_eq!(state_chains_info.0.len(), 0);

        let state_chains_info = wallets[1].get_state_chains_info().unwrap();
        assert_eq!(state_chains_info.0.len(), 1);

        let shared_key_id1 = state_chains_info.0.last().unwrap();
        assert_eq!(new_shared_key_id1, shared_key_id1.to_owned());

        let funding_txid1: String;
        let statechain_id1: Uuid;
        {
            let shared_key = wallets[1]
                .get_shared_key_by_statechain_id(statechain_id)
                .unwrap();
            funding_txid1 = shared_key.funding_txid.to_owned();
            statechain_id1 = shared_key.statechain_id.unwrap().to_owned();
        }
        // Should not have changed
        assert_eq!(statechain_id.to_string(), statechain_id1.to_string());
        assert_eq!(funding_txid, funding_txid1);

        // Transfer 2
        let receiver2_addr = wallets[2]
            .get_new_state_entity_address()
            .unwrap();

        let new_shared_key_id2 = run_transfer(&mut wallets, 1, 2, &receiver2_addr, statechain_id);

        // check shared keys have the same master public key
        assert_eq!(
            wallets[0]
                .get_shared_key(&shared_key_id0)
                .unwrap()
                .share
                .public
                .q,
            wallets[1]
                .get_shared_key(shared_key_id1)
                .unwrap()
                .share
                .public
                .q
        );
        assert_eq!(
            wallets[1]
                .get_shared_key(shared_key_id1)
                .unwrap()
                .share
                .public
                .q,
            wallets[2]
                .get_shared_key(&new_shared_key_id2)
                .unwrap()
                .share
                .public
                .q
        );

        // check shared key is marked spent in wallets 0, 1 and unspent in 2
        assert!(!wallets[0].get_shared_key(&shared_key_id0).unwrap().unspent);
        assert!(!wallets[1].get_shared_key(shared_key_id1).unwrap().unspent);
        assert!(
            wallets[2]
                .get_shared_key(&new_shared_key_id2)
                .unwrap()
                .unspent
        );

        // check state chain is updated
        let state_chain =
            state_entity::api::get_statechain(&wallets[0].client_shim, &statechain_id1).unwrap();
        assert_eq!(state_chain.chain.len(), 3);
        assert_eq!(
            state_chain.chain.get(1).unwrap().data.to_string(),
            receiver1_addr.proof_key.to_string()
        );
        assert_eq!(
            state_chain.get_tip().unwrap().data.to_string(),
            receiver2_addr.proof_key.to_string()
        );

        // Get SMT inclusion proof and verify
        let root = state_entity::api::get_smt_root(&wallets[1].client_shim)
            .unwrap()
            .unwrap();
        let proof = state_entity::api::get_smt_proof(&wallets[1].client_shim, &root, &funding_txid)
            .unwrap();
        // Ensure wallet's shared key is updated with proof info
        let shared_key = wallets[2].get_shared_key(&new_shared_key_id2).unwrap();
        assert_eq!(shared_key.smt_proof.clone().unwrap().root, root);
        assert_eq!(shared_key.smt_proof.clone().unwrap().proof, proof);
        assert_eq!(
            shared_key.proof_key.clone().unwrap(),
            receiver2_addr.proof_key.to_string()
        );
        reset_data(&wallets[0].client_shim).unwrap();
    }

    #[test]
    #[serial]
    fn test_withdraw() {
        time_test!();
        let _handle = start_server(None, None);
        let mut wallet = gen_wallet(None);

        let deposit_resp = run_deposit(&mut wallet, &10000);
        let shared_key_id = &deposit_resp.0;
        let statechain_id = &deposit_resp.1;

        assert!(wallet.get_shared_key(shared_key_id).unwrap().unspent);
        assert!(
            wallet
                .get_shared_key_by_statechain_id(statechain_id)
                .unwrap()
                .unspent
        );

        // Try withdraw wrong key
        assert!(state_entity::withdraw::withdraw(&mut wallet, &Uuid::new_v4(), &FEE).is_err());

        // Check withdraw method completes without Err

        println!("running withdraw...");
        run_withdraw(&mut wallet, statechain_id);
        println!("withdraw complete.");
        
        // Check marked spent in wallet
        assert!(!wallet.get_shared_key(shared_key_id).unwrap().unspent);

        // Check state chain is updated
        let state_chain =
            state_entity::api::get_statechain(&wallet.client_shim, statechain_id).unwrap();
        assert_eq!(state_chain.chain.len(), 2);

        // Check chain data is address
        assert!(state_chain
            .chain
            .last()
            .unwrap()
            .data
            .contains(&String::from("bcrt")));
        // Check purpose of state chain signature
        assert_eq!(
            state_chain
                .chain
                .get(0)
                .unwrap()
                .next_state
                .clone()
                .unwrap()
                .purpose,
            String::from("WITHDRAW")
        );

        // Try again after funds already withdrawn
        let err = state_entity::withdraw::withdraw(&mut wallet, shared_key_id, &FEE);
        assert!(err.is_err());
        reset_data(&wallet.client_shim).unwrap();
    }
    
    
    #[test]
    #[serial]
    fn test_withdraw_rbf() {
        time_test!();
        let _handle = start_server(None, None);
        let mut wallet = gen_wallet(None);

        let deposit_resp = run_deposit(&mut wallet, &10000);
        let shared_key_id = &deposit_resp.0;
        let statechain_id = &deposit_resp.1;

        assert!(wallet.get_shared_key(shared_key_id).unwrap().unspent);
        assert!(
            wallet
                .get_shared_key_by_statechain_id(statechain_id)
                .unwrap()
                .unspent
        );

        
        // Check withdraw method completes without Err
        run_withdraw_init(&mut wallet, statechain_id, &(FEE-3));


        let receiver_addr = wallet
        .get_new_state_entity_address()
        .unwrap();

        //Confirm that transfer can not take place after withdraw init
        let send_result = state_entity::transfer::transfer_sender(
            &mut wallet,
            statechain_id,
            receiver_addr.clone(),
            None
        );
        assert!(send_result.is_err() && format!("{:?}",send_result)
        .contains("is signed for withdrawal"));

        //Withdraw 
        run_withdraw_init(&mut wallet, statechain_id, &(FEE-2));

        //replace by fee
        run_withdraw_init(&mut wallet, statechain_id, &(FEE-1));
        
        let (sk_id, _address, tx_signed, _amount) = run_withdraw_init(&mut wallet, statechain_id, &(FEE));
        let _tx_id = run_withdraw_confirm(&mut wallet, &sk_id, &tx_signed);

        // Check marked spent in wallet
        let sk1 = wallet.get_shared_key(&shared_key_id).unwrap();
        assert!(!sk1.unspent);
        assert_eq!(&sk1.statechain_id.unwrap(), statechain_id);
        dbg!(&statechain_id);
        // Check state chain is updated
        let state_chain =
            state_entity::api::get_statechain(&wallet.client_shim, statechain_id).unwrap();
        assert_eq!(state_chain.chain.len(), 2);
        
        // Check chain data is address
        assert!(state_chain
            .chain
            .last()
            .unwrap()
            .data
            .contains(&String::from("bcrt")));
        // Check purpose of state chain signature
        assert_eq!(
            state_chain
                .chain
                .get(0)
                .unwrap()
                .next_state
                .clone()
                .unwrap()
                .purpose,
            String::from("WITHDRAW")
        );

        // Try again after funds already withdrawn
        let err = state_entity::withdraw::withdraw(&mut wallet, shared_key_id, &FEE);
        assert!(err.is_err());
        reset_data(&wallet.client_shim).unwrap();
    }


    #[test]
    #[serial]
    fn test_batch_withdraw() {
        time_test!();
        let _handle = start_server(None, None);
        let mut wallet = gen_wallet(None);

        let n_inputs = 3;
        
        let mut shared_key_id = vec![];
        let mut statechain_id = vec![];

        for _ in 0..n_inputs {
            let deposit_resp = run_deposit(&mut wallet, &10000);
            shared_key_id.push(deposit_resp.0);
            statechain_id.push(deposit_resp.1);
            
            assert!(wallet.get_shared_key(shared_key_id.last().unwrap()).unwrap().unspent);
            assert!(
                wallet
                .get_shared_key_by_statechain_id(statechain_id.last().unwrap())
                .unwrap()
                .unspent
            );
        }

        let wrong_scid_vec = vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
        // Try withdraw wrong key
        assert!(state_entity::withdraw::batch_withdraw(&mut wallet, &wrong_scid_vec, &FEE).is_err());

        // Check withdraw method completes without Err
        run_batch_withdraw(&mut wallet, &statechain_id);

        // Check marked spent in wallet
        for (i, sk_id) in shared_key_id.iter().enumerate(){
            let sc_id = &statechain_id[i];
            assert!(!wallet.get_shared_key(sk_id).unwrap().unspent,"key number {} is unspent", i);
                
            // Check state chain is updated
            let state_chain =
                state_entity::api::get_statechain(&wallet.client_shim, sc_id).unwrap();
            assert_eq!(state_chain.chain.len(), 2);

            // Check chain data is address
            assert!(state_chain
                .chain
                .last()
                .unwrap()
                .data
                .contains(&String::from("bcrt")));
            // Check purpose of state chain signature
            assert_eq!(
                state_chain
                    .chain
                    .get(0)
                    .unwrap()
                    .next_state
                    .clone()
                    .unwrap()
                    .purpose,
                String::from("WITHDRAW")
            );

            // Try again after funds already withdrawn
            let err = state_entity::withdraw::withdraw(&mut wallet, sk_id, &FEE);
            assert!(err.is_err());
        }
        reset_data(&wallet.client_shim).unwrap();
    }

    #[test]
    #[serial]
    /// Test wallet load from json correctly when shared key present.
    fn test_wallet_load_with_shared_key() {
        time_test!();
        let _handle = start_server(None, None);

        let mut wallet = gen_wallet(None);
        run_deposit(&mut wallet, &10000);

        let wallet_json = wallet.to_json();
        let wallet_rebuilt = wallet::wallet::Wallet::from_json(
            wallet_json,
            ClientShim::new("http://localhost:8000".to_string(), None, None),
            ClientShim::new("http://localhost:8000".to_string(), None, None),
        )
        .unwrap();

        let shared_key = wallet.shared_keys.get(0).unwrap();
        let shared_key_rebuilt = wallet_rebuilt.shared_keys.get(0).unwrap();

        assert_eq!(shared_key.id, shared_key_rebuilt.id);
        assert_eq!(shared_key.share.public, shared_key_rebuilt.share.public);
        assert_eq!(shared_key.proof_key, shared_key_rebuilt.proof_key);
        assert_eq!(
            shared_key.smt_proof.clone().unwrap().root,
            shared_key_rebuilt.smt_proof.clone().unwrap().root
        );
        assert_eq!(
            shared_key.smt_proof.clone().unwrap().proof,
            shared_key_rebuilt.smt_proof.clone().unwrap().proof
        );
        reset_data(&wallet.client_shim).unwrap();
    }

}

#[cfg(feature = "mockdb")]
#[cfg(test)]
mod tests {
    use crate::*;
    extern crate bitcoin;
    extern crate client_lib;
    extern crate server_lib;
    extern crate shared_lib;

    use mockito::mock;
    use server_lib::MockDatabase;
    use shared_lib::mainstay;

    #[test]
    //This test starts a rocket server so is ignored by default
    //If this test is run, the 'accept incoming connection dialog' can be ignored, or click 'Deny'
    #[ignore]
    #[serial]
    fn test_get_statechain() {
        let mockito_server_url = mockito::server_url();
        let _m = mock("GET", "/ping").create();
        let mainstay_config = mainstay::MainstayConfig::mock_from_url(&mockito_server_url);
        let mut db = MockDatabase::new();
        let wallet = gen_wallet(None);
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_reset().returning(|| Ok(()));
        let invalid_scid = Uuid::new_v4();
        db.expect_get_statechain_amount().returning(|_x| {
            Err(server_lib::error::SEError::DBError(
                server_lib::error::DBErrorType::NoDataForID,
                "".to_string(),
            ))
        });
        db.expect_create_user_session()
            .returning(|_user_id, _auth, _proof_key, _challenge, _user_ids| Ok(()));
        db.expect_get_user_auth()
            .returning(|_user_id| Ok(String::from("user_auth")));
        db.expect_init_ecdsa()
            .returning(|_user_id| Ok(0));
        db.expect_update_keygen_first_msg()
            .returning(|_user_id, _fm| Ok(()));
            //Key generation not completed for this ID yet
        db.expect_get_ecdsa_master().returning(|_user_id| Ok(None));
        db.expect_update_keygen_first_msg_and_witness()
            .returning(|_user_id, _fm, _cw, _ec_kp| Ok(()));
        
        let (_key_gen_first_msg, comm_witness, ec_key_pair) =
            server_lib::protocol::ecdsa::MasterKey1::key_gen_first_message();

        db.expect_get_ecdsa_witness_keypair()
            .returning(move |_user_id| Ok((comm_witness.clone(), ec_key_pair.clone())));

        db.expect_update_keygen_second_msg()
            .returning(|_, _, _, _| Ok(()));

        let _handle = db.spawn_server(Some(mainstay_config), None, None);

        let err = state_entity::api::get_statechain(&wallet.client_shim, &invalid_scid);
        assert!(err.is_err());
        reset_data(&wallet.client_shim).unwrap();
    }

}
