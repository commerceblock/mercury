#[cfg(test)]
mod tests {
    use crate::*;
    extern crate bitcoin;
    extern crate client_lib;
    extern crate server_lib;
    extern crate shared_lib;

    use shared_lib::{mocks::mock_electrum::MockElectrum, structs::Protocol};
    use shared_lib::mainstay;

    use curv::elliptic::curves::traits::ECScalar;
    use curv::FE;

    use mockito;

    #[test]
    #[serial]
    fn test_gen_shared_key() {
        let mainstay_config = mainstay::Config::mock_from_url(&mockito::server_url());
        let _ = spawn_server(Some(mainstay_config));

        let mut wallet = gen_wallet();
        let proof_key = wallet.se_proof_keys.get_new_key().unwrap();
        let init_res =
            client_lib::state_entity::deposit::session_init(&mut wallet, &proof_key.to_string());
        assert!(init_res.is_ok());
        let key_res = wallet.gen_shared_key(&init_res.unwrap(), &1000);
        assert!(key_res.is_ok());
    }

    #[test]
    #[serial]
    fn test_failed_auth() {
        let mainstay_config = mainstay::Config::mock_from_url(&mockito::server_url());
        let _ = spawn_server(Some(mainstay_config));
        let client_shim = ClientShim::new("http://localhost:8000".to_string(), None);
        let secret_key: FE = ECScalar::new_random();
        let invalid_key = Uuid::new_v4();
        let err = ecdsa::get_master_key(
            &invalid_key,
            &client_shim,
            &secret_key,
            &1000,
            Protocol::Deposit,
        );
        assert!(err.is_err());
    }

    #[test]
    #[serial]
    fn test_deposit() {
        let mainstay_config = mainstay::Config::mock_from_url(&mockito::server_url());
        let _ = spawn_server(Some(mainstay_config));
        let wallet = gen_wallet_with_deposit(10000);

        let state_chains_info = wallet.get_state_chains_info();
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

        println!("Shared wallet id: {:?} ", funding_txid);
        println!("Funding txid: {:?} ", funding_txid);
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
        let mainstay_config = mainstay::Config::mock_from_url(&mockito::server_url());
        let _ = spawn_server(Some(mainstay_config));
        let mut wallet = gen_wallet();

        let err = state_entity::api::get_statechain(&wallet.client_shim, &Uuid::new_v4());
        assert!(err.is_err());
        let deposit = run_deposit(&mut wallet, &10000);

        let state_chain =
            state_entity::api::get_statechain(&wallet.client_shim, &deposit.1.clone()).unwrap();
        assert_eq!(
            state_chain.chain.last().unwrap().data,
            deposit.5.to_string()
        );
    }

    #[test]
    #[serial]
    fn test_transfer() {
        let mainstay_config = mainstay::Config::mock_from_url(&mockito::server_url());
        let _ = spawn_server(Some(mainstay_config));
        let mut wallets = vec![];
        wallets.push(gen_wallet_with_deposit(10000)); // sender
        wallets.push(gen_wallet()); // receiver

        // Get state chain owned by wallet
        let state_chains_info = wallets[0].get_state_chains_info();
        let shared_key_id = state_chains_info.0.last().unwrap();
        let (state_chain_id, funding_txid, _, _, _) =
            wallets[0].get_shared_key_info(shared_key_id).unwrap();

        let receiver_addr = wallets[1]
            .get_new_state_entity_address(&funding_txid)
            .unwrap();

        let new_shared_key_id = run_transfer(&mut wallets, 0, 1, &state_chain_id);

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
            state_entity::api::get_statechain(&wallets[0].client_shim, &state_chain_id).unwrap();
        assert_eq!(state_chain.chain.len(), 2);
        assert_eq!(
            state_chain.chain.last().unwrap().data.to_string(),
            receiver_addr.proof_key.to_string()
        );

        // Get SMT inclusion proof and verify
        let root = state_entity::api::get_smt_root(&wallets[1].client_shim)
            .unwrap()
            .unwrap();
        let proof = state_entity::api::get_smt_proof(&wallets[1].client_shim, &root, &funding_txid)
            .unwrap();
        // Ensure wallet's shared key is updated with proof info
        println!("ensure wallet's sC is updated with proof info");
        let shared_key = wallets[1].get_shared_key(&new_shared_key_id).unwrap();
        assert_eq!(shared_key.smt_proof.clone().unwrap().root, root);
        assert_eq!(shared_key.smt_proof.clone().unwrap().proof, proof);
        assert_eq!(
            shared_key.proof_key.clone().unwrap(),
            receiver_addr.proof_key
        );
        println!("end");
    }

    #[test]
    #[serial]
    fn test_double_transfer() {
        let mainstay_config = mainstay::Config::mock_from_url(&mockito::server_url());
        let _ = spawn_server(Some(mainstay_config));
        let mut wallets = vec![];
        wallets.push(gen_wallet_with_deposit(10000)); // sender
        wallets.push(gen_wallet()); // receiver1
        wallets.push(gen_wallet()); // receiver2

        // Get state chain owned by wallets[0] info
        let state_chains_info = wallets[0].get_state_chains_info();
        assert_eq!(state_chains_info.0.len(), 1);
        let state_chain_id = state_chains_info.1.last().unwrap();
        let funding_txid: String;
        let shared_key_id0: Uuid;
        {
            let shared_key = wallets[0]
                .get_shared_key_by_state_chain_id(state_chain_id)
                .unwrap();
            funding_txid = shared_key.funding_txid.to_owned();
            shared_key_id0 = shared_key.id.to_owned();
        }

        // Transfer 1
        let receiver1_addr = wallets[1]
            .get_new_state_entity_address(&funding_txid)
            .unwrap();

        let new_shared_key_id1 = run_transfer(&mut wallets, 0, 1, state_chain_id);

        // Get state chain owned by wallets[1]
        let state_chains_info = wallets[0].get_state_chains_info();
        assert_eq!(state_chains_info.0.len(), 0);

        let state_chains_info = wallets[1].get_state_chains_info();
        assert_eq!(state_chains_info.0.len(), 1);

        let shared_key_id1 = state_chains_info.0.last().unwrap();
        assert_eq!(new_shared_key_id1, shared_key_id1.to_owned());

        let funding_txid1: String;
        let state_chain_id1: Uuid;
        {
            let shared_key = wallets[1]
                .get_shared_key_by_state_chain_id(state_chain_id)
                .unwrap();
            funding_txid1 = shared_key.funding_txid.to_owned();
            state_chain_id1 = shared_key.state_chain_id.unwrap().to_owned();
        }
        // Should not have changed
        assert_eq!(state_chain_id.to_string(), state_chain_id1.to_string());
        assert_eq!(funding_txid, funding_txid1);

        // Transfer 2
        let receiver2_addr = wallets[2]
            .get_new_state_entity_address(&funding_txid)
            .unwrap();

        let new_shared_key_id2 = run_transfer(&mut wallets, 1, 2, state_chain_id);

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
            state_entity::api::get_statechain(&wallets[0].client_shim, &state_chain_id1).unwrap();
        assert_eq!(state_chain.chain.len(), 3);
        assert_eq!(
            state_chain.chain.get(1).unwrap().data.to_string(),
            receiver1_addr.proof_key.to_string()
        );
        assert_eq!(
            state_chain.chain.last().unwrap().data.to_string(),
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
            receiver2_addr.proof_key
        );
    }

    #[test]
    #[serial]
    fn test_withdraw() {
        let mainstay_config = mainstay::Config::mock_from_url(&mockito::server_url());
        let _ = spawn_server(Some(mainstay_config));
        let mut wallet = gen_wallet();

        let deposit_resp = run_deposit(&mut wallet, &10000);
        let shared_key_id = &deposit_resp.0;
        let state_chain_id = &deposit_resp.1;

        assert!(wallet.get_shared_key(shared_key_id).unwrap().unspent);
        assert!(
            wallet
                .get_shared_key_by_state_chain_id(state_chain_id)
                .unwrap()
                .unspent
        );

        // Try withdraw wrong key
        assert!(state_entity::withdraw::withdraw(&mut wallet, &Uuid::new_v4()).is_err());

        // Check withdraw method completes without Err
        run_withdraw(&mut wallet, state_chain_id);

        // Check marked spent in wallet
        assert!(!wallet.get_shared_key(shared_key_id).unwrap().unspent);

        // Check state chain is updated
        let state_chain =
            state_entity::api::get_statechain(&wallet.client_shim, state_chain_id).unwrap();
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
        let err = state_entity::withdraw::withdraw(&mut wallet, shared_key_id);
        assert!(err.is_err());
    }

    #[test]
    #[serial]
    /// Test wallet load from json correctly when shared key present.
    fn test_wallet_load_with_shared_key() {
        let mainstay_config = mainstay::Config::mock_from_url(&mockito::server_url());
        let _ = spawn_server(Some(mainstay_config));

        let mut wallet = gen_wallet();
        run_deposit(&mut wallet, &10000);

        let wallet_json = wallet.to_json();
        let wallet_rebuilt = wallet::wallet::Wallet::from_json(
            wallet_json,
            ClientShim::new("http://localhost:8000".to_string(), None),
            Box::new(MockElectrum::new()),
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
    }
}
