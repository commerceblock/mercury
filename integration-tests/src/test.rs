#[cfg(test)]
mod tests {
    use crate::*;
    extern crate server_lib;
    extern crate client_lib;
    extern crate shared_lib;
    extern crate bitcoin;

    use shared_lib::mocks::mock_electrum::MockElectrum;

    use curv::elliptic::curves::traits::ECScalar;
    use curv::FE;


    #[test]
    fn test_gen_shared_key() {
        spawn_server();
        let mut wallet = gen_wallet();
        let proof_key = wallet.se_proof_keys.get_new_key().unwrap();
        let init_res = client_lib::state_entity::deposit::session_init(&mut wallet, &proof_key.to_string());
        assert!(init_res.is_ok());
        let key_res = wallet.gen_shared_key(&init_res.unwrap(), &1000);
        assert!(key_res.is_ok());
    }

    #[test]
    fn test_failed_auth() {
        spawn_server();
        let client_shim = ClientShim::new("http://localhost:8000".to_string(), None);
        let secret_key: FE = ECScalar::new_random();
        let err = ecdsa::get_master_key(&"Invalid id".to_string(), &client_shim, &secret_key, &1000, false);
        assert!(err.is_err());
    }

    // #[test]
    // fn test_schnorr() {
    //     spawn_server();
    //
    //     let client_shim = ClientShim::new("http://localhost:8000".to_string(), None);
    //
    //     let share: schnorr::Share = schnorr::generate_key(&client_shim).unwrap();
    //
    //     let msg: BigInt = BigInt::from(1234);  // arbitrary message
    //     let signature = schnorr::sign(&client_shim, msg, &share)
    //         .expect("Schnorr signature failed");
    //
    //     println!(
    //         "signature = (e: {:?}, s: {:?})",
    //         signature.e,
    //         signature.s
    //     );
    // }

    #[test]
    fn test_deposit() {
        spawn_server();
        let wallet = gen_wallet_with_deposit(10000);

        let state_chains_info = wallet.get_state_chains_info();
        let (_, funding_txid, proof_key, _, _) = wallet.get_shared_key_info(state_chains_info.0.last().unwrap()).unwrap();

        // Get SMT inclusion proof and verify
        let root = state_entity::api::get_smt_root(&wallet.client_shim).unwrap();
        let proof = state_entity::api::get_smt_proof(&wallet.client_shim, &root, &funding_txid).unwrap();

        // ensure wallet's shared key is updated with proof info
        let shared_key = wallet.get_shared_key(state_chains_info.0.last().unwrap()).unwrap();
        assert_eq!(shared_key.smt_proof.clone().unwrap().root, root);
        assert_eq!(shared_key.smt_proof.clone().unwrap().proof, proof);
        assert_eq!(shared_key.proof_key.clone().unwrap(), proof_key);

        println!("Shared wallet id: {:?} ",funding_txid);
        println!("Funding txid: {:?} ",funding_txid);
    }

    #[test]
    fn test_get_statechain() {
        spawn_server();
        let mut wallet = gen_wallet();

        let err = state_entity::api::get_statechain(&wallet.client_shim, &String::from("id"));
        assert!(err.is_err());

        let deposit = run_deposit(&mut wallet, &10000);

        let state_chain = state_entity::api::get_statechain(&wallet.client_shim, &String::from(deposit.1.clone())).unwrap();
        assert_eq!(state_chain.chain.last().unwrap().data, deposit.5.to_string());
    }

    #[test]
    fn test_transfer() {
        spawn_server();
        let mut wallets = vec!();
        wallets.push(gen_wallet_with_deposit(10000)); // sender
        wallets.push(gen_wallet()); // receiver

        // Get deposit info from wallet
        let state_chains_info = wallets[0].get_state_chains_info();
        let shared_key_id = state_chains_info.0.last().unwrap();
        let (state_chain_id, funding_txid, _, _, _) = wallets[0].get_shared_key_info(shared_key_id).unwrap();

        let receiver_addr = wallets[1].get_new_state_entity_address(&funding_txid).unwrap();

        let new_shared_key_id = run_transfer(&mut wallets, 0, 1, shared_key_id);

        // check shared keys have the same master public key
        assert_eq!(
            wallets[0].get_shared_key(shared_key_id).unwrap().share.public.q,
            wallets[1].get_shared_key(&new_shared_key_id).unwrap().share.public.q
        );

        // check shared key is marked spent in sender and unspent in sender
        assert!(!wallets[0].get_shared_key(shared_key_id).unwrap().unspent);
        assert!(wallets[1].get_shared_key(&new_shared_key_id).unwrap().unspent);

        // check state chain is updated
        let state_chain = state_entity::api::get_statechain(&wallets[0].client_shim, &state_chain_id).unwrap();
        assert_eq!(state_chain.chain.len(),2);
        assert_eq!(state_chain.chain.last().unwrap().data.to_string(), receiver_addr.proof_key.to_string());

        // Get SMT inclusion proof and verify
        let root = state_entity::api::get_smt_root(&wallets[1].client_shim).unwrap();
        let proof = state_entity::api::get_smt_proof(&wallets[1].client_shim, &root, &funding_txid).unwrap();
        // Ensure wallet's shared key is updated with proof info
        let shared_key = wallets[1].get_shared_key(&new_shared_key_id).unwrap();
        assert_eq!(shared_key.smt_proof.clone().unwrap().root, root);
        assert_eq!(shared_key.smt_proof.clone().unwrap().proof, proof);
        assert_eq!(shared_key.proof_key.clone().unwrap(),receiver_addr.proof_key);
    }


    #[test]
    fn test_withdraw() {
        spawn_server();
        let mut wallet = gen_wallet_with_deposit(10000);

        let deposit_resp = run_deposit(&mut wallet, &10000);
        assert!(wallet.get_shared_key(&deposit_resp.0).unwrap().unspent);

        // Try withdraw wrong key
        assert!(state_entity::withdraw::withdraw(&mut wallet, &"key".to_string()).is_err());

        // Check withdraw method completes without Err
        state_entity::withdraw::withdraw(&mut wallet, &deposit_resp.0)
            .unwrap();

        // Check marked spent in wallet
        assert!(!wallet.get_shared_key(&deposit_resp.0).unwrap().unspent);

        // Check state chain is updated
        let state_chain = state_entity::api::get_statechain(&wallet.client_shim, &deposit_resp.1).unwrap();
        assert_eq!(state_chain.chain.len(),2);

        // Check chain data is address
        assert!(state_chain.chain.last().unwrap().data.contains(&String::from("bcrt")));
        // Check purpose of state chain signature
        assert_eq!(state_chain.chain.get(0).unwrap().next_state.clone().unwrap().purpose, String::from("WITHDRAW"));

        // Try again after funds already withdrawn
        let err = state_entity::withdraw::withdraw(&mut wallet, &deposit_resp.0);
        assert!(err.is_err());
    }

    #[test]
    /// Test wallet load from json correctly when shared key present.
    fn test_wallet_load_with_shared_key() {
        spawn_server();

        let mut wallet = gen_wallet();
        run_deposit(&mut wallet, &10000);

        let wallet_json = wallet.to_json();
        let wallet_rebuilt = wallet::wallet::Wallet::from_json(wallet_json, ClientShim::new("http://localhost:8000".to_string(), None), Box::new(MockElectrum::new())).unwrap();

        let shared_key = wallet.shared_keys.get(0).unwrap();
        let shared_key_rebuilt = wallet_rebuilt.shared_keys.get(0).unwrap();

        assert_eq!(shared_key.id,shared_key_rebuilt.id);
        assert_eq!(shared_key.share.public, shared_key_rebuilt.share.public);
        assert_eq!(shared_key.proof_key, shared_key_rebuilt.proof_key);
        assert_eq!(shared_key.smt_proof.clone().unwrap().root, shared_key_rebuilt.smt_proof.clone().unwrap().root);
        assert_eq!(shared_key.smt_proof.clone().unwrap().proof, shared_key_rebuilt.smt_proof.clone().unwrap().proof);
    }
}
