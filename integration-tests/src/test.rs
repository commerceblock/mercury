#[cfg(test)]
mod tests {
    extern crate server_lib;
    extern crate client_lib;
    extern crate shared_lib;
    extern crate bitcoin;

    use client_lib::*;
    use client_lib::wallet::wallet::Wallet;

    use server_lib::server;
    use shared_lib::structs::PrepareSignMessage;

    use bitcoin::{ Amount, TxIn, Transaction, OutPoint, PublicKey };
    use bitcoin::hashes::sha256d;
    use curv::elliptic::curves::traits::ECScalar;
    use curv::FE;

    use std::{thread, time};

    pub const TEST_WALLET_FILENAME: &str = "../client/test-assets/wallet.data";

    #[test]
    fn test_gen_shared_key() {
        spawn_server();
        let mut wallet = load_wallet();
        let proof_key = wallet.se_proof_keys.get_new_key().unwrap();
        let init_res = client_lib::state_entity::deposit::session_init(&mut wallet, &proof_key.to_string());
        assert!(init_res.is_ok());
        let key_res = wallet.gen_shared_key(&init_res.unwrap());
        assert!(key_res.is_ok());
    }

    #[test]
    fn test_failed_auth() {
        spawn_server();
        let client_shim = ClientShim::new("http://localhost:8000".to_string(), None);
        let secret_key: FE = ECScalar::new_random();
        if let Err(e) = ecdsa::get_master_key(&"Invalid id".to_string(), &client_shim, &secret_key, false) {
            assert_eq!(e.to_string(),"State Entity Error: Authentication Error: User authorisation failed".to_string());
        }
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

    fn run_deposit(wallet: &mut Wallet) -> (String, String, Transaction, PrepareSignMessage, PublicKey)  {
        // make TxIns for funding transaction
        let amount = Amount::ONE_BTC.as_sat();
        let inputs =  vec![
        TxIn {
            previous_output: OutPoint { txid: sha256d::Hash::default(), vout: 0 },
            sequence: 0xffffffff - 2,
            witness: Vec::new(),
            script_sig: bitcoin::Script::default(),
        }
        ];

        let funding_spend_addrs = vec!(wallet.keys.get_new_address().unwrap());
        let resp = state_entity::deposit::deposit(
            wallet,
            &inputs,
            &funding_spend_addrs,
            &amount
        ).unwrap();

        return resp
    }

    #[test]
    fn test_deposit() {
        spawn_server();
        let mut wallet = gen_wallet();

        let deposit = run_deposit(&mut wallet);

        let funding_tx = deposit.2;
        let backup_tx_psm_msg = deposit.3;
        let proof_key = deposit.4;

        // Get SMT inclusion proof and verify
        let root = state_entity::api::get_smt_root(&mut wallet).unwrap();
        let proof = state_entity::api::get_smt_proof(&mut wallet, &root, &funding_tx.txid().to_string()).unwrap();

        //ensure wallet's shared key is updated with proof info
        let shared_key = wallet.get_shared_key(&deposit.0).unwrap();
        assert_eq!(shared_key.smt_proof.clone().unwrap().root, root);
        assert_eq!(shared_key.smt_proof.clone().unwrap().proof, proof);
        assert_eq!(shared_key.proof_key.unwrap(), proof_key);

        println!("Shared wallet id: {:?} ",deposit.0);
        println!("Funding transaction: {:?} ",funding_tx);
        println!("Back up transaction data: {:?} ",backup_tx_psm_msg);
    }

    #[test]
    fn test_get_statechain() {
        spawn_server();
        let mut wallet = gen_wallet();

        if let Err(e) = state_entity::api::get_statechain(&mut wallet, &String::from("id")) {
            assert!(e.to_string().contains(&String::from("No data for such identifier")))
        }

        let deposit = run_deposit(&mut wallet);

        let state_chain = state_entity::api::get_statechain(&mut wallet, &String::from(deposit.1.clone())).unwrap();
        assert_eq!(state_chain.chain.last().unwrap().data, deposit.4.to_string());
    }

    #[test]
    fn test_transfer() {
        spawn_server();
        let mut wallet_sender = gen_wallet();

        let deposit_resp = run_deposit(&mut wallet_sender);

        // transfer
        let mut wallet_receiver = gen_wallet();
        let funding_txid = deposit_resp.2.input.get(0).unwrap().previous_output.txid.to_string();
        let receiver_addr = wallet_receiver.get_new_state_entity_address(&funding_txid).unwrap();

        let tranfer_sender_resp =
            state_entity::transfer::transfer_sender(
                &mut wallet_sender,
                &deposit_resp.0,    // shared wallet id
                &deposit_resp.1,    // state chain id
                &receiver_addr,
                &deposit_resp.3     // backup tx prepare sign msg
        ).unwrap();

        let transfer_receiver_resp  =
            state_entity::transfer::transfer_receiver(
                &mut wallet_receiver,
                &tranfer_sender_resp,
                &receiver_addr
            ).unwrap();

        // check shared keys have the same master public key
        assert_eq!(
            wallet_sender.get_shared_key(&deposit_resp.0).unwrap().share.public.q,
            wallet_receiver.get_shared_key(&transfer_receiver_resp.new_shared_key_id).unwrap().share.public.q
        );

        // check state chain is updated
        let state_chain = state_entity::api::get_statechain(&mut wallet_sender, &deposit_resp.1).unwrap();
        assert_eq!(state_chain.chain.len(),2);
        assert_eq!(state_chain.chain.last().unwrap().data.to_string(), receiver_addr.proof_key.to_string());

        // Get SMT inclusion proof and verify
        let root = state_entity::api::get_smt_root(&mut wallet_receiver).unwrap();
        let proof = state_entity::api::get_smt_proof(&mut wallet_receiver, &root, &deposit_resp.2.txid().to_string()).unwrap();
        //ensure wallet's shared key is updated with proof info
        let shared_key = wallet_receiver.get_shared_key(&transfer_receiver_resp.new_shared_key_id).unwrap();
        assert_eq!(shared_key.smt_proof.clone().unwrap().root, root);
        assert_eq!(shared_key.smt_proof.clone().unwrap().proof, proof);
        assert_eq!(shared_key.proof_key.unwrap(),receiver_addr.proof_key);
    }

    #[test]
    fn test_withdraw() {
        spawn_server();
        let mut wallet = gen_wallet();

        let deposit_resp = run_deposit(&mut wallet);

        let withdraw_tx = state_entity::withdraw::withdraw(&mut wallet, &deposit_resp.0);
        // ensure withdraw tx is signed
        assert!(withdraw_tx.unwrap().input.last().unwrap().witness.len() > 0);

        // check state chain is updated
        let state_chain = state_entity::api::get_statechain(&mut wallet, &deposit_resp.1).unwrap();
        assert_eq!(state_chain.chain.len(),2);

        // check chain data is address
        assert!(state_chain.chain.last().unwrap().data.contains(&String::from("bcrt")));
        // check purpose of state chain signature
        assert_eq!(state_chain.chain.get(0).unwrap().next_state.clone().unwrap().purpose, String::from("WITHDRAW"));
    }

    #[test]
    fn test_wallet_load_with_shared_key() {
        spawn_server();

        let mut wallet = load_wallet();
        run_deposit(&mut wallet);

        let wallet_json = wallet.to_json();
        let wallet_rebuilt = wallet::wallet::Wallet::from_json(wallet_json, ClientShim::new("http://localhost:8000".to_string(), None)).unwrap();

        let shared_key = wallet.shared_keys.get(0).unwrap();
        let shared_key_rebuilt = wallet_rebuilt.shared_keys.get(0).unwrap();

        assert_eq!(shared_key.id,shared_key_rebuilt.id);
        assert_eq!(shared_key.share.public, shared_key_rebuilt.share.public);
        assert_eq!(shared_key.proof_key, shared_key_rebuilt.proof_key);
        assert_eq!(shared_key.smt_proof.clone().unwrap().root, shared_key_rebuilt.smt_proof.clone().unwrap().root);
        assert_eq!(shared_key.smt_proof.clone().unwrap().proof, shared_key_rebuilt.smt_proof.clone().unwrap().proof);
    }


    fn spawn_server() {
        // Rocket server is blocking, so we spawn a new thread.
        thread::spawn(move || {
            server::get_server().launch();
        });

        let five_seconds = time::Duration::from_millis(5000);
        thread::sleep(five_seconds);
    }
    fn gen_wallet() -> Wallet {
        Wallet::new(
            &[0xcd; 32],
            &"regtest".to_string(),
            ClientShim::new("http://localhost:8000".to_string(), None)
        )
    }
    fn load_wallet() -> Wallet {
        Wallet::load_from(TEST_WALLET_FILENAME,ClientShim::new("http://localhost:8000".to_string(), None)).unwrap()
    }
}
