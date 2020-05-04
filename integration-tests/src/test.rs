#[cfg(test)]
mod tests {
    extern crate server_lib;
    extern crate client_lib;
    extern crate bitcoin;

    use client_lib::*;
    use client_lib::wallet::wallet::Wallet;
    use server_lib::server;

    use bitcoin::{ Amount, TxIn };
    use bitcoin::OutPoint;
    use bitcoin::hashes::sha256d;
    use std::{thread, time};

    pub const TEST_WALLET_FILENAME: &str = "../client/test-assets/wallet.data";

    #[test]
    fn test_session_init() {
        spawn_server();
        let mut wallet = load_wallet();
        let res = client_lib::state_entity::deposit::session_init(&mut wallet);
        assert!(res.is_ok());
        println!("ID: {}",res.unwrap());
    }

    #[test]
    fn test_failed_auth() {
        spawn_server();
        let client_shim = ClientShim::new("http://localhost:8000".to_string(), None);
        if let Err(e) = ecdsa::get_master_key(&"Invalid id".to_string(), &client_shim) {
            assert_eq!(e.to_string(),"State Entity Error: User authorisation failed".to_string());
        }
    }

    //TODO: UPDATE TEST - ecdsa::sign now only works on Transactions
    // #[test]
    // fn test_ecdsa() {
    //     spawn_server();
    //
    //     let mut wallet = load_wallet();
    //     let id = client_lib::state_entity::deposit::session_init(&mut wallet).unwrap();
    //     let ps: ecdsa::PrivateShare = ecdsa::get_master_key(&id, &wallet.client_shim).unwrap();
    //
    //     for y in 0..10 {
    //         let x_pos = BigInt::from(0);
    //         let y_pos = BigInt::from(y);
    //         println!("Deriving child_master_key at [x: {}, y:{}]", x_pos, y_pos);
    //
    //         let child_master_key = ps
    //             .master_key
    //             .get_child(vec![x_pos.clone(), y_pos.clone()]);
    //
    //         let msg: BigInt = BigInt::from(12345);  // arbitrary message
    //         let signature =
    //             ecdsa::sign(&wallet.client_shim, msg, &child_master_key, x_pos, y_pos, &ps.id)
    //                 .expect("ECDSA signature failed");
    //
    //         println!(
    //             "signature = (r: {}, s: {})",
    //             signature.r.to_hex(),
    //             signature.s.to_hex()
    //         );
    //     }
    // }

    #[test]
    fn test_schnorr() {
        spawn_server();

        let client_shim = ClientShim::new("http://localhost:8000".to_string(), None);

        let share: schnorr::Share = schnorr::generate_key(&client_shim).unwrap();

        let msg: BigInt = BigInt::from(1234);  // arbitrary message
        let signature = schnorr::sign(&client_shim, msg, &share)
            .expect("Schnorr signature failed");

        println!(
            "signature = (e: {:?}, s: {:?})",
            signature.e,
            signature.s
        );
    }

    #[test]
    fn test_deposit() {
        spawn_server();
        let mut wallet = gen_wallet();

        // make TxIns for funding transaction
        let amount = Amount::ONE_BTC;
        let inputs =  vec![
            TxIn {
                previous_output: OutPoint { txid: sha256d::Hash::default(), vout: 0 },
                sequence: 0xffffffff - 2,
                witness: Vec::new(),
                script_sig: bitcoin::Script::default(),
            }
        ];
        // This addr should correspond to UTXOs being spent
        let funding_spend_addrs = vec!(wallet.get_new_bitcoin_address().unwrap());
        let resp = state_entity::deposit::deposit(
            &mut wallet,
            inputs,
            funding_spend_addrs,
            amount
        ).unwrap();

        println!("Shared wallet id: {:?} ",resp.0);
        println!("Funding transaction: {:?} ",resp.1);
        println!("Back up transaction: {:?} ",resp.2);
    }

    #[test]
    fn test_transfer() {
        spawn_server();
        let mut wallet_sender = gen_wallet();
        // deposit
        let amount = Amount::ONE_BTC;
        let inputs =  vec![
            TxIn {
                previous_output: OutPoint { txid: sha256d::Hash::default(), vout: 0 },
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
                script_sig: bitcoin::Script::default(),
            }
        ];
        // This addr should correspond to UTXOs being spent
        let funding_spend_addrs = vec!(wallet_sender.get_new_bitcoin_address().unwrap());
        let deposit_resp = state_entity::deposit::deposit(&mut wallet_sender, inputs, funding_spend_addrs, amount).unwrap();
        println!("Shared wallet id: {:?} ",deposit_resp.0);
        println!("Funding transaction: {:?} ",deposit_resp.1);
        println!("Back up transaction: {:?} ",deposit_resp.2);

        let mut wallet_receiver = gen_wallet();
        let receiver_addr = wallet_receiver.get_new_state_entity_address().unwrap();

        let tranfer_sender_resp =
            state_entity::transfer::transfer_sender(
                &mut wallet_sender,
                &deposit_resp.0,    // shared wallet id
                &receiver_addr,
                deposit_resp.3     // backup tx prepare sign msg
        ).unwrap();

        println!("x1: {:?} ",tranfer_sender_resp.0);
        println!("Back up transaction: {:?} ",tranfer_sender_resp.1);

    }

    #[test]
    fn test_wallet_load_with_shared_wallet() {
        spawn_server();

        let mut wallet = load_wallet();
        let id = client_lib::state_entity::deposit::session_init(&mut wallet).unwrap();
        wallet.gen_shared_wallet(&id.to_string()).unwrap();

        let wallet_json = wallet.to_json();
        let wallet_rebuilt = wallet::wallet::Wallet::from_json(wallet_json, &"regtest".to_string(), ClientShim::new("http://localhost:8000".to_string(), None)).unwrap();

        let shared = wallet.shared_wallets.get(0).unwrap();
        let shared_rebuilt = wallet_rebuilt.shared_wallets.get(0).unwrap();

        assert_eq!(shared.id,shared_rebuilt.id);
        assert_eq!(shared.network,shared_rebuilt.network);
        assert_eq!(shared.private_share.id, shared_rebuilt.private_share.id);
        assert_eq!(shared.private_share.master_key.public, shared_rebuilt.private_share.master_key.public);
        assert_eq!(shared.last_derived_pos,shared_rebuilt.last_derived_pos);
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
        Wallet::load_from(TEST_WALLET_FILENAME,&"regtest".to_string(),ClientShim::new("http://localhost:8000".to_string(), None)).unwrap()
    }
}
