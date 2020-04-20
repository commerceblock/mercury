#[cfg(test)]
mod tests {
    extern crate server_lib;
    extern crate client_lib;
    extern crate bitcoin;

    use client_lib::wallet::wallet::Wallet;
    use client_lib::*;
    use server_lib::server;

    use bitcoin::{ Amount, TxIn };
    use bitcoin::OutPoint;
    use bitcoin::hashes::sha256d;

    use std::{thread, time};
    use std::collections::HashMap;

    #[test]
    fn test_ecdsa() {
        spawn_server();

        let client_shim = ClientShim::new("http://localhost:8000".to_string(), None);

        let ps: ecdsa::PrivateShare = ecdsa::get_master_key(&client_shim);

        for y in 0..10 {
            let x_pos = BigInt::from(0);
            let y_pos = BigInt::from(y);
            println!("Deriving child_master_key at [x: {}, y:{}]", x_pos, y_pos);

            let child_master_key = ps
                .master_key
                .get_child(vec![x_pos.clone(), y_pos.clone()]);

            let msg: BigInt = BigInt::from(y + 1);  // arbitrary message
            let signature =
                ecdsa::sign(&client_shim, msg, &child_master_key, x_pos, y_pos, &ps.id)
                    .expect("ECDSA signature failed");

            println!(
                "signature = (r: {}, s: {})",
                signature.r.to_hex(),
                signature.s.to_hex()
            );
        }
    }

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

        let client_shim = ClientShim::new("http://localhost:8000".to_string(), None);

        // 2P-ECDSA
        let private_share: ecdsa::PrivateShare = ecdsa::get_master_key(&client_shim);
        println!("{}",private_share.id);
        println!("{:?}",private_share.master_key.public);

        // make wallet
        let id = String::from("1");
        let last_derived_pos = 0;
        let addresses_derivation_map = HashMap::new();
        let network = "regtest".to_string();
        let mut wallet = Wallet {
            id,
            network,
            private_share,
            last_derived_pos,
            addresses_derivation_map,
        };


        let addr = wallet.get_new_bitcoin_address();
        let amount = Amount::ONE_BTC;
        let inputs =  vec![
            TxIn {
                previous_output: OutPoint { txid: sha256d::Hash::default(), vout: 0 },
                sequence: 0xffffffff - 2,
                witness: Vec::new(),
                script_sig: bitcoin::Script::default(),
            }
        ];
        let resp = state_entity::deposit::deposit(wallet, &client_shim, inputs, addr, amount);
        println!("{} {}",resp.0,resp.1);
        assert!(resp.0 == String::from("deposit"));
    }


    fn spawn_server() {
        // Rocket server is blocking, so we spawn a new thread.
        thread::spawn(move || {
            server::get_server().launch();
        });

        let five_seconds = time::Duration::from_millis(5000);
        thread::sleep(five_seconds);
    }
}
