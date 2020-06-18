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

    use std::str::FromStr;

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
        let mut batch_id = String::from("123456789");

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
        let batch_id = String::from("123456789");

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
        assert!(
            state_entity::transfer::transfer_sender(
                &mut wallets[0],
                &deposits[0].0,    // shared wallet id
                receiver_addr.clone(),
        ).is_err());

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
    }
}
