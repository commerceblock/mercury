//! Transfer
//!
//! Transfer coins in state entity to new owner


// transfer() messages:
// 0. Receiver communicates address to Sender (B2 and C2)
// 1. Sender Initialises transfer protocol with State Entity
//      a. init, authorisation, provide receivers proofkey C2
//      b. State Entity generate x1 and sends to Sender
//      c. Sender and State Entity Co-sign new back up transaction sending to Receivers
//          backup address Addr(B2)
// 2. Receiver performs transfer with State Entity
//      a. Verify state chain is updated
//      b. calculate t1=01x1
//      c. calucaulte t2 = t1*o2_inv
//      d. Send t2, O2 to state entity
//      e. Verify o2*S2 = P

use super::super::Result;

extern crate shared_lib;

use crate::error::CError;
use crate::wallet::wallet::{StateEntityAddress, Wallet};
use crate::state_entity::{util::cosign_tx_input, api::get_statechain};
use super::super::utilities::requests;

use shared_lib::structs::{PrepareSignTxMessage, TransferMsg1, TransferMsg2, TransferMsg3, TransferMsg4, TransferMsg5};

use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{FE, GE};

/// Transfer coins to new Owner from this wallet
pub fn transfer_sender(
    wallet: &mut Wallet,
    shared_wallet_id: &String,
    state_chain_id: &String,
    receiver_addr: &StateEntityAddress,
    mut prev_tx_b_prepare_sign_msg: PrepareSignTxMessage
) -> Result<TransferMsg3> {
    // first sign state chain (simply append receivers proof key for now)
    let mut state_chain: Vec<String> = get_statechain(wallet, state_chain_id)?;
    state_chain.push(receiver_addr.proof_key.to_string());

    // init transfer: perform auth and send new statechain
    let transfer_msg2: TransferMsg2 = requests::postb(&wallet.client_shim,&format!("/transfer/sender"),
        &TransferMsg1 {
            shared_wallet_id: shared_wallet_id.to_string(),
            new_state_chain: state_chain.clone()
        })?;

    // sign new back up tx
    prev_tx_b_prepare_sign_msg.address = receiver_addr.backup_addr.clone();
    let (_, new_tx_b_signed) = cosign_tx_input(wallet, &shared_wallet_id, &prev_tx_b_prepare_sign_msg)?;

    // get o1 priv key
    let shared_wal = wallet.get_shared_wallet(&shared_wallet_id).expect("No shared wallet found for id");
    let o1 = shared_wal.private_share.master_key.private.get_private_key();

    // t1 = o1x1
    let t1 = o1 * transfer_msg2.x1;

    let transfer_msg3 = TransferMsg3 {
        shared_wallet_id: shared_wallet_id.to_string(),
        t1, // should be encrypted
        new_backup_tx: new_tx_b_signed,
        state_chain
    };
    Ok(transfer_msg3)
}

/// Transfer coins from old Owner to this wallet
pub fn transfer_receiver(
    wallet: &mut Wallet,
    transfer_msg3: &TransferMsg3,
    se_addr: &StateEntityAddress
) -> Result<TransferMsg5> {
    // verify state chain represents this address as new owner
    if se_addr.proof_key.to_string() != transfer_msg3.state_chain.last().ok_or("State chain empty")?.to_string() {
        return Err(CError::Generic(String::from("State Chain verification failed.")))
    }

    // check try_o2() comments and docs for justification of below code
    let mut done = false;
    let mut transfer_msg5 = TransferMsg5::default();
    let mut o2 = FE::zero();
    while !done {
        match try_o2(wallet, transfer_msg3) {
            Ok(success_resp) => {
                o2 = success_resp.0.clone();
                transfer_msg5 = success_resp.1.clone();
                done = true;
            },
            Err(e) => {
                if !e.to_string().contains(&String::from("Error: Invalid o2, try again.")) {
                    return Err(e);
                }
                debug!("try o2 failure. Trying again...");
            }
        }
    }

    // Make shared wallet with new private share
    let shared_id = &transfer_msg5.new_shared_wallet_id;
    wallet.gen_shared_wallet_fixed_secret_key(shared_id,&o2)?;

    // Check shared wallet master public key
    if (transfer_msg5.s2_pub*o2).get_element()
        != wallet.get_shared_wallet(&shared_id).unwrap().private_share.master_key.public.q.get_element() {
            return Err(CError::StateEntityError(String::from("Transfer failed. Incorrect master public key generated.")))
    }

    Ok(transfer_msg5)
}

// Constraint on s2 size means that some (most) o2 values are not valid for the lindell_2017 protocol.
// We must generate random o2, test if the resulting s2 is valid and try again if not.
/// Carry out transfer_receiver() protocol with a randomly generated o2 value.
pub fn try_o2(wallet: &mut Wallet, transfer_msg3: &TransferMsg3) -> Result<(FE,TransferMsg5)>{
    // generate o2 private key and corresponding 02 public key
    let o2: FE = ECScalar::new_random();

    let g: GE = ECPoint::generator();
    let o2_pub: GE = g * o2;

    // decrypt t1

    // t2 = t1*o2_inv = o1*x1*o2_inv
    let t2 = transfer_msg3.t1 * (o2.invert());

    // encrypt t2 with SE key and sign with Receiver proof key (se_addr.proof_key)

    let transfer_msg5: TransferMsg5 = requests::postb(&wallet.client_shim,&format!("/transfer/receiver"),
        &TransferMsg4 {
            shared_wallet_id: transfer_msg3.shared_wallet_id.clone(),
            t2, // should be encrypted
            state_chain: transfer_msg3.state_chain.clone(),
            o2_pub
        })?;
    Ok((o2,transfer_msg5))

}

#[cfg(test)]
mod tests {

    use curv::elliptic::curves::traits::{ECPoint, ECScalar};
    use curv::{FE, GE};

    #[test]
    fn math() {
        let g: GE = ECPoint::generator();

        //owner1 share
        let o1_s: FE = ECScalar::new_random();
        let o1_p: GE = g * o1_s;

        // SE share
        let s1_s: FE = ECScalar::new_random();
        let s1_p: GE = g * s1_s;

        // deposit P
        let p_p = s1_p*o1_s;
        println!("P1: {:?}",p_p);
        let p_p = o1_p*s1_s;
        println!("P1: {:?}",p_p);


        // transfer
        // SE new random key x1
        let x1_s: FE = ECScalar::new_random();

        // owner2 share
        let o2_s: FE = ECScalar::new_random();
        let o2_p: GE = g * o2_s;

        // t1 = o1*x1*o2_inv
        let t1 = o1_s*x1_s*(o2_s.invert());

        // t2 = t1*x1_inv*s1
        let s2_s = t1*(x1_s.invert())*s1_s;

        println!("P2: {:?}",o2_p*s2_s);
    }
}
