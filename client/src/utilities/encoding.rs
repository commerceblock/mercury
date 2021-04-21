//! Bech32
//!
//! Bech32 encoding for statecoin addresses and messages

use bech32::{self, FromBase32, ToBase32};
use shared_lib::structs::{SCEAddress,TransferMsg3,FESer,PrepareSignTxMsg, Protocol};
use shared_lib::state_chain::StateChainSig;
use bitcoin::secp256k1;
use bitcoin::{Address, Network};
use crate::wallet::wallet::to_bitcoin_public_key;
use uuid::Uuid;
use hex;

use super::super::Result;
use crate::error::CError;

/// Encode a statechain address (proof key) in bech32 format
pub fn encode_address(sce_address: SCEAddress) -> Result<String> {

	let proof_key = sce_address.proof_key;
	let encoded = bech32::encode("sc", proof_key.serialize().to_base32()).unwrap();

    Ok(encoded)
}

/// Encode a statechain address (proof key) in bech32 format
pub fn decode_address(bech32_address: String, network: &String) -> Result<SCEAddress> {

	let (prefix, pubkey) = bech32::decode(&bech32_address).unwrap();

	if prefix != "sc" {
	    return Err(CError::Generic(String::from(
	        "Mercury address incorrect prefix",
	    )));
	}

	let keyslice = Vec::<u8>::from_base32(&pubkey).unwrap();
	let proof_key = secp256k1::PublicKey::from_slice(&keyslice).unwrap();

    let tx_backup_addr = Some(Address::p2wpkh(&to_bitcoin_public_key(proof_key), network.parse::<Network>().unwrap())?);

    Ok(SCEAddress { tx_backup_addr, proof_key })
}

// Encode a mercury transaction message in bech32 format
pub fn encode_message(message: TransferMsg3) -> Result<String> {

	let mut sig_bytes = hex::decode(message.statechain_sig.sig.clone()).unwrap();
	let mut tx_bytes = hex::decode(message.tx_backup_psm.clone().tx_hex).unwrap();

	// compact messgae serialisation to byte vector
	let mut ser_bytes = Vec::new();
	//bytes 0..129 encrypted t1
	ser_bytes.append(&mut message.t1.secret_bytes.clone());
	//bytes 129..162 (33 bytes) compressed proof key
	ser_bytes.append(&mut message.rec_se_addr.proof_key.clone().serialize().to_vec());
	//bytes 162..178 (16 bytes) statechain_id
	ser_bytes.append(&mut hex::decode(message.statechain_id.clone().simple().to_string()).unwrap());
	//bytes 178..194 (16 bytes) shared_key_id
	ser_bytes.append(&mut hex::decode(message.tx_backup_psm.shared_key_id.clone().simple().to_string()).unwrap());
	//byte 194 is statechain signature length (variable)
	ser_bytes.push(sig_bytes.len() as u8);
	//byte 195..sig_len is statechain signature
	ser_bytes.append(&mut sig_bytes);
	//byte sig_len is backup tx length (variable)
	ser_bytes.push(tx_bytes.len() as u8);
	//remaining bytes backup tx
	ser_bytes.append(&mut tx_bytes);

	let bech32_encoded = bech32::encode("mm",ser_bytes.to_base32()).unwrap();

	Ok(bech32_encoded)
}

// Decode a mercury transaction message from bech32 format
pub fn decode_message(message: String, network: &String) -> Result<TransferMsg3> {

	let (prefix, decoded_msg) = bech32::decode(&message).unwrap();

	if prefix != "mm" {
	    return Err(CError::Generic(String::from(
	        "Mercury transfer message incorrect prefix",
	    )));
	}

	// compact messgae deserialisation to byte vectors
	let decoded_bytes = Vec::<u8>::from_base32(&decoded_msg).unwrap();
	//bytes 0..129 encrypted t1
	let t1_bytes = &decoded_bytes[0..125];
	//bytes 129..162 (33 bytes) compressed proof key
	let proof_key_bytes = &decoded_bytes[125..158];
	//bytes 162..178 (16 bytes) statechain_id
	let statechain_id_bytes = &decoded_bytes[158..174];
	//bytes 178..194 (16 bytes) shared_key_id
	let shared_key_id_bytes = &decoded_bytes[174..190];
	//byte 194 is statechain signature length (variable)
	let sig_len = (decoded_bytes[190] as usize) + 191;
	//byte 195..sig_len is statechain signature
	let sig_bytes = &decoded_bytes[191..sig_len];
	//byte sig_len is backup tx length (variable)
	let tx_len = (decoded_bytes[sig_len] as usize) + sig_len.clone() + 1;
	//remaining bytes backup tx
	let tx_bytes = &decoded_bytes[(sig_len+1)..tx_len];

	let proof_key = secp256k1::PublicKey::from_slice(&proof_key_bytes.clone()).unwrap();
    let tx_backup_addr = Some(Address::p2wpkh(&to_bitcoin_public_key(proof_key), network.parse::<Network>().unwrap())?);

	let mut tx_backup_psm = PrepareSignTxMsg::default();
	tx_backup_psm.tx_hex = hex::encode(tx_bytes);
	tx_backup_psm.shared_key_id = Uuid::from_bytes(&shared_key_id_bytes.clone()).unwrap();
	tx_backup_psm.proof_key = Some(hex::encode(proof_key_bytes.clone()));
	tx_backup_psm.protocol = Protocol::Transfer;

	let mut t1 = FESer::new_random();
	t1.secret_bytes = t1_bytes.clone().to_vec();

	// recreate transfer message 3
	let transfer_msg3 = TransferMsg3 {
	    shared_key_id: Uuid::from_bytes(&shared_key_id_bytes.clone()).unwrap(),
	    t1: t1,
	    statechain_sig: StateChainSig {
		    purpose: "TRANSFER".to_string(),
		    data: hex::encode(proof_key_bytes.clone()),
		    sig: hex::encode(sig_bytes),
	    },
	    statechain_id: Uuid::from_bytes(&statechain_id_bytes.clone()).unwrap(),
	    tx_backup_psm: tx_backup_psm,
	    rec_se_addr: SCEAddress {
	    	tx_backup_addr,
	    	proof_key: proof_key,
	    },
	};

	Ok(transfer_msg3)
}


#[cfg(test)]
mod tests {

    use super::*;
	static SCEADDR: &str = "{ \"tx_backup_addr\": \"bcrt1q28jhk2vkyksvxa2lrqzsc6z2dt0ac4xpvlhtj5\", \"proof_key\": \"0284cbb3019459e603b5242d8602ba2d14b8d9fb238782048287be32eb00dafa66\" }";
	static TRANSFER_MSG_3: &str = "{ \"shared_key_id\": \"bec09086-ff5a-4654-984e-4b0722c0dbef\", \"t1\": { \"secret_bytes\": [4, 205, 61, 74, 107, 173, 231, 32, 22, 93, 82, 80, 211, 251, 184, 165, 79, 197, 216, 194, 220, 25, 70, 222, 238, 52, 240, 157, 53, 165, 104, 149, 153, 132, 142, 229, 190, 165, 226, 25, 119, 137, 87, 104, 178, 156, 169, 102, 129, 252, 176, 240, 83, 148, 121, 98, 210, 191, 23, 22, 115, 156, 71, 113, 175, 173, 176, 159, 160, 69, 197, 40, 61, 239, 140, 47, 222, 195, 29, 68, 112, 228, 38, 84, 43, 255, 108, 159, 153, 4, 60, 94, 250, 35, 184, 16, 152, 111, 178, 78, 89, 209, 85, 237, 93, 81, 203, 199, 157, 104, 62, 9, 178, 146, 8, 106, 34, 224, 35, 228, 161, 99, 162, 119, 56 ] }, \"statechain_sig\": { \"purpose\": \"TRANSFER\", \"data\": \"032bba3673baecf8bb9ab9a7d8a56406595325d6ac18cb42ccb9f79c3d775018a4\", \"sig\": \"304402203647888e56952bb15ae9d566a36a6a13cbd19850a3e01c93e81ab03665845a1b02205811701164799f97cf875d5eeac776cab4033196a899168d8332b87bf3793f6f\" }, \"statechain_id\": \"9fd31ccb-e6c1-498c-80be-e8d9deec7c79\", \"tx_backup_psm\": { \"shared_key_id\": \"bec09086-ff5a-4654-984e-4b0722c0dbef\", \"protocol\": \"Transfer\", \"tx_hex\": \"020000000001014e3e3b35c39ac305aaa3dc364c7378fceaf3cd124101e4f234672a51e74c17d10000000000ffffffff011fae01000000000016001451e57b299625a0c3755f18050c684a6adfdc54c102483045022100de6849daa364f55bdbff15a24250dad308110fbf5c32e02259349ca23c41e1e702201efcee6590fac368585172a9ac31281055e3590e9478ba954500e49cd51be012012102992a0ce40f87d9bf333dbbf60b726b5023fc10c2838179b66c577cb843bf2355a5080000\", \"input_addrs\": [\"0347da6a8ec18b6f2d884b295ab7be01163dd28b555b145e2f260975b061e3c689\"], \"input_amounts\": [111111], \"proof_key\": \"032bba3673baecf8bb9ab9a7d8a56406595325d6ac18cb42ccb9f79c3d775018a4\" }, \"rec_se_addr\": { \"tx_backup_addr\": \"bcrt1q28jhk2vkyksvxa2lrqzsc6z2dt0ac4xpvlhtj5\", \"proof_key\": \"0284cbb3019459e603b5242d8602ba2d14b8d9fb238782048287be32eb00dafa66\" } }";

    #[test]
    fn test_sc_address_encoding() {

		let bech32_sc_addr: String = "sc1q2zvhvcpj3v7vqa4yskcvq46952t3k0mywrcypyzs7lr96cqmtaxvl434fe".to_string();

    	let sce_address = serde_json::from_str::<SCEAddress>(&SCEADDR.to_string()).unwrap();
    	let bech32_encoded = encode_address(sce_address.clone());

    	assert_eq!(bech32_encoded.unwrap().to_string(), bech32_sc_addr);

    	let dec_sce_address = decode_address(bech32_sc_addr,&"regtest".to_string());

    	assert_eq!(sce_address,dec_sce_address.unwrap());
	}

    #[test]
    fn test_message_encoding() {
		let mmessage: String = "mm1qnxn6jnt4hnjq9ja2fgd87ac548utkxzmsv5dhhwxncf6dd9dz2enpywukl2tcsew7y4w69jnj5kdq0ukrc989revtft79ckwwwywud04kcflgz9c55rmmuv9l0vx82ywrjzv4ptlakflxgy83005gaczzvxlvjwt8g4tm2a289u08tg8cym9ysgdg3wqgly5936yaecq2zvhvcpj3v7vqa4yskcvq46952t3k0mywrcypyzs7lr96cqmtaxd87nrn97ds2f3jqta6xemmk8c7d7czggdl66ge2fsnjtqu3vpkl0gccygq3qxerc3rjkj54mzkhf64n2x6n2z09arxzs50speylgr2crvevytgdsygzcz9cpzeren7tulp6atm4vwak2kspnr94gnytgmqejhpalx7fldlqqyqqqqqqqzq2w8cantsu6cvz64g7uxex8x78uateu6yjpq8j0ydr89fg7wnqh6yqqqqqqqrllllllqy06uqgqqqqqqqqkqq29retm9xtztgxrw403spgvdp9x4h7u2nqsyjpsg5pzzqx7dpya4gmy74dahlc45fp9pkknpqgsl06uxtszykf5nj3rcs0puupzq8huaejep7krdpv9zu4f4scjsyz4udvsa9rch2252q8ynn23hcqjqyss9xf2pnjqlp7ehuenmwlkpdexk5prlsgv9qup0xmxc4muhppm7g6455yqqqqjnskn8".to_string();
        let transfer_msg_3 =
            serde_json::from_str::<TransferMsg3>(&TRANSFER_MSG_3.to_string()).unwrap();

        let b32enc = encode_message(transfer_msg_3.clone()).unwrap();

        assert_eq!(b32enc.to_string(),mmessage);

        let decmsg = decode_message(b32enc, &"bitcoin".to_string()).unwrap();

        assert_eq!(transfer_msg_3.shared_key_id,decmsg.shared_key_id);
        assert_eq!(transfer_msg_3.t1,decmsg.t1);
        assert_eq!(transfer_msg_3.statechain_id,decmsg.statechain_id);
    }
}
