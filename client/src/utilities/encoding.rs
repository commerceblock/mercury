//! Bech32
//!
//! Bech32 encoding for statecoin addresses and messages

use bech32::{self, FromBase32, ToBase32};
use shared_lib::structs::{SCEAddress,TransferMsg3,FESer,PrepareSignTxMsg};
use shared_lib::state_chain::StateChainSig;
use bitcoin::secp256k1;
use bitcoin::{Address, Network, PublicKey};
use crate::wallet::wallet::to_bitcoin_public_key;
use uuid::Uuid;
use rmp_serde;

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

// compact struct for serialising the transfer message
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CompactTransfer {
    pub t1: FESer, // t1 = o1x1
    pub proof_key: PublicKey,
    pub sig: String,
    pub statechain_id: Uuid,
    pub tx_backup_psm: PrepareSignTxMsg,
}

// Encode a mercury transaction message in bech32 format
pub fn encode_message(message: TransferMsg3) -> Result<String> {

	let compact = CompactTransfer {
		t1: message.t1,
		proof_key: to_bitcoin_public_key(message.rec_se_addr.proof_key.clone()),
		sig: message.statechain_sig.sig.clone(),
		statechain_id: message.statechain_id.clone(),
		tx_backup_psm: message.tx_backup_psm.clone(),
	};

	let encoded_msg = rmp_serde::to_vec(&compact).unwrap();
	let bech32_encoded = bech32::encode("mm",encoded_msg.to_base32()).unwrap();

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

	let decoded_bytes = Vec::<u8>::from_base32(&decoded_msg).unwrap();
	let decoded_struct: CompactTransfer = rmp_serde::from_read_ref(&decoded_bytes[..]).unwrap();
    let tx_backup_addr = Some(Address::p2wpkh(&decoded_struct.proof_key.clone(), network.parse::<Network>().unwrap())?);

	let transfer_msg3 = TransferMsg3 {
	    shared_key_id: decoded_struct.tx_backup_psm.shared_key_ids[0],
	    t1: decoded_struct.t1.clone(),
	    statechain_sig: StateChainSig {
		    purpose: "TRANSFER".to_string(),
		    data: decoded_struct.proof_key.clone().to_string(),
		    sig: decoded_struct.sig,
	    },
	    statechain_id: decoded_struct.statechain_id,
	    tx_backup_psm: decoded_struct.tx_backup_psm,
	    rec_se_addr: SCEAddress {
	    	tx_backup_addr,
	    	proof_key: decoded_struct.proof_key.key
	    },
	};

	Ok(transfer_msg3)
}


#[cfg(test)]
mod tests {

    use super::*;
	static SCEADDR: &str = "{ \"tx_backup_addr\": \"bcrt1q28jhk2vkyksvxa2lrqzsc6z2dt0ac4xpvlhtj5\", \"proof_key\": \"0284cbb3019459e603b5242d8602ba2d14b8d9fb238782048287be32eb00dafa66\" }";
	static TRANSFER_MSG_3: &str = "{ \"shared_key_id\": \"bec09086-ff5a-4654-984e-4b0722c0dbef\", \"t1\": { \"secret_bytes\": [4, 205, 61, 74, 107, 173, 231, 32, 22, 93, 82, 80, 211, 251, 184, 165, 79, 197, 216, 194, 220, 25, 70, 222, 238, 52, 240, 157, 53, 165, 104, 149, 153, 132, 142, 229, 190, 165, 226, 25, 119, 137, 87, 104, 178, 156, 169, 102, 129, 252, 176, 240, 83, 148, 121, 98, 210, 191, 23, 22, 115, 156, 71, 113, 175, 173, 176, 159, 160, 69, 197, 40, 61, 239, 140, 47, 222, 195, 29, 68, 112, 228, 38, 84, 43, 255, 108, 159, 153, 4, 60, 94, 250, 35, 184, 16, 152, 111, 178, 78, 89, 209, 85, 237, 93, 81, 203, 199, 157, 104, 62, 9, 178, 146, 8, 106, 34, 224, 35, 228, 161, 99, 162, 119, 56, 223, 172, 243, 57] }, \"statechain_sig\": { \"purpose\": \"TRANSFER\", \"data\": \"032bba3673baecf8bb9ab9a7d8a56406595325d6ac18cb42ccb9f79c3d775018a4\", \"sig\": \"304402203647888e56952bb15ae9d566a36a6a13cbd19850a3e01c93e81ab03665845a1b02205811701164799f97cf875d5eeac776cab4033196a899168d8332b87bf3793f6f\" }, \"statechain_id\": \"9fd31ccb-e6c1-498c-80be-e8d9deec7c79\", \"tx_backup_psm\": { \"shared_key_id\": \"bec09086-ff5a-4654-984e-4b0722c0dbef\", \"protocol\": \"Transfer\", \"tx_hex\": \"020000000001014e3e3b35c39ac305aaa3dc364c7378fceaf3cd124101e4f234672a51e74c17d10000000000ffffffff011fae01000000000016001451e57b299625a0c3755f18050c684a6adfdc54c102483045022100de6849daa364f55bdbff15a24250dad308110fbf5c32e02259349ca23c41e1e702201efcee6590fac368585172a9ac31281055e3590e9478ba954500e49cd51be012012102992a0ce40f87d9bf333dbbf60b726b5023fc10c2838179b66c577cb843bf2355a5080000\", \"input_addrs\": [\"0347da6a8ec18b6f2d884b295ab7be01163dd28b555b145e2f260975b061e3c689\"], \"input_amounts\": [111111], \"proof_key\": \"032bba3673baecf8bb9ab9a7d8a56406595325d6ac18cb42ccb9f79c3d775018a4\" }, \"rec_se_addr\": { \"tx_backup_addr\": \"bcrt1q28jhk2vkyksvxa2lrqzsc6z2dt0ac4xpvlhtj5\", \"proof_key\": \"0284cbb3019459e603b5242d8602ba2d14b8d9fb238782048287be32eb00dafa66\" } }";

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
		let mmessage: String = "mm1jkgacqypqnxv6022d0x2mn88yqt965jsenfue77vhrx22n7vchxd3nxzenwpj3kvmmxwudxv7rxf6dwv545ve9wvn8xgfnywenjue0kv5hxwyxthejy4w6xvktxfen9fvmxgrn8uejcveuznej28jckv6txt79ckw0xfc3m3ejhuetwvkrxfln9qghxv22paenhuerp0en0vescag3cveepx2s4uelmvej0uexgy830ve73rejuppnycdlxtynjeeng4tn8dt4guej7vclxf66p7p8xt9nyjpp4z9n8qy0xwfn9pv0x2yaecen0uetxv7vuugggzsn9mxqv5t8nq8dfy9krq9w3dzjudn7ers7pqfq58hcewkqx6lfndnrpnxq6rgvpjxgcrxd35xuurswr9x5mrjdfjvf3rzdtpv5ukgdfkxesnxdnpxesnzvmrvfjrzwfcx5cxzvm9xqckxwfnv5urzctzxqenvd348q6r2cf3vgcryv3sx5urzvfhxqcnzd35xuunje3exa3kvwphx4jr2et9v93nwdekvdskydpsxvenzwfkvyurjwf3xcuxgwpnxvexywphvfnrxdeexdnrvekeysukvepnx93kxc3dv5mxxvfdxsunsced8qcxyefdv5uxgwtyv4jkxdmrxuuedkfyvfjkxvpexqurvttxvc6kztf5xc6ngtfe8q6x2tf5vgcrwv3jvvcxgcn9v6qsrsx6qxqrqv3sxqcrqvpsxqcrqvfsxy6x2vm9xd3rxdtrxvukzcenxq6kzctpxdjxxvekx33nwveh8pnxxetpvcekxep3xg6rzvp3v56xvv3nxsmrwvnpx5ck2de5vvcnwep3xqcrqvpsxqcrqvpsvenxvenxvenxvvp3x9nxzefsxycrqvpsxqcrqvpsxqcnvvpsxy6r2vt9x5mkyv3e8ymrydtpxp3nxde4x4nrzwpsx5cxxd3cx3snvctyvejxxdf5vvcnqv358qenqdp4xqeryvfsxpjx2d3cxsukgctpxvmrge34x43xgcnxvccn2cfjxser2vryv9jrxvpcxycnqenzvc6kxvejv5cryv348yengwtrvyerxce5x9jnzefhxqeryvp3v4nxxet9xc6njvrxv93nxd3cx5ur2vfhxfsnjctrxvcnywp3xq6n2efnx5unqefexsmnscnp8y6ngdfsxpjngwtrvs6nzcn9xqcnyvp3xgcnqv3e8yexzvrrv56rqe3cxajrjcnxxvenxerzvfnrvvrzxuervc34xqerxenrxycxxv3cxvurzdeevgmrvce4xumkxc3cxsekye3jxv6n2cf4xqurqvpsxzgugggrgldx4rkp3dhjmzzt99dt00spzc7a9z64tv29utexp96mqc0rc6yernsqqxeq0k2zxqenycnzvyenvdenvfsk2cmx8p3xywtpvgukzdmy8psn2d35xqmr2wf4xver2epkv93nzwrrvg6rycmrvgukvdeevvekgdehx5crzwrpxs32wk57".to_string();
		let transfer_msg_3 =
            serde_json::from_str::<TransferMsg3>(&TRANSFER_MSG_3.to_string()).unwrap();

        let b32enc = encode_message(transfer_msg_3).unwrap();

        println!("{:?}", b32enc);

        assert_eq!(b32enc.to_string(),mmessage);
    }
}
