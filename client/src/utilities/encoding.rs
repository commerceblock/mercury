//! Bech32
//!
//! Bech32 encoding for statecoin addresses and messages

use bech32::{self, FromBase32, ToBase32};
use shared_lib::structs::SCEAddress;
use bitcoin::secp256k1;
use bitcoin::{Address, Network};
use crate::wallet::wallet::to_bitcoin_public_key;

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

	let (_prefix, pubkey) = bech32::decode(&bech32_address).unwrap();
	let keyslice = Vec::<u8>::from_base32(&pubkey).unwrap();
	let proof_key = secp256k1::PublicKey::from_slice(&keyslice).unwrap();

    let tx_backup_addr = Some(Address::p2wpkh(&to_bitcoin_public_key(proof_key), network.parse::<Network>().unwrap())?);

    Ok(SCEAddress { tx_backup_addr, proof_key })
}

// Encode a mercury transaction message in bech32 format







// Decode a mercury transaction message from bech32 format

