//! # Coordinator Library
//!
//! Core functionality of the coordinator library

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(missing_docs)]
#![warn(unsafe_code)]
#![warn(unreachable_pub)]
#![warn(unused_extern_crates)]
#![warn(unused_import_braces)]
#![warn(unused_results)]
#![warn(unused_imports)] // alow this for now - remove later
#![allow(dead_code)] // alow this for now - remove later
#![allow(deprecated)] // alow this for now - remove later

#[macro_use]
extern crate log;
extern crate config as config_rs;
extern crate serde as serde;
#[macro_use]
// extern crate mongodb;


pub mod config;
pub mod state_entity;
pub mod error;
// pub mod listener;
// pub mod payments;
//
pub mod interfaces;
// pub mod util;
