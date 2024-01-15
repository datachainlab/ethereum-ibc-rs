#![allow(clippy::result_large_err)]
#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub mod client_state;
pub mod commitment;
pub mod consensus_state;
pub mod errors;
pub mod header;
pub mod misbehaviour;
pub mod types;
pub mod update;
pub use ethereum_consensus as consensus;
pub use ethereum_light_client_verifier as light_client_verifier;

mod internal_prelude {
    pub use alloc::boxed::Box;
    pub use alloc::format;
    pub use alloc::string::{String, ToString};
    pub use alloc::vec::Vec;
}
use ibc::core::ics02_client::client_type::ClientType;

pub(crate) const ETHEREUM_CLIENT_TYPE: &str = "ethereum";

pub fn eth_client_type() -> ClientType {
    ClientType::new(ETHEREUM_CLIENT_TYPE.into())
}
