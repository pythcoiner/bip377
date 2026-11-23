//! Codec for BIP-377, with conversions to and from a `bitcoin` release.
//!
//! The codec itself lives in [`bip377-ll`](ll), which is dependency-free so a
//! bare-metal signer can depend on it directly. This crate re-exports it and adds
//! [`backend`], the conversions between its wire types and those of the `bitcoin`
//! release selected by a feature flag.

#![no_std]

extern crate alloc;

pub use bip377_ll as ll;

pub mod backend;
pub mod request;
pub mod response;

#[cfg(feature = "bitcoin_0_32")]
pub use crate::backend::bitcoin;
