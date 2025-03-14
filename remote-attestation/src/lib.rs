//! Remote attestation for NVIDIA GPUs
//!
//! This crate provides functionality for performing remote attestation
//! of NVIDIA GPUs by sending evidence to a verification service.

pub mod attest_remote;
pub mod constants;
pub mod errors;
#[cfg(test)]
mod tests;
pub mod types;
pub mod utils;

pub use attest_remote::attest_remote;
pub use errors::{AttestError, Result};
pub use types::DeviceEvidence;
