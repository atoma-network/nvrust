//! Remote attestation for NVIDIA GPUs
//!
//! This crate provides functionality for performing remote attestation
//! of NVIDIA GPUs by sending evidence to a verification service.

pub mod constants;
pub mod errors;
pub mod remote_gpu_attestation;
pub mod remote_nvswitch_attestation;
#[cfg(test)]
mod tests;
pub mod types;
pub mod utils;

pub use errors::{AttestError, Result};
pub use remote_gpu_attestation::verify_gpu_attestation;
pub use remote_nvswitch_attestation::verify_nvswitch_attestation;
pub use types::{DeviceEvidence, NvSwitchEvidence};
