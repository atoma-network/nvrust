pub mod error;
pub mod functions;

use std::convert::TryFrom;
use std::ffi::{CStr, CString};
use std::fmt;
use std::marker::PhantomData;
use std::mem;
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::ptr::{self, NonNull};

use error::{NscqError, Result};

/// NSCQ certificate chain max size
pub const NSCQ_CERTIFICATE_CERT_CHAIN_MAX_SIZE: usize = 0x1400;

/// NSCQ attestation report nonce size
pub const NSCQ_ATTESTATION_REPORT_NONCE_SIZE: usize = 0x20;

/// NSCQ attestation report size
pub const NSCQ_ATTESTATION_REPORT_SIZE: usize = 0x2000;

/// NSCQ session create mount devices
pub const NSCQ_SESSION_CREATE_MOUNT_DEVICES: u32 = 1;

/// NSCQ tnvl status type
pub type nscq_tnvl_status_t = i8;

/// NSCQ architecture type
pub type nscq_arch_t = i8;

/// NSCQ session structure
/// This is a C struct where Rust only needs a pointer, not the internal layout.
#[repr(C)]
pub struct nscq_session_st {
    _private: [u8; 0],
}

/// NSCQ observer structure
/// This is a C struct where Rust only needs a pointer, not the internal layout.
#[repr(C)]
pub struct nscq_observer_st {
    _private: [u8; 0],
}

// --- Pointer Types ---
// Using NonNull where appropriate if the C API guarantees non-null pointers.
// Assuming session/observer handles might be null initially or after errors/destruction.
pub type nscq_session_t = *mut nscq_session_st;
pub type nscq_observer_t = *mut nscq_observer_st;
pub type p_nscq_uuid_t = *mut NscqUuid; // Raw pointer for C interaction

#[repr(i8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NscqDeviceTnvlMode {
    Unknown = -1,
    Disabled = 0,
    Enabled = 1,
    Failure = 2,
    Locked = 3,
}

impl TryFrom<nscq_tnvl_status_t> for NscqDeviceTnvlMode {
    type Error = NscqError; // Or a simple error type indicating invalid value

   fn try_from(value: nscq_tnvl_status_t) -> std::result::Result<Self, Self::Error> {
       match value {
           -1 => Ok(NscqDeviceTnvlMode::Unknown),
            0 => Ok(NscqDeviceTnvlMode::Disabled),
            1 => Ok(NscqDeviceTnvlMode::Enabled),
            2 => Ok(NscqDeviceTnvlMode::Failure),
            3 => Ok(NscqDeviceTnvlMode::Locked),
            _ => Err(NscqError::UnknownReturnCode(value)), // Reuse error type
       }
   }
}

#[repr(i8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NscqArchType {
    Sv10 = 0,
    Lr10 = 1,
    Ls10 = 2,
}

impl TryFrom<nscq_arch_t> for NscqArchType {
    type Error = NscqError;

    fn try_from(value: nscq_arch_t) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(NscqArchType::Sv10),
            1 => Ok(NscqArchType::Lr10),
            2 => Ok(NscqArchType::Ls10),
            _ => Err(NscqError::UnknownReturnCode(value)),
        }
    }
}


#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NscqUuid {
    pub bytes: [u8; 16],
}

impl fmt::Display for NscqUuid {
     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.bytes.iter().map(|b| format!("0x{:02x}", b)).collect::<Vec<_>>().join(", "))
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NscqLabel {
    pub data: [c_char; 64], // Equivalent to char[64] in C
}

impl NscqLabel {
    /// Attempts to convert the C char array to a Rust String.
    /// Returns an error if the data is not valid UTF-8 or contains NUL bytes unexpectedly.
    pub fn to_string(&self) -> Result<String> {
        // Find the first NUL byte or the end of the buffer
        let len = self.data.iter().position(|&c| c == 0).unwrap_or(64);
        let c_str_slice = unsafe { CStr::from_ptr(self.data.as_ptr().cast::<c_char>()) };
        Ok(c_str_slice.to_str()?.to_owned())

        // Safer alternative if NUL termination isn't guaranteed or might be past buffer:
        // let slice = unsafe { std::slice::from_raw_parts(self.data.as_ptr().cast::<u8>(), len) };
        // Ok(std::str::from_utf8(slice)?.to_owned())
    }
}

impl fmt::Debug for NscqLabel {
     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
         write!(f, "NscqLabel({:?})", self.to_string().unwrap_or_else(|_| "<invalid utf8>".to_string()))
     }
}