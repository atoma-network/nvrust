use std::ffi::c_void;

/// Constants for the NSCQ API
pub const NSCQ_ATTESTATION_REPORT_SIZE: usize = 0x2000;
pub const NSCQ_CERTIFICATE_CERT_CHAIN_MAX_SIZE: usize = 0x1400;

/// Result Code from the NSCQ API
pub type NscqRc = i8;

/// Session ID for the NSCQ API
pub type NscqSession = *mut c_void;

/// Tnvl status for the NSCQ API
pub type NscqTnvlStatus = i8;

/// Architecture for the NSCQ API
pub type NscqArch = i8;

/// Observer ID for the NSCQ API
pub type NscqObserver = *mut c_void;

/// UUID for the NSCQ API
pub type NscqUuid = *mut c_void;

/// User data for the NSCQ API
pub type UserData = *mut c_void;

/// Session result for the NSCQ API
#[derive(Debug)]
#[repr(C)]
pub struct NscqSessionResult {
    /// Result code
    pub rc: NscqRc,
    /// Session ID
    pub session: NscqSession,
}

/// Observer result for the NSCQ API
#[derive(Debug)]
#[repr(C)]
pub struct NscqObserverResult {
    /// Result code
    pub rc: NscqRc,
    /// Observer ID
    pub observer: NscqObserver,
}

/// Attestation report for the NSCQ API
#[derive(Debug)]
#[repr(C)]
pub struct NscqAttestationReport {
    /// Report data
    pub report: [u8; NSCQ_ATTESTATION_REPORT_SIZE],
    /// Report size
    report_size: u32,
}

/// Attestation certificate for the NSCQ API
#[derive(Debug)]
#[repr(C)]
pub struct NscqAttestationCertificate {
    /// Certificate data
    pub cert_chain: [u8; NSCQ_CERTIFICATE_CERT_CHAIN_MAX_SIZE],
    /// Certificate size
    pub cert_chain_size: u32,
}

/// Label for the NSCQ API
pub struct NscqLabel {
    /// Label data
    pub data: [i8; 64],
}

impl NscqLabel {
    pub fn new() -> Self {
        NscqLabel { data: [0; 64] }
    }
}

#[allow(clippy::from_over_into)]
impl Into<String> for NscqLabel {
    fn into(self) -> String {
        let label = unsafe { std::ffi::CStr::from_ptr(self.data.as_ptr()) };
        label.to_string_lossy().into_owned()
    }
}

// UUID callback function type
pub type UuidCallback =
    unsafe extern "C" fn(device: NscqUuid, rc: NscqRc, uuid: NscqUuid, user_data: UserData);

// Architecture callback function type
pub type ArchitectureCallback =
    unsafe extern "C" fn(device: NscqUuid, rc: NscqRc, arch: NscqArch, user_data: UserData);

/// TNVL callback function type
pub type TnvlCallback =
    unsafe extern "C" fn(device: NscqUuid, rc: NscqRc, tnvl: NscqTnvlStatus, user_data: UserData);

/// Attestation report callback function type
pub type AttestationReportCallback = unsafe extern "C" fn(
    device: NscqUuid,
    rc: NscqRc,
    report: NscqAttestationReport,
    user_data: UserData,
);

/// Attestation certificate report callback function type
pub type AttestationCertificateReportCallback = unsafe extern "C" fn(
    device: NscqUuid,
    rc: NscqRc,
    cert: NscqAttestationCertificate,
    user_data: UserData,
);

/// NSCQ callback enum
pub enum NscqCallback {
    Uuid(UuidCallback),
    Architecture(ArchitectureCallback),
    Tnvl(TnvlCallback),
    AttestationReport(AttestationReportCallback),
    AttestationCertificate(AttestationCertificateReportCallback),
}

impl NscqCallback {
    /// Converts the callback to a raw pointer.
    pub fn as_ptr(&self) -> *const c_void {
        match self {
            NscqCallback::Uuid(callback) => *callback as *const _,
            NscqCallback::Architecture(callback) => *callback as *const _,
            NscqCallback::Tnvl(callback) => *callback as *const _,
            NscqCallback::AttestationReport(callback) => *callback as *const _,
            NscqCallback::AttestationCertificate(callback) => *callback as *const _,
        }
    }
}
