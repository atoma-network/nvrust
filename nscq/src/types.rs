use std::ffi::c_void;

pub type NscqRc = i8;

pub type NscqSession = *mut c_void;

pub type NscqTnvlStatus = i8;

pub type NscqArch = i8;

#[derive(Debug)]
#[repr(C)]
pub struct NscqSessionResult {
    pub rc: NscqRc,
    pub session: NscqSession,
}

pub type NscqObserver = *mut c_void;

#[derive(Debug)]
#[repr(C)]
pub struct NscqObserverResult {
    pub rc: NscqRc,
    pub observer: NscqObserver,
}

pub const NSCQ_ATTESTATION_REPORT_SIZE: usize = 0x2000;
pub const NSCQ_CERTIFICATE_CERT_CHAIN_MAX_SIZE: usize = 0x1400;

#[derive(Debug)]
#[repr(C)]
pub struct NscqAttestationReport {
    report_size: u32,
    pub report: [u8; NSCQ_ATTESTATION_REPORT_SIZE],
}

#[derive(Debug)]
#[repr(C)]
pub struct NscqAttestationCertificate {
    pub cert_chain: [u8; NSCQ_CERTIFICATE_CERT_CHAIN_MAX_SIZE],
    pub cert_chain_size: u32,
}

pub type NscqUuid = *mut c_void;

pub type UserData = *mut c_void;

pub struct NscqLabel {
    pub data: [i8; 64],
}

impl NscqLabel {
    pub fn new() -> Self {
        NscqLabel { data: [0; 64] }
    }
}

impl Into<String> for NscqLabel {
    fn into(self) -> String {
        let label = unsafe { std::ffi::CStr::from_ptr(self.data.as_ptr()) };
        label.to_string_lossy().into_owned()
    }
}

// Define the callback type
pub type UuidCallback =
    unsafe extern "C" fn(device: NscqUuid, rc: NscqRc, uuid: NscqUuid, user_data: UserData);

pub type ArchitectureCallback =
    unsafe extern "C" fn(device: NscqUuid, rc: NscqRc, arch: NscqArch, user_data: UserData);

pub type TnvlCallback =
    unsafe extern "C" fn(device: NscqUuid, rc: NscqRc, tnvl: NscqTnvlStatus, user_data: UserData);

pub type AttestationReportCallback = unsafe extern "C" fn(
    device: NscqUuid,
    rc: NscqRc,
    report: NscqAttestationReport,
    user_data: UserData,
);

pub type AttestationCertificateReportCallback = unsafe extern "C" fn(
    device: NscqUuid,
    rc: NscqRc,
    cert: NscqAttestationCertificate,
    user_data: UserData,
);

pub enum NscqCallback {
    Uuid(UuidCallback),
    Architecture(ArchitectureCallback),
    Tnvl(TnvlCallback),
    AttestationReport(AttestationReportCallback),
    AttestationCertificate(AttestationCertificateReportCallback),
}

impl NscqCallback {
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
