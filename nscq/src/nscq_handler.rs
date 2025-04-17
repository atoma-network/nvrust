use std::{
    collections::HashMap,
    ffi::{c_char, c_void},
    ptr,
    sync::{LazyLock, Mutex},
};

use crate::functions::nscq_uuid_to_label;

use super::{
    session::Session,
    types::{
        NscqArch, NscqAttestationCertificate, NscqAttestationReport, NscqCallback, NscqRc,
        NscqUuid, UserData, NSCQ_ATTESTATION_REPORT_SIZE,
    },
};

const TNVL_BIT_POSITION: usize = 0;
const LOCK_BIT_POSITION: usize = 1;
const UUID_PATH: &str = "/drv/nvswitch/{device}/uuid";
const TNVL_STATUS_PATH: &str = "/config/pcie_mode";
const ATTESTATION_REPORT_PATH: &str = "/config/attestation_report";
const ATTESTATION_CERTIFICATE_CHAIN_PATH: &str = "/config/certificate";
const ALL_SWITCHES: &str = "/{nvswitch}";
const ARCH: &str = "/id/arch";

static SHARED_UUID: LazyLock<Mutex<Vec<String>>> = LazyLock::new(|| Mutex::new(Vec::new()));
static SHARED_TNVL_STATUS: LazyLock<Mutex<HashMap<String, u8>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static SHARED_ATTESTATION_REPORT: LazyLock<
    Mutex<HashMap<String, [u8; NSCQ_ATTESTATION_REPORT_SIZE]>>,
> = LazyLock::new(|| Mutex::new(HashMap::new()));
static SHARED_CERTIFICATE_CHAIN: LazyLock<Mutex<HashMap<String, Vec<u8>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static SHARED_ARCHITECTURE: LazyLock<Mutex<HashMap<String, NscqArch>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static LAST_RETURN_CODE: LazyLock<Mutex<NscqRc>> = LazyLock::new(|| Mutex::new(0));

pub struct NscqHandler {
    session: Session,
}

impl NscqHandler {
    pub fn new() -> Self {
        let session = Session::new(1, vec![]);
        NscqHandler { session }
    }

    pub fn get_all_switch_uuid(&self) -> Result<Vec<String>, NscqRc> {
        let mut shared_uuid = SHARED_UUID.lock().unwrap();
        shared_uuid.clear();
        drop(shared_uuid);
        self.session.path_observe(
            UUID_PATH,
            NscqCallback::Uuid(_device_uuid_callback),
            ptr::null_mut(),
            0,
        );
        let rc = *LAST_RETURN_CODE.lock().unwrap();
        if rc == 0 {
            Ok(SHARED_UUID.lock().unwrap().clone())
        } else {
            Err(rc)
        }
    }

    pub fn get_switch_architecture(&self) -> Result<HashMap<String, NscqArch>, NscqRc> {
        self.session.path_observe(
            &format!("{ALL_SWITCHES}{ARCH}"),
            NscqCallback::Architecture(_device_architecture_callback),
            ptr::null_mut(),
            0,
        );
        let rc = *LAST_RETURN_CODE.lock().unwrap();
        if rc == 0 {
            Ok(SHARED_ARCHITECTURE.lock().unwrap().clone())
        } else {
            Err(rc)
        }
    }

    pub fn get_switch_tnvl_status(&self, device: &str) -> Result<u8, NscqRc> {
        self.session.path_observe(
            &format!("/{device}{TNVL_STATUS_PATH}"),
            NscqCallback::Tnvl(_device_tnvl_status_callback),
            ptr::null_mut(),
            0,
        );
        let rc = *LAST_RETURN_CODE.lock().unwrap();
        if rc == 0 {
            let shared_tnvl_status = SHARED_TNVL_STATUS.lock().unwrap();
            Ok(shared_tnvl_status.get(device).copied().unwrap())
        } else {
            Err(rc)
        }
    }

    pub fn get_all_switch_tnvl_status(&self) -> Result<HashMap<String, u8>, NscqRc> {
        self.session.path_observe(
            &format!("{ALL_SWITCHES}{TNVL_STATUS_PATH}"),
            NscqCallback::Tnvl(_device_tnvl_status_callback),
            ptr::null_mut(),
            0,
        );
        let rc = *LAST_RETURN_CODE.lock().unwrap();
        if rc == 0 {
            Ok(SHARED_TNVL_STATUS.lock().unwrap().clone())
        } else {
            Err(rc)
        }
    }

    pub fn is_switch_tnvl_mode(&self, device: &str) -> Result<bool, NscqRc> {
        let tnvl_status = self.get_switch_tnvl_status(device)?;
        Ok(((tnvl_status >> TNVL_BIT_POSITION) & 1) == 1)
    }

    pub fn is_switch_lock_mode(&self, device: &str) -> Result<bool, NscqRc> {
        let tnvl_status = self.get_switch_tnvl_status(device)?;
        Ok(((tnvl_status >> LOCK_BIT_POSITION) & 1) == 1)
    }

    pub fn get_switch_attestation_certificate_chain(
        &self,
        device: &str,
    ) -> Result<Vec<u8>, NscqRc> {
        self.session.path_observe(
            &format!("/{device}{ATTESTATION_CERTIFICATE_CHAIN_PATH}"),
            NscqCallback::AttestationCertificate(_device_attestation_certificate_callback),
            ptr::null_mut(),
            0,
        );
        let rc = *LAST_RETURN_CODE.lock().unwrap();
        if rc == 0 {
            let shared_certificate_chain = SHARED_CERTIFICATE_CHAIN.lock().unwrap();
            let certificate_chain = shared_certificate_chain
                .get(device)
                .map(|chain| chain.as_slice())
                .unwrap_or(&[]);
            Ok(certificate_chain.to_vec())
        } else {
            Err(rc)
        }
    }

    pub fn get_all_switch_attestation_certificate_chain(
        &self,
    ) -> Result<HashMap<String, Vec<u8>>, NscqRc> {
        self.session.path_observe(
            &format!("{ALL_SWITCHES}{ATTESTATION_CERTIFICATE_CHAIN_PATH}"),
            NscqCallback::AttestationCertificate(_device_attestation_certificate_callback),
            ptr::null_mut(),
            0,
        );
        let rc = *LAST_RETURN_CODE.lock().unwrap();
        if rc == 0 {
            Ok(SHARED_CERTIFICATE_CHAIN.lock().unwrap().clone())
        } else {
            Err(rc)
        }
    }

    pub fn get_switch_attestation_report(
        &self,
        device: &str,
        nonce: &[u8; 32],
    ) -> Result<[u8; NSCQ_ATTESTATION_REPORT_SIZE], NscqRc> {
        let nonce_ptr = nonce.as_ptr() as *mut c_void;
        let nonce_len = nonce.len() as u32;
        let input_arg = unsafe { &mut *nonce_ptr };
        self.session.set_input(input_arg, nonce_len, 0);
        self.session.path_observe(
            &format!("/{device}{ATTESTATION_REPORT_PATH}"),
            NscqCallback::AttestationReport(_device_attestation_report_callback),
            ptr::null_mut(),
            0,
        );
        let rc = *LAST_RETURN_CODE.lock().unwrap();
        if rc == 0 {
            let shared_attestation_report = SHARED_ATTESTATION_REPORT.lock().unwrap();
            let report = shared_attestation_report
                .get(device)
                .map(|report| report.as_slice())
                .unwrap_or(&[]);
            Ok(report.try_into().unwrap())
        } else {
            Err(rc)
        }
    }

    pub fn get_all_switch_attestation_report(
        &self,
        nonce: &[u8; 32],
    ) -> Result<HashMap<String, [u8; NSCQ_ATTESTATION_REPORT_SIZE]>, NscqRc> {
        let nonce_ptr = nonce.as_ptr() as *mut c_void;
        let nonce_len = nonce.len() as u32;
        let input_arg = unsafe { &mut *nonce_ptr };
        self.session.set_input(input_arg, nonce_len, 0);
        self.session.path_observe(
            &format!("{ALL_SWITCHES}{ATTESTATION_REPORT_PATH}"),
            NscqCallback::AttestationReport(_device_attestation_report_callback),
            ptr::null_mut(),
            0,
        );
        let rc = *LAST_RETURN_CODE.lock().unwrap();
        if rc == 0 {
            Ok(SHARED_ATTESTATION_REPORT.lock().unwrap().clone())
        } else {
            Err(rc)
        }
    }
}

unsafe extern "C" fn _device_uuid_callback(
    _device: NscqUuid,
    rc: NscqRc,
    uuid: NscqUuid,
    _user_data: UserData,
) {
    let label = nscq_uuid_to_label(uuid, 0);
    let mut shared_uuid = SHARED_UUID.lock().unwrap();
    shared_uuid.push(label.into());
    let mut last_return_code = LAST_RETURN_CODE.lock().unwrap();
    *last_return_code = rc;
}

// @nscqCallback(p_nscq_uuid_t, nscq_rc_t, nscq_arch_t, user_data_type)
unsafe extern "C" fn _device_architecture_callback(
    device: NscqUuid,
    rc: NscqRc,
    arch: NscqArch,
    _user_data: UserData,
) {
    let label = nscq_uuid_to_label(device, 0);
    let mut shared_architecture = SHARED_ARCHITECTURE.lock().unwrap();
    shared_architecture.insert(label.into(), arch);
    let mut last_return_code = LAST_RETURN_CODE.lock().unwrap();
    *last_return_code = rc;
}

unsafe extern "C" fn _device_tnvl_status_callback(
    device: NscqUuid,
    rc: NscqRc,
    tnvl: c_char,
    _user_data: UserData,
) {
    let label = nscq_uuid_to_label(device, 0);
    let mut shared_tnvl_status = SHARED_TNVL_STATUS.lock().unwrap();
    shared_tnvl_status.insert(label.into(), tnvl as u8);
    let mut last_return_code = LAST_RETURN_CODE.lock().unwrap();
    *last_return_code = rc;
}

unsafe extern "C" fn _device_attestation_report_callback(
    device: NscqUuid,
    rc: NscqRc,
    report: NscqAttestationReport,
    _user_data: UserData,
) {
    let label = nscq_uuid_to_label(device, 0);
    let mut shared_attestation_report = SHARED_ATTESTATION_REPORT.lock().unwrap();
    shared_attestation_report.insert(
        label.into(),
        report.report.map(|a| a as u8).try_into().unwrap(),
    );
    let mut last_return_code = LAST_RETURN_CODE.lock().unwrap();
    *last_return_code = rc;
}

unsafe extern "C" fn _device_attestation_certificate_callback(
    device: NscqUuid,
    rc: NscqRc,
    cert: NscqAttestationCertificate,
    _user_data: UserData,
) {
    let label = nscq_uuid_to_label(device, 0);
    let mut shared_certificate_chain = SHARED_CERTIFICATE_CHAIN.lock().unwrap();
    shared_certificate_chain.insert(
        label.into(),
        cert.cert_chain[..(cert.cert_chain_size as usize)].to_vec(),
    );
    let mut last_return_code = LAST_RETURN_CODE.lock().unwrap();
    *last_return_code = rc;
}
