use std::{
    collections::HashMap,
    ffi::{c_char, c_void},
};

use crate::functions::nscq_uuid_to_label;

use super::{
    session::Session,
    types::{
        NscqArch, NscqAttestationCertificate, NscqAttestationReport, NscqCallback, NscqRc,
        NscqTnvlStatus, NscqUuid, UserData, NSCQ_ATTESTATION_REPORT_SIZE,
    },
};

/// Bit position for the Trusted NVLink Mode (TNVL) status
const TNVL_BIT_POSITION: usize = 0;
/// Bit position for the lock status
const LOCK_BIT_POSITION: usize = 1;
/// Path for UUID, this is complete path
const UUID_PATH: &str = "/drv/nvswitch/{device}/uuid";
/// Path for Trusted NVLink Mode (TNVL) status, this is partial path
const TNVL_STATUS_PATH: &str = "/config/pcie_mode";
/// Path for attestation report, this is partial path
const ATTESTATION_REPORT_PATH: &str = "/config/attestation_report";
/// Path for attestation certificate chain, this is partial path
const ATTESTATION_CERTIFICATE_CHAIN_PATH: &str = "/config/certificate";
/// Path for all switches, this is partial path
const ALL_SWITCHES: &str = "/{nvswitch}";
/// Path for architecture, this is partial path
const ARCH: &str = "/id/arch";

/// Handler for NSCQ (NVIDIA Switch Control Query) operations.
/// This struct provides methods to interact with the NSCQ service, including
/// observing paths, retrieving UUIDs, architecture information, Trusted NVLink Mode (TNVL) status,
/// attestation certificates, and attestation reports.
pub struct NscqHandler {
    session: Session,
}

impl NscqHandler {
    /// Creates a new instance of `NscqHandler`.
    ///
    /// # Returns
    ///
    /// * `Ok(NscqHandler)` if the session is created successfully.
    /// * `Err(NscqRc)` if there is an error creating the session.
    pub fn new() -> Result<Self, NscqRc> {
        let session = Session::new(1, vec![])?;
        Ok(NscqHandler { session })
    }

    /// Get all switch UUIDs.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<String>)` containing all switch UUIDs if successful.
    /// * `Err(NscqRc)` if there is an error retrieving the UUIDs.
    pub fn get_all_switch_uuid(&self) -> Result<Vec<String>, NscqRc> {
        let user_data_ptr: *mut Vec<Result<String, NscqRc>> = Box::into_raw(Box::new(Vec::new()));
        let user_data_ffi: UserData = user_data_ptr as UserData;
        self.session.path_observe(
            UUID_PATH,
            NscqCallback::Uuid(uuid_callback),
            user_data_ffi,
            0,
        )?;
        let uuids = *unsafe { Box::from_raw(user_data_ptr) };
        uuids.into_iter().collect()
    }

    /// Get all switch architecture information.
    ///
    /// # Returns
    ///
    /// * `Ok(HashMap<String, NscqArch>)` containing all switch architecture information if successful.
    /// * `Err(NscqRc)` if there is an error retrieving the architecture information.
    pub fn get_switch_architecture(&self) -> Result<HashMap<String, NscqArch>, NscqRc> {
        let user_data_ptr: *mut Vec<Result<(String, NscqArch), NscqRc>> =
            Box::into_raw(Box::new(Vec::new()));
        let user_data_ffi: UserData = user_data_ptr as UserData;
        self.session.path_observe(
            &format!("{ALL_SWITCHES}{ARCH}"),
            NscqCallback::Architecture(architecture_callback),
            user_data_ffi,
            0,
        )?;
        let architecture = *unsafe { Box::from_raw(user_data_ptr) };
        architecture.into_iter().collect()
    }

    /// Get the Trusted NVLink Mode (TNVL) status of a specific switch.
    ///
    /// # Arguments
    ///
    /// * `device` - The device identifier for the switch.
    ///
    /// # Returns
    ///
    /// * `Ok(NscqTnvlStatus)` containing the Trusted NVLink Mode (TNVL) status of the switch if successful.
    /// * `Err(NscqRc)` if there is an error retrieving the Trusted NVLink Mode (TNVL) status.
    pub fn get_switch_tnvl_status(&self, device: &str) -> Result<NscqTnvlStatus, NscqRc> {
        let user_data_ptr: *mut Vec<Result<(String, NscqTnvlStatus), NscqRc>> =
            Box::into_raw(Box::new(Vec::new()));
        let user_data_ffi: UserData = user_data_ptr as UserData;
        self.session.path_observe(
            &format!("/{device}{TNVL_STATUS_PATH}"),
            NscqCallback::Tnvl(tnvl_status_callback),
            user_data_ffi,
            0,
        )?;
        let tnvl_status = *unsafe { Box::from_raw(user_data_ptr) };
        let tnvl_status: HashMap<String, NscqTnvlStatus> =
            tnvl_status.into_iter().collect::<Result<_, _>>()?;
        Ok(tnvl_status[device])
    }

    /// Get the Trusted NVLink Mode (TNVL) status of all switches.
    ///
    /// # Returns
    ///
    /// * `Ok(HashMap<String, NscqTnvlStatus>)` containing the Trusted NVLink Mode (TNVL) status of all switches if successful.
    /// * `Err(NscqRc)` if there is an error retrieving the Trusted NVLink Mode (TNVL) status.
    pub fn get_all_switch_tnvl_status(&self) -> Result<HashMap<String, NscqTnvlStatus>, NscqRc> {
        let user_data_ptr: *mut Vec<Result<(String, NscqTnvlStatus), NscqRc>> =
            Box::into_raw(Box::new(Vec::new()));
        let user_data_ffi: UserData = user_data_ptr as UserData;
        self.session.path_observe(
            &format!("{ALL_SWITCHES}{TNVL_STATUS_PATH}"),
            NscqCallback::Tnvl(tnvl_status_callback),
            user_data_ffi,
            0,
        )?;
        let tnvl_status = *unsafe { Box::from_raw(user_data_ptr) };
        tnvl_status.into_iter().collect()
    }

    /// Check if the switch is in Trusted NVLink Mode (TNVL) mode.
    ///
    /// # Arguments
    ///
    /// * `device` - The device identifier for the switch.
    ///
    /// # Returns
    ///
    /// * `Ok(bool)` indicating whether the switch is in Trusted NVLink Mode (TNVL) mode if successful.
    /// * `Err(NscqRc)` if there is an error retrieving the Trusted NVLink Mode (TNVL) status.
    pub fn is_switch_tnvl_mode(&self, device: &str) -> Result<bool, NscqRc> {
        let tnvl_status = self.get_switch_tnvl_status(device)?;
        Ok(((tnvl_status >> TNVL_BIT_POSITION) & 1) == 1)
    }

    /// Check if the switch is in lock mode.
    ///
    /// # Arguments
    ///
    /// * `device` - The device identifier for the switch.
    ///
    /// # Returns
    ///
    /// * `Ok(bool)` indicating whether the switch is in lock mode if successful.
    /// * `Err(NscqRc)` if there is an error retrieving the Trusted NVLink Mode (TNVL) status.
    pub fn is_switch_lock_mode(&self, device: &str) -> Result<bool, NscqRc> {
        let tnvl_status = self.get_switch_tnvl_status(device)?;
        Ok(((tnvl_status >> LOCK_BIT_POSITION) & 1) == 1)
    }

    /// Get the attestation certificate chain for a specific switch.
    ///
    /// # Arguments
    ///
    /// * `device` - The device identifier for the switch.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` containing the attestation certificate chain if successful.
    /// * `Err(NscqRc)` if there is an error retrieving the certificate chain.
    pub fn get_switch_attestation_certificate_chain(
        &self,
        device: &str,
    ) -> Result<Vec<u8>, NscqRc> {
        let user_data_ptr: *mut Vec<Result<(String, Vec<u8>), NscqRc>> =
            Box::into_raw(Box::new(Vec::new()));
        let user_data_ffi: UserData = user_data_ptr as UserData;
        self.session.path_observe(
            &format!("/{device}{ATTESTATION_CERTIFICATE_CHAIN_PATH}"),
            NscqCallback::AttestationCertificate(attestation_certificate_callback),
            user_data_ffi,
            0,
        )?;
        let certificate_chain = *unsafe { Box::from_raw(user_data_ptr) };
        let certificate_chain: HashMap<String, Vec<u8>> =
            certificate_chain.into_iter().collect::<Result<_, _>>()?;
        Ok(certificate_chain[device].clone())
    }

    /// Get the attestation certificate chain for all switches.
    ///
    /// # Returns
    ///
    /// * `Ok(HashMap<String, Vec<u8>>) containing the attestation certificate chain for all switches if successful.
    /// * `Err(NscqRc)` if there is an error retrieving the certificate chain.
    pub fn get_all_switch_attestation_certificate_chain(
        &self,
    ) -> Result<HashMap<String, Vec<u8>>, NscqRc> {
        let user_data_ptr: *mut Vec<Result<(String, Vec<u8>), NscqRc>> =
            Box::into_raw(Box::new(Vec::new()));
        let user_data_ffi: UserData = user_data_ptr as UserData;
        self.session.path_observe(
            &format!("{ALL_SWITCHES}{ATTESTATION_CERTIFICATE_CHAIN_PATH}"),
            NscqCallback::AttestationCertificate(attestation_certificate_callback),
            user_data_ffi,
            0,
        )?;
        let certificate_chain = *unsafe { Box::from_raw(user_data_ptr) };
        certificate_chain.into_iter().collect()
    }

    /// Get the attestation report for a specific switch.
    ///
    /// # Arguments
    ///
    /// * `device` - The device identifier for the switch.
    /// * `nonce` - A 32-byte nonce used for the attestation report.
    ///
    /// # Returns
    ///
    /// * `Ok([u8; NSCQ_ATTESTATION_REPORT_SIZE])` containing the attestation report if successful.
    /// * `Err(NscqRc)` if there is an error retrieving the attestation report.
    pub fn get_switch_attestation_report(
        &self,
        device: &str,
        nonce: &[u8; 32],
    ) -> Result<[u8; NSCQ_ATTESTATION_REPORT_SIZE], NscqRc> {
        let nonce_ptr = nonce.as_ptr() as *mut c_void;
        let nonce_len = nonce.len() as u32;
        let input_arg = unsafe { &mut *nonce_ptr };
        self.session.set_input(input_arg, nonce_len, 0)?;

        let user_data_ptr: *mut Vec<Result<(String, [u8; NSCQ_ATTESTATION_REPORT_SIZE]), NscqRc>> =
            Box::into_raw(Box::new(Vec::new()));
        let user_data_ffi: UserData = user_data_ptr as UserData;

        self.session.path_observe(
            &format!("/{device}{ATTESTATION_REPORT_PATH}"),
            NscqCallback::AttestationReport(attestation_report_callback),
            user_data_ffi,
            0,
        )?;
        let attestation_reports = *unsafe { Box::from_raw(user_data_ptr) };
        let attestation_reports: HashMap<String, [u8; NSCQ_ATTESTATION_REPORT_SIZE]> =
            attestation_reports.into_iter().collect::<Result<_, _>>()?;
        Ok(attestation_reports[device])
    }

    /// Get the attestation report for all switches.
    ///
    /// # Arguments
    ///
    /// * `nonce` - A 32-byte nonce used for the attestation report.
    ///
    /// # Returns
    ///
    /// * `Ok(HashMap<String, [u8; NSCQ_ATTESTATION_REPORT_SIZE]>)` containing the attestation report for all switches if successful.
    /// * `Err(NscqRc)` if there is an error retrieving the attestation report.
    pub fn get_all_switch_attestation_report(
        &self,
        nonce: &[u8; 32],
    ) -> Result<HashMap<String, [u8; NSCQ_ATTESTATION_REPORT_SIZE]>, NscqRc> {
        let nonce_ptr = nonce.as_ptr() as *mut c_void;
        let nonce_len = nonce.len() as u32;
        let input_arg = unsafe { &mut *nonce_ptr };
        self.session.set_input(input_arg, nonce_len, 0)?;

        let user_data_ptr: *mut Vec<Result<(String, [u8; NSCQ_ATTESTATION_REPORT_SIZE]), NscqRc>> =
            Box::into_raw(Box::new(Vec::with_capacity(NSCQ_ATTESTATION_REPORT_SIZE)));

        let user_data_ffi: UserData = user_data_ptr as UserData;

        self.session.path_observe(
            &format!("{ALL_SWITCHES}{ATTESTATION_REPORT_PATH}"),
            NscqCallback::AttestationReport(attestation_report_callback),
            user_data_ffi,
            0,
        )?;
        let attestation_reports = *unsafe { Box::from_raw(user_data_ptr) };
        attestation_reports.into_iter().collect()
    }
}

/// Callback function for UUID observation.
unsafe extern "C" fn uuid_callback(
    _device: NscqUuid,
    rc: NscqRc,
    uuid: NscqUuid,
    user_data: UserData,
) {
    let label = nscq_uuid_to_label(uuid, 0);
    let vec_ptr = user_data as *mut Vec<Result<String, NscqRc>>;
    let vec_ref: &mut Vec<Result<String, NscqRc>> = unsafe { &mut *vec_ptr };
    if rc == 0 {
        match label {
            Ok(label) => vec_ref.push(Ok(label.into())),
            Err(rc) => vec_ref.push(Err(rc)),
        }
    } else {
        vec_ref.push(Err(rc));
    }
}

/// Callback function for architecture observation.
unsafe extern "C" fn architecture_callback(
    device: NscqUuid,
    rc: NscqRc,
    arch: NscqArch,
    user_data: UserData,
) {
    let label = nscq_uuid_to_label(device, 0);
    let vec_ptr = user_data as *mut Vec<Result<(String, NscqArch), NscqRc>>;
    let vec_ref: &mut Vec<Result<(String, NscqArch), NscqRc>> = unsafe { &mut *vec_ptr };
    if rc == 0 {
        match label {
            Ok(label) => vec_ref.push(Ok((label.into(), arch))),
            Err(rc) => vec_ref.push(Err(rc)),
        }
    } else {
        vec_ref.push(Err(rc));
    }
}

/// Callback function for Trusted NVLink Mode (TNVL) status observation.
unsafe extern "C" fn tnvl_status_callback(
    device: NscqUuid,
    rc: NscqRc,
    tnvl: c_char,
    user_data: UserData,
) {
    let label = nscq_uuid_to_label(device, 0);
    let vec_ptr = user_data as *mut Vec<Result<(String, NscqArch), NscqRc>>;
    let vec_ref: &mut Vec<Result<(String, NscqArch), NscqRc>> = unsafe { &mut *vec_ptr };
    if rc == 0 {
        match label {
            Ok(label) => vec_ref.push(Ok((label.into(), tnvl))),
            Err(rc) => vec_ref.push(Err(rc)),
        }
    } else {
        vec_ref.push(Err(rc));
    }
}

/// Callback function for attestation report observation.
unsafe extern "C" fn attestation_report_callback(
    device: NscqUuid,
    rc: NscqRc,
    report: NscqAttestationReport,
    user_data: UserData,
) {
    let label = nscq_uuid_to_label(device, 0);
    let vec_ptr =
        user_data as *mut Vec<Result<(String, [u8; NSCQ_ATTESTATION_REPORT_SIZE]), NscqRc>>;
    let vec_ref: &mut Vec<Result<(String, [u8; NSCQ_ATTESTATION_REPORT_SIZE]), NscqRc>> =
        unsafe { &mut *vec_ptr };
    if rc == 0 {
        match label {
            Ok(label) => vec_ref.push(Ok((label.into(), report.report))),
            Err(rc) => vec_ref.push(Err(rc)),
        }
    } else {
        vec_ref.push(Err(rc));
    }
}

/// Callback function for attestation certificate observation.
unsafe extern "C" fn attestation_certificate_callback(
    device: NscqUuid,
    rc: NscqRc,
    cert: NscqAttestationCertificate,
    user_data: UserData,
) {
    let label = nscq_uuid_to_label(device, 0);
    let vec_ptr = user_data as *mut Vec<Result<(String, Vec<u8>), NscqRc>>;
    let vec_ref: &mut Vec<Result<(String, Vec<u8>), NscqRc>> = unsafe { &mut *vec_ptr };
    if rc == 0 {
        match label {
            Ok(label) => vec_ref.push(Ok((
                label.into(),
                cert.cert_chain[..(cert.cert_chain_size as usize)].to_vec(),
            ))),
            Err(rc) => vec_ref.push(Err(rc)),
        }
    } else {
        vec_ref.push(Err(rc));
    }
}
