use std::collections::HashSet;

use thiserror::Error;

use crate::swtich_pdis::opaque_data_field_size::PDI_DATA_FIELD_SIZE;

pub type Result<T> = std::result::Result<T, NvidiaRemoteAttestationError>;

#[derive(Error, Debug)]
pub enum NvidiaRemoteAttestationError {
    #[error("NVML error: {0}")]
    NvmlError(#[from] nvml_wrapper::error::NvmlError),
    #[error("Invalid report length: {message}, expected {length_of_spdm_get_measurement_request_message} bytes, got {report_length} bytes")]
    InvalidReportLength {
        message: String,
        length_of_spdm_get_measurement_request_message: usize,
        report_length: usize,
    },
    #[error("Invalid SPDM measurement length: {message}, expected {length_of_field} bytes, got {report_length} bytes")]
    InvalidSpdmMeasurementLength {
        message: String,
        field: String,
        length_of_field: usize,
        report_length: usize,
    },
    #[error("Invalid opaque data type: {message}, opaque data length: {opaque_data_length} bytes, current position: {current_position} bytes")]
    InvalidOpaqueDataType {
        message: String,
        current_position: usize,
        opaque_data_length: usize,
    },
    #[error("Invalid opaque data size: {message}, opaque data length: {opaque_data_length} bytes, current position: {current_position} bytes")]
    InvalidOpaqueDataSize {
        message: String,
        current_position: usize,
        opaque_data_length: usize,
    },
    #[error("NV switch PIDS not found")]
    NvSwitchPidsNotFound,
    #[error("Invalid switch PDIS length: {message}, length: {length}")]
    InvalidSwitchPdisLength { message: String, length: usize },
    #[error("Invalid number of GPU attestation reports: {message}, expected {expected_length}, got {actual_length}")]
    InvalidGpuAttestationReportsLength {
        message: String,
        expected_length: usize,
        actual_length: usize,
    },
    #[error("Invalid switch PDIS topology, we found a mismatch between the expected and actual switch PDIS topology: expected {expected:?}, got {actual:?}")]
    InvalidSwitchPdisTopology {
        message: String,
        expected: HashSet<[u8; PDI_DATA_FIELD_SIZE]>,
        actual: HashSet<[u8; PDI_DATA_FIELD_SIZE]>,
    },
}
