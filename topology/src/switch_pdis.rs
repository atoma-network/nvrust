use crate::error::{NvidiaRemoteAttestationError, Result};

/// The expected length of the SPDM `GET_MEASUREMENT` request message part.
const LENGTH_OF_SPDM_GET_MEASUREMENT_REQUEST_MESSAGE: usize = 37;

/// Extracts `NVSwitch` `Platform Data Information` (PDI) entries from a full GPU attestation report.
///
/// This function orchestrates the process of parsing an attestation report to find and extract
/// individual `NVSwitch` `Platform Data Information` (PDI) entries. It involves:
/// 1. Identifying the SPDM measurement portion of the report.
/// 2. Locating the TLV-encoded opaque data within the SPDM measurement.
/// 3. Searching the opaque data for the specific TLV entry containing concatenated `NVSwitch` `Platform Data Information` (PDI) data
///    (`OPAQUE_FIELD_ID_SWITCH_GPU_PDIS`).
/// 4. Parsing the concatenated PDI data into distinct, fixed-size PDI entries.
///
/// # Arguments
///
/// * `report` - A byte slice representing the complete GPU attestation report.
///
/// # Returns
///
/// Returns a `Result` containing a `Vec<[u8; opaque_data_field_size::PDI_DATA_FIELD_SIZE]>`,
/// where each element is a fixed-size array representing a single `NVSwitch` `Platform Data Information` (PDI) entry.
///
/// # Errors
///
/// This function can return several errors, originating from the different parsing steps:
/// * `NvidiaRemoteAttestationError::InvalidReportLength`: If the input `report` is shorter than
///   the expected minimum length for an SPDM `GET_MEASUREMENT` request message part.
/// * Errors propagated from `compute_opaque_data_position` (e.g.,
///   `InvalidSpdmMeasurementLength`) if the SPDM measurement structure is invalid.
/// * Errors propagated from `extract_switch_gpu_pdis_in_opaque_data` (e.g.,
///   `InvalidOpaqueDataType`, `InvalidOpaqueDataSize`, `InvalidOpaqueDataValue`,
///   `NvSwitchPdisNotFound`) if the opaque data TLV structure is invalid or the
///   `OPAQUE_FIELD_ID_SWITCH_GPU_PDIS` field is missing or malformed.
/// * Errors propagated from `extract_switch_pdis` (e.g., `InvalidSwitchPdisLength`)
///   if the extracted concatenated PDI data length is not a multiple of the expected
///   individual PDI size.
pub fn extract_switch_pdis_in_gpu_attestation_report_data(
    report: &[u8],
) -> Result<Vec<[u8; opaque_data_field_size::PDI_DATA_FIELD_SIZE]>> {
    if report.len() < LENGTH_OF_SPDM_GET_MEASUREMENT_REQUEST_MESSAGE {
        return Err(NvidiaRemoteAttestationError::InvalidReportLength {
            message: "Report is too short to contain a SPDM GET_MEASUREMENT request message"
                .to_string(),
            length_of_spdm_get_measurement_request_message:
                LENGTH_OF_SPDM_GET_MEASUREMENT_REQUEST_MESSAGE,
            report_length: report.len(),
        });
    }
    let spdm_measurement = &report[LENGTH_OF_SPDM_GET_MEASUREMENT_REQUEST_MESSAGE..];
    let (opaque_data_start, opaque_data_length) = compute_opaque_data_position(spdm_measurement)?;
    let opaque_data = &spdm_measurement[opaque_data_start..opaque_data_start + opaque_data_length];
    let switch_gpu_pdis = extract_switch_gpu_pdis_in_opaque_data(opaque_data)?;
    let switch_pdis = extract_switch_pdis(&switch_gpu_pdis)?;
    Ok(switch_pdis)
}

/// Extracts individual PDI (Platform Data Information) entries from a concatenated byte slice.
///
/// This function assumes that the input `switch_gpu_pdis` slice is composed of one or more
/// PDI entries, each having a fixed size defined by `opaque_data_field_size::PDI_DATA_FIELD_SIZE`.
/// It segments the input slice into these fixed-size chunks.
///
/// # Arguments
///
/// * `switch_gpu_pdis` - A byte slice containing the concatenated PDI data, typically extracted
///   from the `OPAQUE_FIELD_ID_SWITCH_GPU_PDIS` field of an SPDM measurement's opaque data.
///
/// # Returns
///
/// Returns a `Result` containing a `Vec<[u8; opaque_data_field_size::PDI_DATA_FIELD_SIZE]>`,
/// where each element is a fixed-size array representing a single PDI entry.
///
/// # Errors
///
/// Returns `NvidiaRemoteAttestationError::InvalidSwitchPdisLength` if the length of the
/// `switch_gpu_pdis` slice is not an exact multiple of `opaque_data_field_size::PDI_DATA_FIELD_SIZE`.
fn extract_switch_pdis(
    switch_gpu_pdis: &[u8],
) -> Result<Vec<[u8; opaque_data_field_size::PDI_DATA_FIELD_SIZE]>> {
    if switch_gpu_pdis.len() % opaque_data_field_size::PDI_DATA_FIELD_SIZE != 0 {
        return Err(NvidiaRemoteAttestationError::InvalidSwitchPdisLength {
            message: format!(
                "Switch PDIS length is not a multiple of {}",
                opaque_data_field_size::PDI_DATA_FIELD_SIZE
            ),
            length: switch_gpu_pdis.len(),
        });
    }
    let mut switch_pdis = Vec::new();
    let mut current_position = 0;
    while current_position < switch_gpu_pdis.len() {
        let pdi = &switch_gpu_pdis
            [current_position..current_position + opaque_data_field_size::PDI_DATA_FIELD_SIZE];
        switch_pdis.push(pdi.try_into().unwrap());
        current_position += opaque_data_field_size::PDI_DATA_FIELD_SIZE;
    }
    Ok(switch_pdis)
}

/// Extracts the Switch GPU PDI (Platform Data Information) data from the TLV-encoded opaque data.
///
/// The opaque data is expected to contain a sequence of Type-Length-Value (TLV) entries.
/// This function iterates through these entries, searching for the one with the type
/// identified as `OPAQUE_FIELD_ID_SWITCH_GPU_PDIS`.
///
/// # Arguments
///
/// * `opaque_data` - A byte slice containing the TLV-encoded opaque data extracted from
///   an SPDM measurement response.
///
/// # Returns
///
/// Returns a `Result` containing a `Vec<u8>` with the raw byte value of the
/// `OPAQUE_FIELD_ID_SWITCH_GPU_PDIS` field if found.
///
/// # Errors
///
/// Returns an error in the following cases:
/// * `NvidiaRemoteAttestationError::InvalidOpaqueDataType`: If reading the type field
///   for a TLV entry fails (e.g., due to insufficient data).
/// * `NvidiaRemoteAttestationError::InvalidOpaqueDataSize`: If reading the size field
///   for a TLV entry fails (e.g., due to insufficient data).
/// * `NvidiaRemoteAttestationError::NvSwitchPdisNotFound`: If the loop completes without
///   finding a TLV entry with the type `OPAQUE_FIELD_ID_SWITCH_GPU_PDIS`.
fn extract_switch_gpu_pdis_in_opaque_data(opaque_data: &[u8]) -> Result<Vec<u8>> {
    let mut current_position = 0;
    while current_position < opaque_data.len() {
        let data_type = opaque_data
            [current_position..current_position + opaque_data_field_size::OPAQUE_DATA_FIELD_TYPE]
            .try_into()
            .map_err(|_| NvidiaRemoteAttestationError::InvalidOpaqueDataType {
                message: "Invalid opaque data type".to_string(),
                current_position,
                opaque_data_length: opaque_data.len(),
            })?;
        let data_type = u16::from_le_bytes(data_type);
        current_position += opaque_data_field_size::OPAQUE_DATA_FIELD_TYPE;
        let data_size = opaque_data
            [current_position..current_position + opaque_data_field_size::OPAQUE_DATA_FIELD_SIZE]
            .try_into()
            .map_err(|_| NvidiaRemoteAttestationError::InvalidOpaqueDataSize {
                message: "Invalid opaque data size".to_string(),
                current_position,
                opaque_data_length: opaque_data.len(),
            })?;
        let data_size = u16::from_le_bytes(data_size);
        let data_size = data_size as usize;
        current_position += opaque_data_field_size::OPAQUE_DATA_FIELD_SIZE;
        if data_type == opaque_data_types::OPAQUE_FIELD_ID_SWITCH_PDI {
            return Ok(opaque_data[current_position..current_position + data_size].to_vec());
        }
        current_position += data_size;
    }
    Err(NvidiaRemoteAttestationError::NvSwitchPdisNotFound)
}

/// Computes the starting position and length of the opaque data within an SPDM measurement response.
///
/// This function parses the initial fields of the SPDM measurement response according
/// to the structure defined in `spdm_response_field_size` to determine the offset
/// and size of the opaque data segment.
///
/// # Arguments
///
/// * `spdm_measurement` - A byte slice representing the SPDM measurement response data,
///   starting *after* the initial SPDM `GET_MEASUREMENT` request message part.
///
/// # Returns
///
/// Returns a `Result` containing a tuple `(usize, usize)`:
///   - The first element is the starting byte index of the opaque data within `spdm_measurement`.
///   - The second element is the length of the opaque data in bytes.
///
/// # Errors
///
/// Returns `NvidiaRemoteAttestationError::InvalidSpdmMeasurementLength` if the
/// `spdm_measurement` slice is too short to contain the necessary fields leading up to
/// or including the opaque data length field. This check is performed by internal calls to
/// `check_spdm_measurement_length`.
fn compute_opaque_data_position(spdm_measurement: &[u8]) -> Result<(usize, usize)> {
    let mut opaque_data_start = 0;

    opaque_data_start += spdm_response_field_size::SPDM_VERSION;
    opaque_data_start += spdm_response_field_size::REQUEST_RESPONSE_CODE;
    opaque_data_start += spdm_response_field_size::PARAM1;
    opaque_data_start += spdm_response_field_size::PARAM2;
    opaque_data_start += spdm_response_field_size::NUMBER_OF_BLOCKS;

    check_spdm_measurement_length(spdm_measurement, opaque_data_start, "Measurement Record")?;

    let measurement_record_length = u32::from_le_bytes([
        spdm_measurement[opaque_data_start],
        spdm_measurement[opaque_data_start + 1],
        spdm_measurement[opaque_data_start + 2],
        0, // Pad with 0 for the 4th byte
    ]) as usize;

    opaque_data_start +=
        spdm_response_field_size::MEASUREMENT_RECORD_LENGTH + measurement_record_length;
    opaque_data_start += spdm_response_field_size::NONCE;

    check_spdm_measurement_length(spdm_measurement, opaque_data_start, "Opaque Data")?;

    let opaque_data_length = u16::from_le_bytes([
        spdm_measurement[opaque_data_start],
        spdm_measurement[opaque_data_start + 1],
    ]) as usize;
    opaque_data_start += spdm_response_field_size::OPAQUE_DATA;

    Ok((opaque_data_start, opaque_data_length))
}

/// Checks if the provided SPDM measurement byte slice is long enough to contain
/// a specific field, considering the cumulative size of all preceding fields.
///
/// # Arguments
///
/// * `spdm_measurement` - The byte slice representing the SPDM measurement data.
/// * `length_of_field` - The minimum expected length of `spdm_measurement` required
///   to contain the specified field and all fields before it.
/// * `field_name` - A descriptive name of the field being checked for error reporting.
///
/// # Returns
///
/// Returns `Ok(())` if the `spdm_measurement` length is greater than or equal to
/// `length_of_field`.
///
/// # Errors
///
/// Returns `NvidiaRemoteAttestationError::InvalidSpdmMeasurementLength` if
/// `spdm_measurement.len()` is less than `length_of_field`.
fn check_spdm_measurement_length(
    spdm_measurement: &[u8],
    length_of_field: usize,
    field_name: &str,
) -> Result<()> {
    if spdm_measurement.len() < length_of_field {
        return Err(NvidiaRemoteAttestationError::InvalidSpdmMeasurementLength {
            message: "SPDM measurement is too short to contain all the fields".to_string(),
            field: field_name.to_string(),
            length_of_field,
            report_length: spdm_measurement.len(),
        });
    }
    Ok(())
}

pub mod spdm_response_field_size {
    /// The size of the SPDM version field.
    pub const SPDM_VERSION: usize = 1;
    /// The size of the request response code field.
    pub const REQUEST_RESPONSE_CODE: usize = 1;
    /// The size of the param1 field.
    pub const PARAM1: usize = 1;
    /// The size of the param2 field.
    pub const PARAM2: usize = 1;
    /// The size of the number of blocks field.
    pub const NUMBER_OF_BLOCKS: usize = 1;
    /// The size of the measurement record length field.
    pub const MEASUREMENT_RECORD_LENGTH: usize = 3;
    /// The size of the nonce field.
    pub const NONCE: usize = 32;
    /// The size of the opaque data field.
    pub const OPAQUE_DATA: usize = 2;
}

pub mod opaque_data_field_size {
    /// The size of the opaque data field type field.
    pub const OPAQUE_DATA_FIELD_TYPE: usize = 2;
    /// The size of the opaque data field size field.
    pub const OPAQUE_DATA_FIELD_SIZE: usize = 2;
    /// The size of the PDI data field.
    pub const PDI_DATA_FIELD_SIZE: usize = 8;
}

pub mod opaque_data_types {
    /// The type of the opaque data field for Switch GPU PDIS.
    pub const OPAQUE_FIELD_ID_SWITCH_PDI: u16 = 22;
}
