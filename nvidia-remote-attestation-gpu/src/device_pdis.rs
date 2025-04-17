use crate::error::{NvidiaRemoteAttestationError, Result};

/// The expected length of the SPDM GET_MEASUREMENT request message part.
const LENGTH_OF_SPDM_GET_MEASUREMENT_REQUEST_MESSAGE: usize = 37;

/// The total number of PDIS.
const TOTAL_NUMBER_OF_PDIS: usize = 8;

/// The Switch Device PDIS.
pub struct SwitchDevicePdis {
    /// The Switch GPU PDIS.
    pub switch_device_gpu_pdis: Vec<[u8; opaque_data_field_size::PDI_DATA_FIELD_SIZE]>,
    /// The Switch PDIS.
    pub switch_pdis: [u8; opaque_data_field_size::PDI_DATA_FIELD_SIZE],
}

/// Extracts the Device PDIS from the GPU attestation report data.
///
/// # Arguments
///
/// * `report` - The GPU attestation report data to extract the Device PDIS from.
///
/// # Returns
///
/// * `Ok(device_pdis)` - If the Device PDIS is found.
/// * `Err(NvidiaRemoteAttestationError::InvalidReportLength)` - If the report is too short to contain a SPDM GET_MEASUREMENT request message.
/// * `Err(NvidiaRemoteAttestationError::InvalidSwitchPdisLength)` - If the Switch Device PDIS is not found.
pub fn extract_device_pdis_in_gpu_attestation_report_data(
    report: &[u8],
) -> Result<SwitchDevicePdis> {
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
    let (switch_device_gpu_pdis, switch_pdis) = parse_opaque_data_for_pdis(opaque_data)?;
    let switch_device_gpu_pdis = extract_switch_device_gpu_pdis(&switch_device_gpu_pdis)?;
    Ok(SwitchDevicePdis {
        switch_device_gpu_pdis,
        switch_pdis,
    })
}

/// Extracts the Switch PDIS from the Switch GPU PDIS.
///
/// # Arguments
///
/// * `switch_gpu_pdis` - The Switch GPU PDIS to extract the Switch PDIS from.
///
/// # Returns
///
/// * `Ok(switch_pdis)` - If the Switch PDIS is found.
/// * `Err(NvidiaRemoteAttestationError::InvalidSwitchPdisLength)` - If the Switch PDIS is not found.
fn extract_switch_device_gpu_pdis(
    switch_gpu_pdis: &[u8],
) -> Result<Vec<[u8; opaque_data_field_size::PDI_DATA_FIELD_SIZE]>> {
    let mut current_position = 0;
    let mut switch_device_gpu_pdis = Vec::with_capacity(TOTAL_NUMBER_OF_PDIS);
    if switch_gpu_pdis.len() < TOTAL_NUMBER_OF_PDIS * opaque_data_field_size::PDI_DATA_FIELD_SIZE {
        return Err(NvidiaRemoteAttestationError::InvalidSwitchPdisLength {
            message: "Switch GPU PDIS is too short to contain all the PDIS".to_string(),
            length: switch_gpu_pdis.len(),
        });
    }
    for _ in 0..TOTAL_NUMBER_OF_PDIS {
        let pdi = &switch_gpu_pdis
            [current_position..current_position + opaque_data_field_size::PDI_DATA_FIELD_SIZE];
        switch_device_gpu_pdis.push(pdi.try_into().unwrap());
        current_position += opaque_data_field_size::PDI_DATA_FIELD_SIZE;
    }
    Ok(switch_device_gpu_pdis)
}

/// Compute the position of the opaque data in the SPDM measurement.
///
/// # Arguments
///
/// * `spdm_measurement` - The SPDM measurement to compute the position of the opaque data in.
///
/// # Returns
///
/// * `Ok((opaque_data_start, opaque_data_length))` - If the position of the opaque data is valid.
/// * `Err(NvidiaRemoteAttestationError::InvalidSpdmMeasurementLength)` - If the position of the opaque data is invalid.
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

/// Check if the SPDM measurement length is valid.
///
/// # Arguments
///
/// * `spdm_measurement` - The SPDM measurement to check.
/// * `length_of_field` - The length of the field to check.
/// * `field_name` - The name of the field to check.
///
/// # Returns
///
/// * `Ok(())` - If the SPDM measurement length is valid.
/// * `Err(NvidiaRemoteAttestationError::InvalidSpdmMeasurementLength)` - If the SPDM measurement length is invalid.
fn check_spdm_measurement_length(
    spdm_measurement: &[u8],
    length_of_field: usize,
    field_name: &str,
) -> Result<()> {
    if spdm_measurement.len() < length_of_field {
        return Err(NvidiaRemoteAttestationError::InvalidSpdmMeasurementLength {
            message: format!(
                "{} is too short to contain a SPDM GET_MEASUREMENT request message",
                field_name
            ),
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
    /// The size of the parameter 1 field.
    pub const PARAM1: usize = 1;
    /// The size of the parameter 2 field.
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
    /// The type of the opaque data field for Device PDI.
    pub const OPAQUE_FIELD_ID_DEVICE_PDI: u16 = 22;
    /// The type of the opaque data field for Switch GPU PDIS.
    pub const OPAQUE_FIELD_ID_SWITCH_GPU_PDIS: u16 = 26;
}

fn parse_opaque_data_for_pdis(
    opaque_data: &[u8],
) -> Result<(Vec<u8>, [u8; opaque_data_field_size::PDI_DATA_FIELD_SIZE])> {
    let mut pos = 0;
    let mut found_switch_pdis: Option<[u8; opaque_data_field_size::PDI_DATA_FIELD_SIZE]> = None;
    let mut found_gpu_pdis_bytes: Option<Vec<u8>> = None;

    while pos < opaque_data.len() {
        if pos
            + opaque_data_field_size::OPAQUE_DATA_FIELD_TYPE
            + opaque_data_field_size::OPAQUE_DATA_FIELD_SIZE
            > opaque_data.len()
        {
            return Err(NvidiaRemoteAttestationError::InvalidSwitchPdisLength {
                message: "Opaque data too short for next type/size header".to_string(),
                length: opaque_data.len(),
            });
        }

        let data_type = u16::from_le_bytes([opaque_data[pos], opaque_data[pos + 1]]);
        pos += opaque_data_field_size::OPAQUE_DATA_FIELD_TYPE;
        let data_size = u16::from_le_bytes([opaque_data[pos], opaque_data[pos + 1]]) as usize;
        pos += opaque_data_field_size::OPAQUE_DATA_FIELD_SIZE;

        if pos + data_size > opaque_data.len() {
            return Err(NvidiaRemoteAttestationError::InvalidSwitchPdisLength {
                message: "Opaque data too short for expected data size".to_string(),
                length: opaque_data.len(),
            });
        }
        let current_data_slice = &opaque_data[pos..pos + data_size];

        match data_type {
            opaque_data_types::OPAQUE_FIELD_ID_DEVICE_PDI => {
                if data_size != opaque_data_field_size::PDI_DATA_FIELD_SIZE {
                    // Error: Incorrect size for Device PDI
                    return Err(NvidiaRemoteAttestationError::InvalidSwitchPdisLength {
                        message: "Incorrect size for Device PDI".to_string(),
                        length: data_size,
                    });
                }
                if found_switch_pdis.is_none() {
                    // Store only the first one found
                    found_switch_pdis = Some(current_data_slice.try_into().map_err(|_| {
                        NvidiaRemoteAttestationError::InvalidSwitchPdisLength {
                            message: "Failed to convert slice to array".to_string(),
                            length: data_size,
                        }
                    })?);
                }
            }
            opaque_data_types::OPAQUE_FIELD_ID_SWITCH_GPU_PDIS => {
                if found_gpu_pdis_bytes.is_none() {
                    found_gpu_pdis_bytes = Some(current_data_slice.to_vec());
                }
            }
            _ => {}
        }

        pos += data_size;

        if found_switch_pdis.is_some() && found_gpu_pdis_bytes.is_some() {
            break;
        }
    }

    match (found_gpu_pdis_bytes, found_switch_pdis) {
        (Some(gpu_pdis), Some(switch_pdis)) => Ok((gpu_pdis, switch_pdis)),
        (None, _) => Err(NvidiaRemoteAttestationError::SwitchGpuPdisNotFound),
        (_, None) => Err(NvidiaRemoteAttestationError::SwitchPdisNotFound),
    }
}
