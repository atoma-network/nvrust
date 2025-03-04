use nvml_wrapper::{Nvml};

type Result<T> = std::result::Result<T, AttestationReportError>;

#[derive(Debug, thiserror::Error)]
pub enum AttestationReportError {
    #[error("Failed to fetch attestation report")]
    FetchError(String),
    #[error("Failed to initialize NVML")]
    NvmlInitError(String),
}

fn fetch_attestation_report(gpu_index: usize, nonce: Vec<u8>) -> Result<Vec<u8>> {
    let nvml = Nvml::init().map_err(|e| AttestationReportError::NvmlInitError(e.to_string()))?;
    let device = nvml.device_by_index(gpu_index as u32).map_err(|e| AttestationReportError::NvmlInitError(e.to_string()))?;
    let report = device.attestation_report(nonce).map_err(|e| AttestationReportError::NvmlInitError(e.to_string()))?;
    Ok(report)  
}
