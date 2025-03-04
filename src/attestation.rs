use nvml_wrapper::error::{nvml_sym, nvml_try, NvmlError};
use nvml_wrapper_sys::bindings::{nvmlConfComputeGpuAttestationReport_t, nvmlDevice_t, NvmlLib};

const LIB_PATH: &str = "libnvidia-ml.so";

type Result<T> = std::result::Result<T, AttestationReportError>;

#[derive(Debug, thiserror::Error)]
pub enum AttestationReportError {
    #[error("Failed to fetch attestation report")]
    FetchError(String),
    #[error("Failed to initialize NVML")]
    NvmlInitError(#[from] NvmlError),
    #[error("Failed to initialize NVML lib")]
    NvmlLibInitError(#[from] libloading::Error),
}

unsafe fn initialize_nvml_lib() -> Result<NvmlLib> {
    let nvml_lib = NvmlLib::new(LIB_PATH)?;
    Ok(nvml_lib)
}

unsafe fn device_by_index(nvml_lib: &NvmlLib, index: usize) -> Result<nvmlDevice_t> {
    let sym = nvml_sym(nvml_lib.nvmlDeviceGetHandleByIndex_v2.as_ref())?;

    unsafe {
        let mut device: nvmlDevice_t = std::mem::zeroed();
        nvml_try(sym(index, &mut device))?;

        Ok(device)
    }
}

pub fn fetch_attestation_report(gpu_index: usize, nonce: Vec<u8>) -> Result<Vec<u8>> {
    let report_t: *mut nvmlConfComputeGpuAttestationReport_t = std::ptr::null_mut();
    let sym = NvmlLib::nvmlDeviceGetConfComputeGpuAttestationReport;

    unsafe {
        let nvml_lib = initialize_nvml_lib()?;
        let device = device_by_index(&nvml_lib, gpu_index)?;
        nvml_try(sym(&nvml_lib, device, report_t))?;

        let mut report = Vec::new();
        report.extend_from_slice((*report_t).attestationReport.as_slice());

        Ok(report)
    }
}
