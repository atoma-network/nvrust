use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NvmlError {
    #[error("Python error: {0}")]
    PythonError(String),

    #[error("Failed to initialize Python interpreter: {0}")]
    PyInitError(#[from] PyErr),

    #[error("Failed to convert to/from Python: {0}")]
    ConversionError(String),
}

/// Fetches an attestation report from the GPU using the Python NvmlHandler class
///
/// # Arguments
///
/// * `index` - The index of the GPU
/// * `nonce` - The nonce bytes for the attestation report
///
/// # Returns
///
/// A vector of bytes containing the attestation report
pub fn fetch_attestation_report(index: usize, nonce: Vec<u8>) -> Result<Vec<u8>, NvmlError> {
    Python::with_gil(|py| {
        let sys = py.import("sys")?;
        let path = sys.getattr("path")?;

        // Add the submodule path
        let manifest_dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("external/nvtrust");
        let repo_path = manifest_dir.to_str().unwrap();

        path.call_method1("insert", (0, repo_path))?;

        // Import the Python module containing NvmlHandler
        let nvml_module = PyModule::import(py, "verifier.nvml.nvml_handler").map_err(|e| {
            NvmlError::PythonError(format!("Failed to import Python module: {}", e))
        })?;

        // Import settings module
        let settings_module = PyModule::import(py, "verifier.config").map_err(|e| {
            NvmlError::PythonError(format!("Failed to import settings module: {}", e))
        })?;

        // Get BaseSettings class
        let base_settings = settings_module
            .getattr("BaseSettings")
            .map_err(|e| NvmlError::PythonError(format!("Failed to get BaseSettings: {}", e)))?;

        // Create a PyBytes object from the nonce vector
        let py_nonce = PyBytes::new(py, &nonce);

        // Initialize NvmlHandler
        let nvml_handler_class = nvml_module.getattr("NvmlHandler").map_err(|e| {
            NvmlError::PythonError(format!("Failed to get NvmlHandler class: {}", e))
        })?;

        // Call NvmlHandler.init_nvml() static method to initialize NVML
        nvml_handler_class
            .getattr("init_nvml")
            .map_err(|e| NvmlError::PythonError(format!("Failed to get init_nvml method: {}", e)))?
            .call0()
            .map_err(|e| NvmlError::PythonError(format!("Failed to call init_nvml: {}", e)))?;

        // Call NvmlHandler.get_number_of_gpus() to initialize handles
        nvml_handler_class
            .getattr("get_number_of_gpus")
            .map_err(|e| {
                NvmlError::PythonError(format!("Failed to get get_number_of_gpus method: {}", e))
            })?
            .call0()
            .map_err(|e| {
                NvmlError::PythonError(format!("Failed to call get_number_of_gpus: {}", e))
            })?;

        // Create a mock settings object (required by NvmlHandler constructor)
        let settings = base_settings.call0().map_err(|e| {
            NvmlError::PythonError(format!("Failed to create BaseSettings instance: {}", e))
        })?;

        // Create an instance of NvmlHandler
        let nvml_handler = nvml_handler_class
            .call1((index, py_nonce, settings))
            .map_err(|e| {
                NvmlError::PythonError(format!("Failed to create NvmlHandler instance: {}", e))
            })?;

        // Call fetch_attestation_report directly
        // This step is optional since the constructor already calls fetch_attestation_report
        let report = nvml_handler.getattr("AttestationReport").map_err(|e| {
            NvmlError::PythonError(format!("Failed to get AttestationReport: {}", e))
        })?;

        // Convert the Python bytes object to a Rust Vec<u8>
        let rust_bytes: Vec<u8> = report.extract().map_err(|e| {
            NvmlError::PythonError(format!("Failed to extract report bytes: {}", e))
        })?;

        // Make sure to shut down NVML
        nvml_handler_class
            .getattr("close_nvml")
            .map_err(|e| NvmlError::PythonError(format!("Failed to get close_nvml method: {}", e)))?
            .call0()
            .map_err(|e| NvmlError::PythonError(format!("Failed to call close_nvml: {}", e)))?;

        Ok(rust_bytes)
    })
}

/// Alternative approach: Directly call fetch_attestation_report method on an existing NvmlHandler instance
/// This is useful if you already have a NvmlHandler instance from elsewhere
pub fn call_fetch_attestation_report(index: usize, nonce: Vec<u8>) -> Result<Vec<u8>, NvmlError> {
    Python::with_gil(|py| {
        let sys = py.import("sys")?;
        let path = sys.getattr("path")?;

        // Add the submodule path
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("external/nvtrust");
        let repo_path = manifest_dir
            .to_str()
            .unwrap();

        path.call_method1("insert", (0, repo_path))?;

        // Import the Python module containing NvmlHandler
        let nvml_module = PyModule::import(py, "verifier.nvml.nvml_handler").map_err(|e| {
            NvmlError::PythonError(format!("Failed to import Python module: {}", e))
        })?;

        // Get NvmlHandler class
        let nvml_handler_class = nvml_module.getattr("NvmlHandler").map_err(|e| {
            NvmlError::PythonError(format!("Failed to get NvmlHandler class: {}", e))
        })?;

        // Initialize NVML
        nvml_handler_class
            .getattr("init_nvml")
            .map_err(|e| NvmlError::PythonError(format!("Failed to get init_nvml method: {}", e)))?
            .call0()
            .map_err(|e| NvmlError::PythonError(format!("Failed to call init_nvml: {}", e)))?;

        // Get handles
        nvml_handler_class
            .getattr("get_number_of_gpus")
            .map_err(|e| {
                NvmlError::PythonError(format!("Failed to get get_number_of_gpus method: {}", e))
            })?
            .call0()
            .map_err(|e| {
                NvmlError::PythonError(format!("Failed to call get_number_of_gpus: {}", e))
            })?;

        // Create a temporary NvmlHandler instance
        let temp_handler = nvml_handler_class.call0().map_err(|e| {
            NvmlError::PythonError(format!("Failed to create temporary NvmlHandler: {}", e))
        })?;

        // Create a PyBytes object from the nonce vector
        let py_nonce = PyBytes::new(py, &nonce);

        // Call fetch_attestation_report directly
        let report = temp_handler
            .call_method1("fetch_attestation_report", (index, py_nonce))
            .map_err(|e| {
                NvmlError::PythonError(format!("Failed to call fetch_attestation_report: {}", e))
            })?;

        // Convert the Python bytes object to a Rust Vec<u8>
        let rust_bytes: Vec<u8> = report.extract().map_err(|e| {
            NvmlError::PythonError(format!("Failed to extract report bytes: {}", e))
        })?;

        // Clean up NVML
        nvml_handler_class
            .getattr("close_nvml")
            .map_err(|e| NvmlError::PythonError(format!("Failed to get close_nvml method: {}", e)))?
            .call0()
            .map_err(|e| NvmlError::PythonError(format!("Failed to call close_nvml: {}", e)))?;

        Ok(rust_bytes)
    })
}
