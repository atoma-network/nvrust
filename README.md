# NVRust

A Rust library for interacting with NVIDIA GPU attestation functions through PyO3.

## Overview

This library provides Rust bindings to call Python functions from the NVIDIA verification library, specifically to fetch attestation reports from GPUs.

## Requirements

- Rust (edition 2021)
- Python 3.6+
- The Python NVIDIA verification library (`pynvml`) installed in your Python environment
- NVIDIA GPU with appropriate drivers

## Installation

Add the library to your Cargo.toml:

```toml
[dependencies]
nvrust = { path = "/path/to/nvrust" }
```

## Usage

```rust
use nvrust::fetch_attestation_report;

fn main() {
    // Create a nonce (32 bytes)
    let nonce = vec![0u8; 32]; 
    
    // GPU index (usually 0 for the first GPU)
    let gpu_index = 0;
    
    // Fetch the attestation report
    match fetch_attestation_report(gpu_index, nonce) {
        Ok(report) => {
            println!("Successfully fetched attestation report!");
            println!("Report size: {} bytes", report.len());
        },
        Err(e) => {
            eprintln!("Error fetching attestation report: {}", e);
        }
    }
}
```

## Library Functions

### `fetch_attestation_report(index: usize, nonce: Vec<u8>) -> Result<Vec<u8>, NvmlError>`

Fetches an attestation report from the specified GPU, using the provided nonce.

- `index`: The index of the GPU (0 for the first GPU)
- `nonce`: A vector of bytes to use as the nonce for the attestation request

Returns a vector of bytes containing the attestation report, or an error if the operation failed.

### `call_fetch_attestation_report(index: usize, nonce: Vec<u8>) -> Result<Vec<u8>, NvmlError>`

An alternative implementation that directly calls the fetch_attestation_report method on a temporary NvmlHandler instance.

## License

[Your license information here]
