# nvrust: Rust Crates for NVIDIA Confidential Computing Attestation

This repository contains a collection of Rust crates designed to facilitate NVIDIA Confidential Computing features, particularly focusing on remote attestation for NVIDIA GPUs and NVSwitches. It provides Rust alternatives to some of the functionalities offered by the official Python-based [NVIDIA nvtrust](https://github.com/NVIDIA/nvtrust) repository.

## Background: NVIDIA Confidential Computing and Attestation

**Confidential Computing** aims to protect data and code *while they are being processed* (i.e., "data in use"). For NVIDIA GPUs (starting with the Hopper H100 architecture), this means creating a secure environment where sensitive data and valuable AI models are isolated and protected from unauthorized access or modification, even from privileged software like the hypervisor or the system administrator.

**Attestation** is the process of verifying the trustworthiness of this environment. It allows a relying party (e.g., a user or an orchestrator) to gain confidence that the GPU hardware, firmware, and drivers are genuine and running in a secure, confidential state. This typically involves:
1.  **Evidence Collection:** The GPU (or NVSwitch, in multi-GPU setups) generates an attestation report containing measurements of its hardware, firmware, and software configuration. This process usually incorporates a unique, time-sensitive value called a **nonce** provided by the relying party to prevent replay attacks. The GPU also provides a certificate chain to prove its identity.
2.  **Verification:** The collected evidence (attestation report + certificates) and the nonce are sent to a trusted verification service (like the NVIDIA Remote Attestation Service - NRAS).
3.  **Result:** The verification service checks the evidence against known good measurements, validates the certificate chain, and verifies the nonce. It returns a signed attestation token (often a JWT) containing claims about the trustworthiness of the attested device.

## Crates

This workspace includes the following crates:

### 1. `remote-attestation-verifier`

This crate provides the core functionality for performing *remote* attestation of NVIDIA GPUs and NVSwitches using Rust.

*   **GPU Attestation (`remote_gpu_attestation.rs`):**
    *   Provides the `verify_gpu_attestation` async function.
    *   Takes GPU evidence (collected via libraries like `nvml-wrapper`) and a nonce.
    *   Sends the evidence to the configured NVIDIA Remote Attestation Service (NRAS) URL for GPUs.
    *   Handles communication with the NRAS, including setting necessary headers (e.g., for OCSP checks, authorization).
    *   Parses the NRAS response, extracts the attestation result (pass/fail), and returns the full JSON response containing the attestation token.
    *   Configurable options include the NRAS URL, timeout, claims version, and whether to allow certificates with a "hold" status during OCSP checks.
*   **NVSwitch Attestation (`remote_nvswitch_attestation.rs`):**
    *   Provides the `collect_nvswitch_evidence` function to gather attestation reports and certificates from NVSwitches using the `nvswitch-nscq` crate.
    *   Provides the `verify_nvswitch_attestation` async function.
    *   Takes NVSwitch evidence (collected using `collect_nvswitch_evidence`) and a nonce.
    *   Sends the evidence to the configured NRAS URL for NVSwitches.
    *   Handles communication and response parsing similar to GPU attestation.
*   **Shared Components:** Includes common types (`DeviceEvidence`, `NvSwitchEvidence`), error handling (`AttestError`), constants (default URLs, JSON keys), and utility functions (e.g., for decoding NRAS tokens).

### 2. `nvswitch-nscq`

This crate provides a safe Rust wrapper around NVIDIA's NVSwitch Secure Channel Query (NSCQ) library (`libnscq`). NSCQ is used to communicate securely with NVSwitches for administrative tasks, including retrieving attestation evidence.

*   Provides an `NscqHandler` to manage sessions with NVSwitches.
*   Offers functions to:
    *   Get UUIDs of connected NVSwitches.
    *   Retrieve attestation reports (`get_switch_attestation_report`) using a provided nonce.
    *   Retrieve attestation certificate chains (`get_switch_attestation_certificate_chain`).
*   Handles FFI bindings and error conversions.

### 3. `topology`

This crate focuses on verifying the physical topology of interconnected GPUs and NVSwitches using data embedded within their attestation reports. This is crucial in multi-GPU systems to ensure the reported connections are consistent and haven't been tampered with.

*   Relies on Platform Data Information (PDI) embedded in the opaque data fields of attestation reports.
*   **GPU Topology Check (`gpu_topology_check`):**
    *   Analyzes a set of GPU attestation reports (typically 8).
    *   Extracts the PDIs of connected NVSwitches from each report.
    *   Verifies that all GPUs report the same consistent set of connected NVSwitches (typically 4 unique, enabled switches).
*   **Switch Topology Check (`switch_topology_check`):**
    *   Analyzes a set of NVSwitch attestation reports (typically 4).
    *   Extracts the PDIs of connected GPUs from each report.
    *   Verifies that each switch report originates from one of the switches identified in the `gpu_topology_check`.
    *   Verifies that all switches report the same consistent set of connected GPUs, matching the expected number of GPUs (`num_gpus`).
*   Includes functions for extracting GPU PDIs and Switch PDIs from report data.
*   Defines specific error types related to topology validation failures.

## Relation to `NVIDIA/nvtrust`

The `NVIDIA/nvtrust` repository provides the official Python SDK and tools for NVIDIA attestation. `nvrust` aims to provide similar capabilities within the Rust ecosystem, allowing developers to build Rust-native applications and services that leverage NVIDIA's Confidential Computing and attestation features without needing a Python dependency for these specific tasks. While `nvtrust` might offer a broader set of tools (e.g., local verifiers, host tools), `nvrust` focuses on the core remote attestation verification logic and necessary underlying components like NSCQ interaction and topology checks. This allows for a more lightweight and efficient implementation, particularly in environments where Python is not available or preferred.

## Projects Using nvrust

The following projects are actively using crates from the `nvrust` repository:

*   **[atoma-node](https://github.com/atoma-network/atoma-node):** A core component of the Atoma Network, leveraging `nvrust` for NVIDIA GPU attestation within its decentralized AI infrastructure.
*   **[atoma-proxy](https://github.com/atoma-network/atoma-proxy):** Another service within the Atoma Network ecosystem, utilizing `nvrust` for remote attestation verification functionality.

## Usage

Below is a conceptual example of how to use the `nvrust` crates to verify a GPU and NVSwitch attestation.

```rust,ignore
// Example (Conceptual - adapt based on actual API and setup)
use remote_attestation_verifier::{verify_gpu_attestation, verify_nvswitch_attestation, AttestRemoteOptions, DeviceEvidence, NvSwitchEvidence};
use nvswitch_nscq::NscqHandler;
// Assume nvml_wrapper is used to get GPU evidence
// use nvml_wrapper::Nvml;
use rand::Rng;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let nonce_bytes = rand::thread_rng().gen::<[u8; 32]>();
    let nonce_hex = hex::encode(nonce_bytes);

    // --- GPU Attestation ---
    let nvml = Nvml::init()?;
    let device = nvml.device_by_index(0)?;
    // Populate gpu_evidence_vec using nvml methods like
    let report = device.confidential_compute_gpu_attestation_report(&nonce_bytes);
    let certificate = device.confidential_compute_gpu_certificate();
    // Base64 encode and store in DeviceEvidence structs
    let evidence = DeviceEvidence {
        report: report.to_base64(),
        certificate: certificate.to_base64(),
    };
    let mut gpu_evidence_vec: Vec<DeviceEvidence> = Vec::new();
    gpu_evidence_vec.push(evidence);

    println!("Verifying GPU Attestation...");
    match verify_gpu_attestation(&gpu_evidence_vec, &nonce_hex, AttestRemoteOptions::default()).await {
        Ok((passed, jwt_response)) => {
            println!("GPU Attestation Passed: {}", passed);
            // Process jwt_response if needed
        }
        Err(e) => eprintln!("GPU Attestation Failed: {}", e),
    }

    // --- NVSwitch Attestation ---
    if let Ok(nscq) = NscqHandler::new() {
         println!("Collecting NVSwitch Evidence...");
         match remote_attestation_verifier::remote_nvswitch_attestation::collect_nvswitch_evidence(&nscq, &nonce_bytes) {
            Ok(nvswitch_evidence) => {
                if !nvswitch_evidence.is_empty() {
                     println!("Verifying NVSwitch Attestation...");
                    match verify_nvswitch_attestation(&nvswitch_evidence, &nonce_hex, AttestRemoteOptions::default()).await {
                        Ok((passed, jwt_response)) => {
                            println!("NVSwitch Attestation Passed: {}", passed);
                            // Process jwt_response if needed
                        }
                        Err(e) => eprintln!("NVSwitch Attestation Failed: {}", e),
                    }
                } else {
                    println!("No NVSwitch evidence collected.");
                }
            }
            Err(e) => eprintln!("Failed to collect NVSwitch evidence: {}", e),
         }
    } else {
        println!("NSCQ Handler initialization failed, skipping NVSwitch attestation.");
    }

    // --- Topology Check (Conceptual) ---
    let gpu_reports: Vec<&[u8]> = gpu_evidence_vec.iter().map(|e| e.evidence_bytes()).collect(); // Need method to get bytes
    let switch_reports: Vec<&[u8]> = nvswitch_evidence.iter().map(|e| e.evidence_bytes()).collect(); // Need method to get bytes
    if let Ok(unique_switches) = topology::gpu_topology_check(&gpu_reports) {
       println!("GPU Topology Check Passed. Unique Switches: {:?}", unique_switches);
       match topology::switch_topology_check(&switch_reports, gpu_evidence_vec.len(), unique_switches) {
           Ok(()) => println!("Switch Topology Check Passed."),
           Err(e) => eprintln!("Switch Topology Check Failed: {}", e),
       }
    } else {
       eprintln!("GPU Topology Check Failed");
    }

    Ok(())
}
```

## Contributing

We welcome contributions to `nvrust`! Please follow these steps:

1.  **Fork the repository** on GitHub.
2.  **Clone your fork** locally: `git clone git@github.com:YOUR_USERNAME/nvrust.git`
3.  **Create a new branch** for your feature or bugfix: `git checkout -b my-feature-branch`
4.  **Make your changes.** Ensure code is well-formatted (`cargo fmt`) and passes linter checks (`cargo clippy`).
5.  **Add tests** for your changes and ensure all tests pass: `cargo test --workspace`
6.  **Commit your changes** with a clear and descriptive commit message: `git commit -m "feat: Add support for X feature"` (See [Conventional Commits](https://www.conventionalcommits.org/) for guidelines).
7.  **Push your branch** to your fork: `git push origin my-feature-branch`
8.  **Open a Pull Request** against the `main` branch of the original `nvrust` repository.
9.  Clearly describe the changes in your Pull Request description. If it addresses an existing issue, please link it (e.g., `Fixes #123`).

If you plan to make significant changes, please open an issue first to discuss your proposal.

## License


This project is licensed under the Apache License, Version 2.0. You may obtain a copy of the License at:

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
