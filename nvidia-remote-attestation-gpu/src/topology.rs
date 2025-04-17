use std::collections::HashSet;

use crate::device_pdis::{extract_device_pdis_in_gpu_attestation_report_data, SwitchDevicePdis};
use crate::error::{NvidiaRemoteAttestationError, Result};
use crate::swtich_pdis::extract_switch_pdis_in_gpu_attestation_report_data;
use crate::swtich_pdis::opaque_data_field_size::PDI_DATA_FIELD_SIZE;

/// The number of GPU attestation reports to check for topology.
const NUMBER_OF_GPU_TOPOLOGY_CHECK_REPORTS: usize = 8;

/// The number of switch PDIS in the set of switch PDIS.
const NUMBER_OF_SWITCH_PDIS: usize = 4;

/// The number of switch attestation reports to check for topology.
const NUMBER_OF_SWITCH_ATTESTATION_REPORTS: usize = 4;

/// The disabled PDI value, to be removed from the set of switch PDIS.
const DISABLED_PDI: &[u8] = &[0u8; PDI_DATA_FIELD_SIZE];

/// Performs a GPU topology check by verifying the consistency of NVSwitch PDI sets across multiple GPU attestation reports.
///
/// This function expects a specific number of attestation reports (`NUMBER_OF_GPU_TOPOLOGY_CHECK_REPORTS`).
/// It processes each report to extract its associated NVSwitch Platform Data Information (PDI) entries.
/// For each report, it:
/// 1. Extracts the list of PDIs using `extract_switch_pdis_in_gpu_attestation_report_data`.
/// 2. Creates a set of unique PDIs from the list.
/// 3. Removes a predefined `DISABLED_PDI` value from the set.
/// 4. Verifies that the number of remaining unique PDIs matches `NUMBER_OF_SWITCH_PDIS`.
/// 5. Compares this set of PDIs with the set derived from the first report. All subsequent reports
///    must have the exact same set of unique, enabled PDIs.
///
/// The function uses `tracing` to log information about the check process and any errors encountered.
///
/// # Arguments
///
/// * `gpu_attestation_reports` - A slice containing references to the byte slices of individual
///   GPU attestation reports.
///
/// # Returns
///
/// Returns `Ok(HashSet<[u8; PDI_DATA_FIELD_SIZE]>)` if all topology checks pass:
///   - The correct number of reports is provided.
///   - PDI extraction is successful for all reports.
///   - Each report contains the expected number of unique, enabled PDIs.
///   - The set of unique, enabled PDIs is identical across all provided reports.
///
/// # Errors
///
/// Returns an `Err(NvidiaRemoteAttestationError)` if any check fails:
/// * `NvidiaRemoteAttestationError::InvalidGpuAttestationReportsLength`: If the number of
///   reports in `gpu_attestation_reports` does not match `NUMBER_OF_GPU_TOPOLOGY_CHECK_REPORTS`.
/// * Errors propagated from `extract_switch_pdis_in_gpu_attestation_report_data`: If PDI extraction
///   fails for any report (e.g., due to invalid report format, missing opaque data, etc.).
/// * `NvidiaRemoteAttestationError::InvalidSwitchPdisLength`: If, after removing the disabled PDI,
///   the number of unique PDIs in a report does not match `NUMBER_OF_SWITCH_PDIS`.
/// * `NvidiaRemoteAttestationError::InvalidSwitchPdisTopology`: If the set of unique, enabled PDIs
///   derived from a report differs from the set derived from the first report processed.
#[tracing::instrument(name = "gpu_topology_check", skip_all)]
pub fn gpu_topology_check(
    gpu_attestation_reports: &[&[u8]],
) -> Result<HashSet<[u8; PDI_DATA_FIELD_SIZE]>> {
    if gpu_attestation_reports.len() != NUMBER_OF_GPU_TOPOLOGY_CHECK_REPORTS {
        tracing::error!(
            "Invalid number of GPU attestation reports: expected {}, got {}",
            NUMBER_OF_GPU_TOPOLOGY_CHECK_REPORTS,
            gpu_attestation_reports.len()
        );
        return Err(
            NvidiaRemoteAttestationError::InvalidGpuAttestationReportsLength {
                message: "Invalid number of GPU attestation reports".to_string(),
                expected_length: 8,
                actual_length: gpu_attestation_reports.len(),
            },
        );
    }
    let mut unique_switch_pdis_set: Option<HashSet<[u8; PDI_DATA_FIELD_SIZE]>> = None;
    for evidence in gpu_attestation_reports {
        let switch_pdis_in_evidence =
            match extract_switch_pdis_in_gpu_attestation_report_data(evidence) {
                Ok(switch_pdis) => switch_pdis,
                Err(e) => {
                    tracing::error!(
                        "Error extracting switch PDIS from GPU attestation report: {}",
                        e
                    );
                    return Err(e);
                }
            };
        let mut switch_pdis_set =
            HashSet::<[u8; PDI_DATA_FIELD_SIZE]>::from_iter(switch_pdis_in_evidence);
        switch_pdis_set.remove(DISABLED_PDI);
        if switch_pdis_set.len() != NUMBER_OF_SWITCH_PDIS {
            tracing::error!(
                "Invalid number of switch PDIS: expected {}, got {}",
                NUMBER_OF_SWITCH_PDIS,
                switch_pdis_set.len()
            );
            return Err(NvidiaRemoteAttestationError::InvalidSwitchPdisLength {
                message: "Invalid number of switch PDIS".to_string(),
                length: switch_pdis_set.len(),
            });
        }
        match unique_switch_pdis_set {
            Some(ref set) => {
                if set != &switch_pdis_set {
                    tracing::error!(
                        "Invalid switch PDIS topology, we found a mismatch between the expected and actual switch PDIS topology: expected {:?}, got {:?}",
                        set,
                        switch_pdis_set
                    );
                    return Err(NvidiaRemoteAttestationError::InvalidSwitchPdisTopology {
                        message: "Invalid switch PDIS topology".to_string(),
                        expected: set.clone(),
                        actual: switch_pdis_set,
                    });
                }
            }
            None => {
                tracing::info!("GPU Topology check: Setting initial unique switches PDIS");
                unique_switch_pdis_set = Some(switch_pdis_set);
            }
        }
    }
    tracing::info!("GPU topology check passed successfully");
    Ok(unique_switch_pdis_set.expect("Unique switch PDIS set should be Some at this point"))
}

#[tracing::instrument(name = "switch_topology_check", skip_all, fields(num_gpus))]
pub fn switch_topology_check(
    switch_attestation_reports: &[&[u8]],
    num_gpus: usize,
    unique_switch_pdis_set: HashSet<[u8; PDI_DATA_FIELD_SIZE]>,
) -> Result<()> {
    if switch_attestation_reports.len() != NUMBER_OF_SWITCH_ATTESTATION_REPORTS {
        tracing::error!(
            "Invalid number of switch attestation reports: expected {}, got {}",
            NUMBER_OF_SWITCH_ATTESTATION_REPORTS,
            switch_attestation_reports.len()
        );
        return Err(
            NvidiaRemoteAttestationError::InvalidSwitchAttestationReportsLength {
                message: "Invalid number of switch attestation reports".to_string(),
                expected_length: NUMBER_OF_SWITCH_ATTESTATION_REPORTS,
                actual_length: switch_attestation_reports.len(),
            },
        );
    }
    let mut unique_switch_device_gpu_pdis_set: Option<HashSet<[u8; PDI_DATA_FIELD_SIZE]>> = None;
    for report in switch_attestation_reports {
        let SwitchDevicePdis {
            switch_device_gpu_pdis,
            switch_pdis,
        } = match extract_device_pdis_in_gpu_attestation_report_data(report) {
            Ok(switch_device_pdis) => switch_device_pdis,
            Err(e) => {
                tracing::error!(
                    "Error extracting device PDIS from switch attestation report: {}",
                    e
                );
                return Err(e);
            }
        };
        if !unique_switch_pdis_set.contains(&switch_pdis) {
            tracing::error!(
                "Switch Topology check: The switch PDI reported in switch attestation report which is {:?} is not in the set of unique switch PDIS: {:?}",
                switch_pdis,
                unique_switch_pdis_set
            );
            return Err(NvidiaRemoteAttestationError::SwitchPdisNotFound);
        }
        let switch_device_gpu_pdis_set =
            HashSet::<[u8; PDI_DATA_FIELD_SIZE]>::from_iter(switch_device_gpu_pdis);
        if switch_device_gpu_pdis_set.len() != num_gpus {
            tracing::error!(
                "Switch Topology check: The number of switch device GPU PDIS is not equal to the number of GPUs: expected {}, got {}",
                num_gpus,
                switch_device_gpu_pdis_set.len()
            );
            return Err(
                NvidiaRemoteAttestationError::InvalidSwitchDeviceGpuPdisLength {
                    message: "Invalid number of switch device GPU PDIS".to_string(),
                    expected_length: num_gpus,
                    actual_length: switch_device_gpu_pdis_set.len(),
                },
            );
        }
        match unique_switch_device_gpu_pdis_set {
            Some(ref set) => {
                if set != &switch_device_gpu_pdis_set {
                    tracing::error!("Invalid switch device GPU PDIS topology, we found a mismatch between the expected and actual switch device GPU PDIS topology: expected {:?}, got {:?}", set, switch_device_gpu_pdis_set);
                    return Err(
                        NvidiaRemoteAttestationError::InvalidSwitchDeviceGpuPdisTopology {
                            message: "Invalid switch device GPU PDIS topology".to_string(),
                            expected: set.clone(),
                            actual: switch_device_gpu_pdis_set,
                        },
                    );
                }
            }
            None => {
                tracing::info!(
                    "Switch Topology check: Setting initial unique switch device GPU PDIS"
                );
                unique_switch_device_gpu_pdis_set = Some(switch_device_gpu_pdis_set);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use nvml_wrapper::Nvml;
    use rand::Rng;

    #[test]
    fn test_gpu_topology_check() {
        let nvml = Nvml::init().unwrap();
        let gpu_count = nvml.device_count().unwrap();
        if gpu_count != 8 {
            println!(
                "Skipping GPU topology check, expected 8 GPUs, got {}",
                gpu_count
            );
            return;
        }
        // let mut is_ppcie_multi_gpu_protected_enabled = true;
        // for i in 0..gpu_count {
        //     is_ppcie_multi_gpu_protected_enabled &= nvml
        //         .device_by_index(i)
        //         .expect("Failed to get device by index")
        //         .is_multi_gpu_protected_pcie_enabled()
        //         .expect("Failed to get multi-GPU protected PCIe status");
        // }
        // if !is_ppcie_multi_gpu_protected_enabled {
        //     println!("Skipping GPU topology check, multi-GPU protected PCIe is not enabled");
        //     return;
        // }
        let mut gpu_attestation_reports = Vec::with_capacity(gpu_count as usize);
        let nonce = rand::thread_rng().gen::<[u8; 32]>();
        for i in 0..gpu_count {
            let gpu_attestation_report = nvml
                .device_by_index(i)
                .unwrap()
                .confidential_compute_gpu_attestation_report(nonce)
                .expect("Failed to get confidential compute GPU attestation report")
                .attestation_report;
            println!(
                "GPU attestation report with length: {:?}",
                gpu_attestation_report.len()
            );
            gpu_attestation_reports.push(gpu_attestation_report);
        }
        let result = gpu_topology_check(
            &gpu_attestation_reports
                .iter()
                .map(|r| r.as_slice())
                .collect::<Vec<_>>(),
        )
        .expect("Failed to check GPU topology");
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn test_switch_topology_check() {
        // GPU Topology Check, we need to do it first to get the unique switch PDIS set
        let start_time = std::time::Instant::now();
        let nvml = Nvml::init().expect("Failed to initialize NVML");
        let gpu_count = nvml.device_count().expect("Failed to get device count");
        let mut gpu_attestation_reports = Vec::with_capacity(gpu_count as usize);
        let nonce = rand::thread_rng().gen::<[u8; 32]>();
        for i in 0..gpu_count {
            let gpu_attestation_report = nvml
                .device_by_index(i)
                .unwrap()
                .confidential_compute_gpu_attestation_report(nonce)
                .expect("Failed to get confidential compute GPU attestation report")
                .attestation_report;
            println!(
                "GPU attestation report with length: {:?}",
                gpu_attestation_report.len()
            );
            gpu_attestation_reports.push(gpu_attestation_report);
        }
        let unique_switch_pdis_set = gpu_topology_check(
            &gpu_attestation_reports
                .iter()
                .map(|r| r.as_slice())
                .collect::<Vec<_>>(),
        )
        .expect("Failed to check GPU topology");

        println!("GPU Topology check took: {:?}", start_time.elapsed());

        // NVSwitch Topology Check
        let start_time = std::time::Instant::now();
        let nscq = nscq::nscq_handler::NscqHandler::new();
        let nonce = rand::thread_rng().gen::<[u8; 32]>();
        let num_gpus = gpu_count as usize;
        let switch_attestation_reports = nscq
            .get_all_switch_attestation_report(&nonce)
            .expect("Failed to get all switch attestation reports");
        let result = switch_topology_check(
            &switch_attestation_reports
                .iter()
                .map(|(_, report)| report.as_slice())
                .collect::<Vec<_>>(),
            num_gpus,
            unique_switch_pdis_set,
        );
        result.expect("Failed to check switch topology");
        println!("Switch Topology check took: {:?}", start_time.elapsed());
    }
}
