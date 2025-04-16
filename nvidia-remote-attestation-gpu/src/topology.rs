use std::collections::HashSet;

use crate::error::{NvidiaRemoteAttestationError, Result};
use crate::swtich_pdis::extract_switch_pdis_in_gpu_attestation_report_data;
use crate::swtich_pdis::opaque_data_field_size::PDI_DATA_FIELD_SIZE;

/// The number of GPU attestation reports to check for topology.
const NUMBER_OF_GPU_TOPOLOGY_CHECK_REPORTS: usize = 8;

/// The number of switch PDIS in the set of switch PDIS.
const NUMBER_OF_SWITCH_PDIS: usize = 4;

/// The disabled PDI value, to be removed from the set of switch PDIS.
const DISABLED_PDI: &[u8] = &[0u8; PDI_DATA_FIELD_SIZE];

#[tracing::instrument(name = "gpu_topology_check", skip_all)]
pub fn gpu_topology_check(gpu_attestation_reports: &[&[u8]]) -> Result<()> {
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
                        "Error extracting switch PIDS from GPU attestation report: {}",
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
    Ok(())
}
