use base64::{engine::general_purpose::STANDARD, Engine};
use nvml_wrapper::Nvml;
use rand::Rng;

use crate::{attest_remote, DeviceEvidence};

fn generate_new_device_evidence() -> (DeviceEvidence, String) {
    let nvml = Nvml::init().expect("Failed to initialize NVML");
    let device = nvml.device_by_index(0).expect("Failed to get device");
    let nonce = rand::thread_rng().gen::<[u8; 32]>();
    let report = device
        .confidential_compute_gpu_attestation_report(nonce)
        .expect("Failed to get report")
        .attestation_report;
    let certificate = device
        .confidential_compute_gpu_certificate()
        .expect("Failed to get certificate")
        .attestation_cert_chain;
    let evidence = DeviceEvidence {
        evidence: STANDARD.encode(report),
        certificate: STANDARD.encode(certificate),
    };
    let nonce_hex = hex::encode(nonce);
    (evidence, nonce_hex)
}

#[tokio::test]
async fn test_retrieve_attestation_evidence() {
    let (evidence, nonce) = generate_new_device_evidence();
    match attest_remote(&[evidence], &nonce, None, None, None).await {
        Ok((attestation_passed, jwt)) => {
            println!("Attestation passed: {}", attestation_passed);
            println!("JWT: {}", jwt);
        }
        Err(e) => {
            panic!("Failed to attest remote: {}", e);
        }
    }
}
