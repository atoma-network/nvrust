use std::{fs, path::Path};

use base64::{engine::general_purpose::STANDARD, Engine};
use nscq::NscqHandler;
use nvml_wrapper::Nvml;
use rand::Rng;

use crate::{
    remote_gpu_attestation::AttestRemoteOptions,
    remote_nvswitch_attestation::collect_nvswitch_evidence, types::NvSwitchEvidence,
    verify_gpu_attestation, verify_nvswitch_attestation, DeviceEvidence,
};

fn read_working_evidence() -> (Vec<DeviceEvidence>, String) {
    let file = Path::new("./evidence/evidence.json");
    let evidence = fs::read_to_string(file).expect("Failed to read evidence file");
    let evidence: Vec<DeviceEvidence> =
        serde_json::from_str(&evidence).expect("Failed to parse evidence");
    (
        evidence,
        "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb".to_string(),
    )
}

fn generate_new_gpu_evidence() -> (Vec<DeviceEvidence>, String) {
    let nvml = Nvml::init().expect("Failed to initialize NVML");
    let num_devices = nvml.device_count().expect("Failed to get device count");
    let nonce = rand::thread_rng().gen::<[u8; 32]>();
    let mut evidence_vec = Vec::with_capacity(num_devices as usize);
    for i in 0..num_devices {
        let device = nvml.device_by_index(i).expect("Failed to get device");
        let attestation_report = device
            .confidential_compute_gpu_attestation_report(nonce)
            .expect("Failed to get report");
        let certificate = device
            .confidential_compute_gpu_certificate()
            .expect("Failed to get certificate");
        evidence_vec.push(DeviceEvidence {
            certificate: STANDARD.encode(certificate.attestation_cert_chain),
            evidence: STANDARD.encode(attestation_report.attestation_report),
        });
    }
    (evidence_vec, hex::encode(nonce))
}

fn generate_new_nvswitch_evidence() -> (Vec<NvSwitchEvidence>, String) {
    let nscq = NscqHandler::new().expect("Failed to initialize NSCQ");
    let mut nonce = rand::thread_rng().gen::<[u8; 32]>();
    let evidence = collect_nvswitch_evidence(&nscq, &mut nonce).expect("Failed to get evidence");
    (evidence, hex::encode(nonce))
}

#[tokio::test]
async fn test_attest_working_evidence() {
    let (evidence, nonce) = read_working_evidence();
    match verify_gpu_attestation(&evidence, &nonce, AttestRemoteOptions::default()).await {
        Ok((attestation_passed, jwt)) => {
            println!("Attestation passed: {attestation_passed}");
            println!("JWT: {jwt}");
            assert!(attestation_passed);
        }
        Err(e) => {
            panic!("Failed to attest remote: {e}");
        }
    }
}

#[tokio::test]
async fn test_attest_new_gpu_evidence() {
    let (evidence, nonce) = generate_new_gpu_evidence();
    match verify_gpu_attestation(&evidence, &nonce, AttestRemoteOptions::default()).await {
        Ok((attestation_passed, jwt)) => {
            println!("Attestation passed: {attestation_passed}");
            println!("JWT: {jwt}");
        }
        Err(e) => {
            panic!("Failed to attest remote: {e}");
        }
    }
}

#[tokio::test]
async fn test_attest_new_nvswitch_evidence() {
    let (evidence, nonce) = generate_new_nvswitch_evidence();
    match verify_nvswitch_attestation(&evidence, &nonce, AttestRemoteOptions::default()).await {
        Ok((attestation_passed, jwt)) => {
            println!("Attestation passed: {attestation_passed}");
            println!("JWT: {jwt}");
        }
        Err(e) => {
            panic!("Failed to attest remote: {e}");
        }
    }
}
