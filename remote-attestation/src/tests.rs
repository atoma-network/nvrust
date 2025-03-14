use std::{fs, path::Path};

use rand::Rng;

use crate::{attest_remote, DeviceEvidence};

fn generate_new_device_evidence() -> (DeviceEvidence, String) {
    let file = Path::new("./evidence/evidence.json");
    let evidence = fs::read_to_string(file).expect("Failed to read evidence file");
    let evidence: DeviceEvidence =
        serde_json::from_str(&evidence).expect("Failed to parse evidence");
    let nonce = rand::thread_rng().gen::<[u8; 32]>();
    (evidence, hex::encode(nonce))
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
