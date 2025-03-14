use std::{fs, path::Path};

use crate::{attest_remote, DeviceEvidence};

fn generate_new_device_evidence() -> (Vec<DeviceEvidence>, String) {
    let file = Path::new("./evidence/evidence.json");
    let evidence = fs::read_to_string(file).expect("Failed to read evidence file");
    let evidence: Vec<DeviceEvidence> =
        serde_json::from_str(&evidence).expect("Failed to parse evidence");
    (
        evidence,
        "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb".to_string(),
    )
}

#[tokio::test]
async fn test_retrieve_attestation_evidence() {
    let (evidence, nonce) = generate_new_device_evidence();
    match attest_remote(&evidence, &nonce, None, None, None).await {
        Ok((attestation_passed, jwt)) => {
            println!("Attestation passed: {}", attestation_passed);
            println!("JWT: {}", jwt);
        }
        Err(e) => {
            panic!("Failed to attest remote: {}", e);
        }
    }
}
