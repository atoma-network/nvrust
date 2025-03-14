use std::{io::Read, path::Path, str::FromStr, time::Duration};

use flate2::read::ZlibDecoder;
use serde::{Deserialize, Serialize};
use sui_sdk::{
    types::{base_types::ObjectID, digests::TransactionDigest},
    wallet_context::WalletContext,
};

use crate::{attest_remote, DeviceEvidence};

const ATOMA_DB_OBJECT_ID: &str =
    "0x9f0f3040b2cdadada2944df8d5caa125b2b296037d231cd969e5cc122cd9519c";
const PUBLIC_KEY_SIZE: usize = 32;
const TRANSACTION_DIGEST: &str = "4PZSvXp4ashuN3pJkDM7P273cycYPvCujszdTk4puo7y";

/// Represents an event emitted when a node's public key is rotated.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NodePublicKeyCommittmentEvent {
    #[serde(deserialize_with = "deserialize_string_to_u64")]
    pub epoch: u64,
    #[serde(deserialize_with = "deserialize_string_to_u64")]
    pub key_rotation_counter: u64,
    pub node_id: NodeSmallId,
    pub new_public_key: Vec<u8>,
    pub device_type: u16,
    pub evidence_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NodeSmallId {
    /// The unique numerical identifier for the node.
    #[serde(deserialize_with = "deserialize_string_to_u64")]
    pub inner: u64,
}

async fn retrieve_gpu_evidences() -> (Vec<DeviceEvidence>, [u8; PUBLIC_KEY_SIZE]) {
    let sui_path = Path::new("/home/.sui/sui_config/client.yaml");
    let wallet_ctx = WalletContext::new(sui_path, Some(Duration::from_secs(10)), Some(10))
        .expect("Failed to create wallet context");

    let client = wallet_ctx.get_client().await.expect("Failed to get client");
    let events = client
        .event_api()
        .get_events(TransactionDigest::from_str(TRANSACTION_DIGEST).unwrap())
        .await
        .expect("Failed to get events");

    let event = events.first().expect("Failed to get event");
    let node_public_key_committment_event: NodePublicKeyCommittmentEvent =
        serde_json::from_value(event.parsed_json.clone()).expect("Failed to parse evidence");

    let evidence_bytes = node_public_key_committment_event.evidence_bytes;
    let mut decoder = ZlibDecoder::new(evidence_bytes.as_slice());
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .expect("Failed to decompress evidence");

    (
        serde_json::from_slice(&decompressed).expect("Failed to parse evidence"),
        node_public_key_committment_event
            .new_public_key
            .try_into()
            .expect("Failed to convert public key to array"),
    )
}

async fn get_last_key_rotation_nonce() -> Option<u64> {
    let sui_path = Path::new("/home/.sui/sui_config/client.yaml");
    let wallet_ctx = WalletContext::new(sui_path, Some(Duration::from_secs(10)), Some(10))
        .expect("Failed to create wallet context");
    let client = wallet_ctx.get_client().await.expect("Failed to get client");
    let events = client
        .read_api()
        .get_object_with_options(
            ObjectID::from_str(ATOMA_DB_OBJECT_ID).expect("Failed to parse object id"),
            sui_sdk::rpc_types::SuiObjectDataOptions {
                show_type: true,
                show_content: true,
                ..Default::default()
            },
        )
        .await
        .expect("Failed to get atoma db")
        .data;
    let atoma_db = events.expect("Failed to get atoma db");
    let content = atoma_db.content.expect("Failed to get atoma db content");
    if let sui_sdk::rpc_types::SuiParsedData::MoveObject(object) = content {
        let object_fields = object.fields.to_json_value();
        object_fields
            .get("nonce")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse::<u64>().ok())
    } else {
        None
    }
}

#[tokio::test]
async fn test_retrieve_attestation_evidence() {
    let (gpu_evidences, public_key) = retrieve_gpu_evidences().await;
    let nonce = get_last_key_rotation_nonce()
        .await
        .expect("Failed to get nonce");

    for (i, evidence) in gpu_evidences.iter().enumerate() {
        let device_nonce =
            blake3::hash(&[&nonce.to_le_bytes()[..], &public_key, &i.to_le_bytes()[..]].concat());
        let device_nonce_hex = hex::encode(device_nonce.as_bytes());
        match attest_remote(&[evidence.clone()], &device_nonce_hex, None, None, None).await {
            Ok((attestation_passed, jwt)) => {
                println!("Attestation passed: {}", attestation_passed);
                println!("JWT: {}", jwt);
            }
            Err(e) => {
                panic!("Failed to attest remote: {}", e);
            }
        }
    }
}

fn deserialize_string_to_u64<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: serde::de::Deserializer<'de>,
    T: FromStr,
    T::Err: std::fmt::Display,
{
    let s = String::deserialize(deserializer)?;
    s.parse::<T>().map_err(serde::de::Error::custom)
}
