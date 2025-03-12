use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use serde_json::{json, Value};
use tracing::{debug, error, instrument, Instrument};

use crate::{
    constants::{
        ARCH_KEY, DEFAULT_TIMEOUT, EVIDENCE_LIST_KEY, HOPPER_ARCH, NONCE_KEY,
        NVIDIA_OCSP_ALLOW_CERT_HOLD_HEADER, REMOTE_GPU_VERIFIER_SERVICE_URL,
    },
    errors::{AttestError, Result},
    types::DeviceEvidence,
    utils::get_allow_hold_cert,
};

#[instrument(
    level = "debug",
    name = "attest_remote",
    skip(gpu_evidence_list, nonce, verifier_url, allow_hold_cert),
    fields(
        nonce = %nonce,
        verifier_url = verifier_url.unwrap_or(REMOTE_GPU_VERIFIER_SERVICE_URL),
        allow_hold_cert = allow_hold_cert.unwrap_or(get_allow_hold_cert()),
    )
)]
pub async fn attest_remote(
    gpu_evidence_list: &[DeviceEvidence],
    nonce: &str,
    verifier_url: Option<&str>,
    allow_hold_cert: Option<bool>,
    timeout: Option<Duration>,
) -> Result<(bool, Value)> {
    let verifier_url = verifier_url.unwrap_or(REMOTE_GPU_VERIFIER_SERVICE_URL);
    let allow_hold_cert = allow_hold_cert.unwrap_or(get_allow_hold_cert());
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if allow_hold_cert {
        headers.insert(
            NVIDIA_OCSP_ALLOW_CERT_HOLD_HEADER,
            HeaderValue::from_static("true"),
        );
    }
    let payload = json!({
        NONCE_KEY: nonce,
        EVIDENCE_LIST_KEY: gpu_evidence_list,
        ARCH_KEY: HOPPER_ARCH,
    });
    debug!(
        level = "attest_remote",
        "Sending attestation request to NRAS url {verifier_url}"
    );
    let client = reqwest::Client::builder()
        .timeout(timeout.unwrap_or(DEFAULT_TIMEOUT))
        .build()?;
    let request_span = tracing::info_span!("nras_request", url = %verifier_url);
    let response = client
        .post(verifier_url)
        .headers(headers)
        .json(&payload)
        .send()
        .instrument(request_span)
        .await?;
    if !response.status().is_success() {
        error!(
            level = "attest_remote",
            "Attestation request failed with status code {}",
            response.status()
        );
        let error_message = response.text().await?;
        return Err(AttestError::ResponseError(error_message));
    }
    match response.json::<Value>().await {
        Ok(response_json) => {
            debug!(
                level = "attest_remote",
                "Attestation request successful, response: {response_json}",
            );
            let main_jwt_token = crate::utils::get_overall_claims_token(&response_json)?;
            let decoded_main_jwt_token =
                crate::utils::nras_token::decode_nras_token(verifier_url, &main_jwt_token).await?;
            let attestation_result = decoded_main_jwt_token.overall_attestation_result;
            Ok((attestation_result, response_json))
        }
        Err(e) => {
            error!(level = "attest_remote", "Failed to parse response: {e}");
            return Err(AttestError::ParseResponseError(e));
        }
    }
}
