use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde_json::{json, Value};
use tracing::{debug, error, instrument, Instrument};

use crate::{
    constants::{
        ARCH_KEY, CLAIMS_VERSION_KEY, DEFAULT_CLAIMS_VERSION, DEFAULT_TIMEOUT, EVIDENCE_LIST_KEY,
        LS10_ARCH, NONCE_KEY, NVIDIA_OCSP_ALLOW_CERT_HOLD_HEADER, REMOTE_GPU_VERIFIER_SERVICE_URL,
    },
    errors::{AttestError, Result},
    remote_gpu_attestation::AttestRemoteOptions,
    types::NvSwitchEvidence,
    utils::get_allow_hold_cert,
};

/// Verifies the attestation of an NVSwitch device
///
/// This function sends the NVSwitch evidence to the remote attestation service
/// and processes the verification result.
///
/// # Arguments
///
/// * `nvswitch_evidences` - A slice of `NvSwitchEvidence` containing attestation data from NVSwitch
/// * `nonce` - A unique string value to prevent replay attacks
/// * `verifier_url` - Optional URL of the verification service. If `None`, uses the default URL
/// * `allow_hold_cert` - Optional flag to allow certificate hold status. If `None`, uses the system default
/// * `timeout` - Optional request timeout. If `None`, uses the default timeout
///
/// # Returns
///
/// A `Result` containing a tuple with:
/// * A boolean indicating the overall attestation result (true = passed, false = failed)
/// * The complete JSON response from the attestation service
///
/// # Errors
///
/// * `AttestError::ParseResponseError` - If the response cannot be parsed as JSON
/// * `AttestError::ResponseError` - If the response status code is not successful
/// * `AttestError::NrasTokenError` - If the NRASToken cannot be decoded
#[instrument(
    name = "verify_nvswitch_attestation",
    skip_all,
    fields(nonce = %nonce)
)]
pub async fn verify_nvswitch_attestation(
    nvswitch_evidences: &[NvSwitchEvidence],
    nonce: &str,
    remote_attestation_options: AttestRemoteOptions,
) -> Result<(bool, Value)> {
    let AttestRemoteOptions {
        verifier_url,
        allow_hold_cert,
        timeout,
        claims_version,
        service_key,
    } = remote_attestation_options;
    let verifier_url = verifier_url.unwrap_or(REMOTE_GPU_VERIFIER_SERVICE_URL.to_string());
    let allow_hold_cert = allow_hold_cert.unwrap_or(get_allow_hold_cert());
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if allow_hold_cert {
        headers.insert(
            NVIDIA_OCSP_ALLOW_CERT_HOLD_HEADER,
            HeaderValue::from_static("true"),
        );
    }
    if let Some(ref service_key) = service_key {
        headers.insert(AUTHORIZATION, HeaderValue::from_str(service_key)?);
    }
    let claims_version = claims_version.unwrap_or(DEFAULT_CLAIMS_VERSION.to_string());
    let payload = json!({
        NONCE_KEY: nonce,
        EVIDENCE_LIST_KEY: nvswitch_evidences,
        CLAIMS_VERSION_KEY: claims_version,
        ARCH_KEY: LS10_ARCH,
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
        .post(&verifier_url)
        .headers(headers)
        .json(&payload)
        .send()
        .instrument(request_span)
        .await
        .map_err(|e| {
            error!(
                level = "attest_remote",
                "Failed to send attestation request: {e}"
            );
            AttestError::ParseResponseError(e)
        })?;
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
                crate::utils::nras_token::decode_nras_token(&verifier_url, &main_jwt_token).await?;
            let attestation_result = decoded_main_jwt_token.overall_attestation_result;
            Ok((attestation_result, response_json))
        }
        Err(e) => {
            error!(level = "attest_remote", "Failed to parse response: {e}");
            return Err(AttestError::ParseResponseError(e));
        }
    }
}
