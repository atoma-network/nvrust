use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde_json::{json, Value};
use tracing::{error, info, instrument, Instrument};

use crate::{
    constants::{
        ARCH_KEY, CLAIMS_VERSION_KEY, DEFAULT_CLAIMS_VERSION, DEFAULT_TIMEOUT, EVIDENCE_LIST_KEY,
        HOPPER_ARCH, NONCE_KEY, NVIDIA_OCSP_ALLOW_CERT_HOLD_HEADER,
        REMOTE_GPU_VERIFIER_SERVICE_URL,
    },
    errors::{AttestError, Result},
    types::DeviceEvidence,
    utils::get_allow_hold_cert,
};

/// Options for remote attestation
#[derive(Debug, Default, Clone)]
pub struct AttestRemoteOptions {
    /// Optional URL of the verification service. If `None`, uses the default URL
    pub verifier_url: Option<String>,
    /// Optional flag to allow certificate hold status. If `None`, uses the system default
    pub allow_hold_cert: Option<bool>,
    /// Optional claims version. If `None`, uses the system default
    pub claims_version: Option<String>,
    /// Optional service key for authorization
    pub service_key: Option<String>,
    /// Optional request timeout
    pub timeout: Option<Duration>,
}

/// Performs remote attestation of GPU devices by sending evidence to a verification service.
///
/// This function sends GPU evidence to a remote attestation service (NRAS) and processes
/// the verification result. It's used to verify the authenticity and integrity of NVIDIA GPUs.
///
/// # Arguments
///
/// * `gpu_evidences` - A slice of `DeviceEvidence` containing attestation data from GPUs
/// * `nonce` - A unique string value to prevent replay attacks
/// * `verifier_url` - Optional URL of the verification service. If `None`, uses the default URL
///
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
/// Returns `AttestError` if:
/// * The HTTP request fails
/// * The server returns a non-success status code
/// * The response cannot be parsed
/// * JWT token validation fails
///
/// # Example
///
/// ```rust,ignore
/// use remote_attestation::{attest_remote, DeviceEvidence};
///
/// async fn example() -> Result<(), Box<dyn std::error::Error>> {
///     let evidence = vec![/* DeviceEvidence instances */];
///     let nonce = "unique-nonce-value";
///     
///     let (attestation_passed, response) = attest_remote(&evidence, nonce, None, None, None).await?;
///     
///     if attestation_passed {
///         println!("GPU attestation successful!");
///     } else {
///         println!("GPU attestation failed!");
///     }
///     
///     Ok(())
/// }
/// ```
#[instrument(
    level = "info",
    name = "attest_remote",
    skip(gpu_evidences, nonce, remote_attestation_options),
    fields(nonce = %nonce)
)]
pub async fn verify_gpu_attestation(
    gpu_evidences: &[DeviceEvidence],
    nonce: &str,
    remote_attestation_options: AttestRemoteOptions,
) -> Result<(bool, Value)> {
    let AttestRemoteOptions {
        verifier_url,
        allow_hold_cert,
        claims_version,
        service_key,
        timeout,
    } = remote_attestation_options;
    let verifier_url = verifier_url.unwrap_or_else(|| REMOTE_GPU_VERIFIER_SERVICE_URL.to_string());
    let allow_hold_cert = allow_hold_cert.unwrap_or_else(get_allow_hold_cert);
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
    let claims_version = claims_version.unwrap_or_else(|| DEFAULT_CLAIMS_VERSION.to_string());
    let payload = json!({
        NONCE_KEY: nonce,
        EVIDENCE_LIST_KEY: gpu_evidences,
        CLAIMS_VERSION_KEY: claims_version,
        ARCH_KEY: HOPPER_ARCH,
    });
    info!(
        level = "GPU::attest_remote",
        verifier_url = %verifier_url,
        claims_version = %claims_version,
        nonce = %nonce,
        timeout = ?timeout,
        "Sending attestation request to NRAS url {verifier_url}, with claims version {claims_version}, nonce {nonce}"
    );
    let client = reqwest::Client::builder()
        .timeout(timeout.unwrap_or(DEFAULT_TIMEOUT))
        .build()?;
    let request_span =
        tracing::info_span!("nras_request", url = %verifier_url, claims_version = %claims_version);
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
            info!(
                level = "GPU::attest_remote",
                verifier_url = %verifier_url,
                claims_version = %claims_version,
                nonce = %nonce,
                timeout = ?timeout,
                "Attestation request successful, response: {response_json}",
            );
            let main_jwt_token = crate::utils::get_overall_claims_token(&response_json)?;
            let decoded_main_jwt_token =
                crate::utils::nras_token::decode_nras_token(&verifier_url, &main_jwt_token).await?;
            let attestation_result = decoded_main_jwt_token.overall_attestation_result;
            Ok((attestation_result, response_json))
        }
        Err(e) => {
            error!(
                level = "GPU::attest_remote",
                verifier_url = %verifier_url,
                claims_version = %claims_version,
                nonce = %nonce,
                timeout = ?timeout,
                "Failed to parse response with error: {e}",
            );
            return Err(AttestError::ParseResponseError(e));
        }
    }
}
