use std::time::Duration;

/// Default URL for the remote GPU verifier service.
///
/// This URL is used as the default endpoint for remote attestation of GPU devices.
pub const REMOTE_GPU_VERIFIER_SERVICE_URL: &str = "https://remote-gpu-verifier.com";

/// Environment variable key for certificate hold status.
/// This key is used to check if certificates should be allowed to be held.
pub const NV_ALLOW_HOLD_CERT_KEY: &str = "NV_ALLOW_HOLD_CERT";

/// Header key for allowing certificate holds in NVIDIA OCSP requests.
///
/// This header is used to indicate that the OCSP responder should allow
/// certificate holds when checking the status of a certificate.
///
/// # Example
/// ```
/// let mut headers = HeaderMap::new();
/// headers.insert(NVIDIA_OCSP_ALLOW_CERT_HOLD_HEADER, HeaderValue::from_static("true"));
/// ```
pub const NVIDIA_OCSP_ALLOW_CERT_HOLD_HEADER: &str = "X-NVIDIA-OCSP-ALLOW-CERT-HOLD";

/// Hopper architecture for remote attestation requests.
///
/// This architecture is used to identify the architecture in the remote attestation request.
pub const HOPPER_ARCH: &str = "HOPPER";

/// Default timeout for remote attestation requests.
///
/// This timeout is used as the default duration for requests to the remote
/// attestation service.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Nonce key for remote attestation requests.
///
/// This key is used to identify the nonce in the remote attestation request.
pub const NONCE_KEY: &str = "nonce";

/// Evidence list key for remote attestation requests.
///
/// This key is used to identify the evidence list in the remote attestation request.
pub const EVIDENCE_LIST_KEY: &str = "evidence_list";

/// Architecture key for remote attestation requests.
///
/// This key is used to identify the architecture in the remote attestation request.
pub const ARCH_KEY: &str = "arch";

/// JWKS key for remote attestation requests.
///
/// This key is used to identify the JWKS in the remote attestation request.
pub const JWKS_KEY: &str = "jwks";

/// Keys key for remote attestation requests.
///
/// This key is used to identify the keys in the remote attestation request.
pub const KEYS_KEY: &str = "keys";

/// KID key for remote attestation requests.
///
/// This key is used to identify the KID in the remote attestation request.
pub const KID_KEY: &str = "kid";
