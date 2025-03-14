use crate::{
    constants::NV_ALLOW_HOLD_CERT_KEY,
    errors::{AttestError, Result},
};
use once_cell::sync::Lazy;
use serde_json::Value;
use std::sync::Mutex;

/// Global state to control certificate hold status.
/// This is initialized as `None` and can be set at runtime.
static CERT_HOLD_STATUS: Lazy<Mutex<Option<bool>>> = Lazy::new(|| Mutex::new(None));

// Sets whether certificates should be allowed to be held.
///
/// This function updates the global certificate hold status.
///
/// # Arguments
///
/// * `value` - A boolean indicating whether to allow certificate holding.
pub fn set_allow_hold_cert(value: bool) {
    let mut status = CERT_HOLD_STATUS.lock().unwrap();
    *status = Some(value);
}

/// Determines whether certificates should be allowed to be held.
///
/// This function first checks the global certificate hold status.
/// If not set, it falls back to checking the "NV_ALLOW_HOLD_CERT" environment variable.
///
/// # Returns
///
/// * `true` if certificates should be allowed to be held
/// * `false` otherwise
pub fn get_allow_hold_cert() -> bool {
    if let Some(value) = *CERT_HOLD_STATUS.lock().unwrap() {
        value
    } else {
        std::env::var(NV_ALLOW_HOLD_CERT_KEY).unwrap_or_default() == "true"
    }
}

/// Gets the overall claims token from a JSON token structure.
///
/// # Arguments
///
/// * `token` - A JSON string containing a nested array structure
///
/// # Returns
///
/// * `Result<String, JsonError>` - The extracted token or an error
#[tracing::instrument(level = "debug", skip(token))]
pub fn get_overall_claims_token(token: &Value) -> Result<String> {
    // 1. Extract the first array element
    let overall_token_arr = token.get(0).and_then(|arr| arr.as_array()).ok_or_else(|| {
        AttestError::JsonError(serde::ser::Error::custom(
            "Token structure invalid: first element is not an array",
        ))
    })?;

    // 2. Extract the second element from the first array
    let overall_token = overall_token_arr
        .get(1)
        .and_then(|token| token.as_str())
        .ok_or_else(|| {
            AttestError::JsonError(serde::ser::Error::custom(
                "Token structure invalid: second element is not a string",
            ))
        })?;

    Ok(overall_token.to_string())
}

pub mod nras_token {
    use crate::{
        constants::{DEFAULT_TIMEOUT, KEYS_KEY, KID_KEY},
        errors::{AttestError, Result},
    };
    use base64::{engine::general_purpose::STANDARD, Engine};
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
    use reqwest::Client;
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use std::collections::HashMap;
    use url::Url;
    use x509_parser::prelude::{FromDer, X509Certificate};

    /// Custom claims structure for NVIDIA attestation tokens.
    ///
    /// This struct represents the claims contained in a JWT token issued by NVIDIA's
    /// Remote Attestation Service (NRAS). It includes standard JWT fields like issuer,
    /// subject, and expiration time, as well as NVIDIA-specific attestation results.   
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct NvidiaAttestationClaims {
        /// Boolean indicating the overall attestation result
        #[serde(rename = "x-nvidia-overall-att-result")]
        pub overall_attestation_result: bool,

        /// Map containing any additional claims present in the token
        #[serde(flatten)]
        pub additional_claims: HashMap<String, Value>,
    }

    /// Decodes and verifies an NVIDIA Remote Attestation Service (NRAS) JWT token.
    ///
    /// This function performs the following steps:
    /// 1. Constructs a JWKS URL from the provided verifier URL
    /// 2. Fetches the JWKS data from the constructed URL
    /// 3. Extracts the key ID (kid) from the token header
    /// 4. Finds the matching key in the JWKS data
    /// 5. Extracts the certificate from the key
    /// 6. Uses the certificate to decode and verify the JWT token
    ///
    /// # Arguments
    ///
    /// * `verifier_url` - Base URL of the NVIDIA attestation verifier service
    /// * `token` - The JWT token string to decode and verify
    ///
    /// # Returns
    ///
    /// * `Result<NvidiaAttestationClaims>` - The decoded and verified token claims
    ///
    /// # Errors
    ///
    /// Returns various `AttestError` variants if:
    /// * The JWKS URL cannot be constructed
    /// * The JWKS data cannot be fetched
    /// * The token header is invalid
    /// * The matching key cannot be found
    /// * The certificate is invalid
    /// * The token signature verification fails
    #[tracing::instrument(
        level = "debug",
        name = "decode_nras_token",
        skip(verifier_url, token),
        fields(
            verifier_url = %verifier_url,
            token = %token
        )
    )]
    pub async fn decode_nras_token(
        verifier_url: &str,
        token: &str,
    ) -> Result<NvidiaAttestationClaims> {
        let jwks_url = create_jwks_url(verifier_url)?;
        let client = Client::builder().timeout(DEFAULT_TIMEOUT).build()?;
        let jwks_data: Value = client.get(&jwks_url).send().await?.json().await?;
        let header = decode_header(token)?;
        let kid = header.kid.ok_or_else(|| {
            AttestError::InvalidJwtToken(format!("Kid not found in token header"))
        })?;
        let matching_key = get_matching_key(&jwks_data, &kid).ok_or_else(|| {
            AttestError::InvalidJwtToken(format!("Matching key not found in JWKS data"))
        })?;
        let x5c = matching_key
            .get("x5c")
            .and_then(|x| x.as_array())
            .ok_or_else(|| {
                AttestError::InvalidJwtToken(format!("No x5c field in the matching key"))
            })?;
        let cert_b64 = x5c.get(0).and_then(|c| c.as_str()).ok_or_else(|| {
            AttestError::InvalidJwtToken(format!("No certificate found in x5c field"))
        })?;
        let cert_der = STANDARD.decode(cert_b64)?;
        decode_jwt_token(&token, &cert_der)
    }

    /// Generate JWKS URL using the verifier URL
    ///
    /// # Arguments
    ///
    /// * `verifier_url` - The URL of the verifier service
    ///
    /// # Returns
    ///
    /// * `Result<String>` - The JWKS URL
    #[tracing::instrument(level = "debug")]
    pub fn create_jwks_url(verifier_url: &str) -> Result<String> {
        // Parse the verifier URL
        let parsed_url = Url::parse(verifier_url)?;

        // Extract the scheme and host
        let scheme = parsed_url.scheme();
        let host = parsed_url.host_str().unwrap_or("");
        let port = parsed_url
            .port()
            .map(|p| format!(":{}", p))
            .unwrap_or_default();

        // Construct the JWKS URL
        let jwks_url = format!("{scheme}://{host}{port}/.well-known/jwks.json");
        Ok(jwks_url)
    }

    /// Finds a matching key in JWKS data based on the key ID (kid)
    ///
    /// # Arguments
    ///
    /// * `jwks_data` - The JWKS data containing keys
    /// * `kid` - The key ID to search for
    ///
    /// # Returns
    ///
    /// * `Option<&Value>` - The matching key if found, or None
    #[tracing::instrument(level = "debug", skip(jwks_data))]
    pub fn get_matching_key<'a>(jwks_data: &'a Value, kid: &str) -> Option<&'a Value> {
        // Try to get the "keys" array from the JWKS data
        jwks_data
            .get(KEYS_KEY)
            .and_then(|keys| keys.as_array())
            .and_then(|keys_array| {
                // Iterate through the keys to find a matching kid
                keys_array.iter().find(|key| {
                    key.get(KID_KEY)
                        .and_then(|k| k.as_str())
                        .map_or(false, |k| k == kid)
                })
            })
    }

    /// Decode a JWT token using a certificate's public key
    ///
    /// # Arguments
    ///
    /// * `token` - The JWT token to decode
    /// * `cert_der` - The DER-encoded certificate data
    ///
    /// # Returns
    ///
    /// * `Result<NvidiaAttestationClaims>` - The decoded token claims or an error
    #[tracing::instrument(skip(token, cert_der))]
    fn decode_jwt_token(token: &str, cert_der: &[u8]) -> Result<NvidiaAttestationClaims> {
        // Parse the X.509 certificate
        dbg!("cert_der: {:?}", cert_der);
        let (_, cert) = X509Certificate::from_der(cert_der)?;

        // Extract the public key from the certificate
        dbg!("cert: {:?}", cert.clone());
        let public_key = cert.public_key();
        dbg!("public_key: {:?}", public_key);
        let public_key_data = public_key.raw;
        dbg!("public_key_data: {:?}", public_key_data);

        // Create a decoding key from the public key
        let decoding_key = DecodingKey::from_ec_der(public_key_data);
        dbg!("decoding_key");

        // Set up validation parameters
        let mut validation = Validation::new(Algorithm::ES384);

        // Decode the token with our custom claims structure
        dbg!("token: {:?}", token);
        let token_data = decode::<NvidiaAttestationClaims>(token, &decoding_key, &validation)?;
        dbg!("token_data: {:?}", token_data.clone());
        Ok(token_data.claims)
    }
}
