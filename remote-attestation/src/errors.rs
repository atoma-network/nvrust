use thiserror::Error;

pub type Result<T> = std::result::Result<T, AttestError>;

#[derive(Debug, Error)]
pub enum AttestError {
    #[error("Failed to attest remote")]
    RemoteAttestationFailed,
    #[error("Response error: {0}")]
    ResponseError(String),
    #[error("Failed to parse response")]
    ParseResponseError(#[from] reqwest::Error),
    #[error("Failed to get overall claims token")]
    JsonError(#[from] serde_json::Error),
    #[error("Failed to parse JWKS URL")]
    UrlParseError(#[from] url::ParseError),
    #[error("Failed to decode header")]
    HeaderDecodeError(#[from] jsonwebtoken::errors::Error),
    #[error("Invalid JWT token: {0}")]
    InvalidJwtToken(String),
    #[error("Failed to decode certificate")]
    CertificateDecodeError(#[from] base64::DecodeError),
    #[error("Failed to parse certificate")]
    CertificateParseError(
        #[from] x509_parser::asn1_rs::Err<x509_parser::prelude::error::X509Error>,
    ),
}
