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
    #[error("Failed to parse service key")]
    ServiceKeyParseError(#[from] reqwest::header::InvalidHeaderValue),
    #[error("Failed to get all switch UUID: `{0}`")]
    NscqError(#[from] NscqError),
}

#[derive(Debug, Error)]
pub enum NscqError {
    NscqRcSuccess,
    NscqRcWarningRdtInitFailure,
    NscqRcErrorNotImplemented,
    NscqRcErrorInvalidUuid,
    NscqRcErrorResourceNotMountable,
    NscqRcErrorOverflow,
    NscqRcErrorUnexpectedValue,
    NscqRcErrorUnsupportedDrv,
    NscqRcErrorDrv,
    NscqRcErrorTimeout,
    NscqRcErrorExt,
    NscqRcErrorUnspecified,
}

impl From<i8> for NscqError {
    fn from(rc: i8) -> Self {
        match rc {
            0 => NscqError::NscqRcSuccess,
            1 => NscqError::NscqRcWarningRdtInitFailure,
            -1 => NscqError::NscqRcErrorNotImplemented,
            -2 => NscqError::NscqRcErrorInvalidUuid,
            -3 => NscqError::NscqRcErrorResourceNotMountable,
            -4 => NscqError::NscqRcErrorOverflow,
            -5 => NscqError::NscqRcErrorUnexpectedValue,
            -6 => NscqError::NscqRcErrorUnsupportedDrv,
            -7 => NscqError::NscqRcErrorDrv,
            -8 => NscqError::NscqRcErrorTimeout,
            -127 => NscqError::NscqRcErrorExt,
            -128 => NscqError::NscqRcErrorUnspecified,
            _ => {
                tracing::error!("Unknown NSCQ Rc error status: {rc}. This should never happen.");
                panic!("Unknown NSCQ Rc error status: {rc}");
            }
        }
    }
}

impl std::fmt::Display for NscqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
