use std::{error::Error, fmt};

/// NSCQ return code type
pub type nscq_rc_t = i8;

pub type Result<T> = std::result::Result<T, NscqError>;

/// Return Code Enum and Error Handling
#[repr(i8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NscqRc {
    Success = 0,
    WarningRdtInitFailure = 1,
    ErrorNotImplemented = -1,
    ErrorInvalidUuid = -2,
    ErrorResourceNotMountable = -3,
    ErrorOverflow = -4,
    ErrorUnexpectedValue = -5,
    ErrorUnsupportedDrv = -6,
    ErrorDrv = -7,
    ErrorTimeout = -8,
    ErrorExt = -127,
    ErrorUnspecified = -128,
}

impl TryFrom<nscq_rc_t> for NscqRc {
    type Error = NscqError; // Or a simple error type indicating invalid value

    fn try_from(value: nscq_rc_t) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(NscqRc::Success),
            1 => Ok(NscqRc::WarningRdtInitFailure),
            -1 => Ok(NscqRc::ErrorNotImplemented),
            -2 => Ok(NscqRc::ErrorInvalidUuid),
            -3 => Ok(NscqRc::ErrorResourceNotMountable),
            -4 => Ok(NscqRc::ErrorOverflow),
            -5 => Ok(NscqRc::ErrorUnexpectedValue),
            -6 => Ok(NscqRc::ErrorUnsupportedDrv),
            -7 => Ok(NscqRc::ErrorDrv),
            -8 => Ok(NscqRc::ErrorTimeout),
            -127 => Ok(NscqRc::ErrorExt),
            -128 => Ok(NscqRc::ErrorUnspecified),
            _ => Err(NscqError::UnknownReturnCode(value)),
        }
    }
}

#[derive(Debug)]
pub enum NscqError {
    Rc(NscqRc),
    UnknownReturnCode(i8),
    NulError(std::ffi::NulError),
    InvalidUtf8(std::str::Utf8Error),
    UnsupportedPlatform,
    LibraryLoadError(libloading::Error),
}

impl fmt::Display for NscqError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NscqError::Rc(rc) => write!(f, "NSCQ Error: {:?}", rc),
            NscqError::UnknownReturnCode(rc) => write!(f, "Unknown NSCQ return code: {}", rc),
            NscqError::NulError(e) => write!(f, "FFI NUL error: {}", e),
            NscqError::InvalidUtf8(e) => write!(f, "Invalid UTF-8 in C string: {}", e),
            NscqError::UnsupportedPlatform => write!(f, "Unsupported platform"),
            NscqError::LibraryLoadError(e) => write!(f, "Failed to load library: {}", e),
        }
    }
}

impl Error for NscqError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
         match self {
            NscqError::NulError(e) => Some(e),
            NscqError::InvalidUtf8(e) => Some(e),
            _ => None,
         }
    }
}

impl From<std::ffi::NulError> for NscqError {
    fn from(err: std::ffi::NulError) -> Self {
        NscqError::NulError(err)
    }
}
impl From<std::str::Utf8Error> for NscqError {
    fn from(err: std::str::Utf8Error) -> Self {
        NscqError::InvalidUtf8(err)
    }
}

/// Checks the nscq_rc_t return code. Returns Ok(()) for success,
/// logs a warning for warnings, and returns Err(NscqError) for errors.
#[inline(always)]
#[tracing::instrument(skip(rc))]
fn check_rc(rc: nscq_rc_t) -> Result<()> {
    match NscqRc::try_from(rc) {
        Ok(NscqRc::Success) => Ok(()),
        Ok(warning @ NscqRc::WarningRdtInitFailure) => {
            // Use a proper logging framework in a real application
            tracing::warn!("NSCQ Warning: {:?}", warning);
            Ok(())
        }
        Ok(error_rc) => Err(NscqError::Rc(error_rc)), // Known errors
        Err(e) => Err(e), // Unknown return code
    }
}