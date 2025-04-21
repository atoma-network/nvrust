use serde::{Deserialize, Serialize};

/// Represents attestation evidence for a hardware device (GPU or NVSwitch)
///
/// This structure contains the certificate chain and attestation evidence
/// required to verify the authenticity and integrity of a hardware device.
/// Both fields are stored as base64 encoded strings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceEvidence {
    /// The certificate chain for the device (either GPU or NVSwitch),
    /// in base64 encoded format
    pub certificate: String,

    /// The remote attestation evidence for the device (either GPU or NVSwitch),
    /// in base64 encoded format
    pub evidence: String,
}

/// Represents attestation evidence for an NVSwitch device
///
/// This structure contains the certificate chain and attestation evidence
/// required to verify the authenticity and integrity of an NVSwitch device.
/// Both fields are stored as base64 encoded strings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvSwitchEvidence {
    /// The UUID of the NVSwitch device
    pub uuid: String,

    /// The certificate chain for the NVSwitch device, in base64 encoded format
    pub certificate: String,

    /// The remote attestation evidence for the NVSwitch device, in base64 encoded format
    pub evidence: String,
}
