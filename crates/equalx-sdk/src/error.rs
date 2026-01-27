//! Error codes shared across the EqualX SDK.

use core::fmt;

/// Result type alias that carries [`ErrorCode`] failures.
pub type Result<T> = std::result::Result<T, ErrorCode>;

/// Unified error taxonomy for the SDK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
    /// CLSAG adaptor statement is invalid or empty.
    ClsagInvalidRing = 1001,
    /// CLSAG response map is inconsistent with expectations.
    ClsagResponseMismatch = 1002,
    /// FCMP adaptor statement is invalid or empty.
    FcmpInvalidStatement = 2001,
    /// FCMP adaptor parameters mismatch recorded metadata.
    FcmpAdaptorMismatch = 2002,
    /// Settlement/escrow deadlines are ordered incorrectly.
    PolicyDeadlineOrder = 4001,
    /// Settlement digest does not meet canonical requirements.
    PolicyDigestLength = 4002,
    /// Settlement context digest mismatch detected.
    SettlementDigestMismatch = 4101,
    /// Missing Monero transaction hash when required.
    TxHashMissing = 4109,
    /// tauPub payload missing or malformed.
    TauPubInvalid = 4110,
    /// On-chain signature would be rejected.
    SignatureInvalid = 4111,
    /// Unsupported backend or bridge parameters.
    BridgeBackendUnsupported = 4200,
    /// Transcript binding mismatch during verification.
    BridgeTranscriptMismatch = 4201,
    /// Log payload failed to decode into a known event.
    BridgeInvalidLog = 4202,
    /// EVM transport or signing failure.
    BridgeTransportEvm = 4203,
    /// Monero RPC failure during automation.
    BridgeTransportMonero = 4204,
}

impl ErrorCode {
    /// Numeric representation associated with the error.
    pub fn code(self) -> u16 {
        self as u16
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?} ({})", self.code())
    }
}

impl std::error::Error for ErrorCode {}
