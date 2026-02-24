//! Shared error taxonomy for EqualX integration layers.

use core::fmt;

/// EqualX integration kit semantic version (MAJOR).
pub const VERSION_MAJOR: u16 = 0;
/// EqualX integration kit semantic version (MINOR).
pub const VERSION_MINOR: u16 = 0;
/// EqualX integration kit semantic version (PATCH).
pub const VERSION_PATCH: u16 = 1;
/// EqualX ABI wire version returned via `eswp_wire_version`.
pub const ABI_WIRE_VERSION: u32 = 1;
/// Human-readable semantic version string.
pub const VERSION: &str = "0.0.1";

/// Result type alias for operations that return [`ErrorCode`].
pub type Result<T> = core::result::Result<T, ErrorCode>;

/// High-level error families used across L0-L4.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorDomain {
    /// L0 cryptographic and protocol primitive failures.
    Core = 0x0100,
    /// L1 chain-interaction and watcher failures.
    Chain = 0x0200,
    /// L2 orchestration and state-machine failures.
    Orchestrator = 0x0300,
    /// L3 FFI boundary failures.
    Ffi = 0x0400,
    /// L4 host-adapter callback and environment failures.
    Adapter = 0x0500,
}

/// Stable numeric error taxonomy shared across layers.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    // L0: Core
    InvalidScalar = 0x0101,
    InvalidPoint = 0x0102,
    DuplicateRingMember = 0x0103,
    PresigVerificationFailed = 0x0104,
    TauExtractionFailed = 0x0105,
    EnvelopeDecryptionFailed = 0x0106,
    EnvelopeTampered = 0x0107,

    // L1: Chain
    UnknownEventTopic = 0x0201,
    TruncatedEventData = 0x0202,
    RpcError = 0x0203,
    ReorgDetected = 0x0204,

    // L2: Orchestrator
    InvalidStateTransition = 0x0301,
    DeadlineExceeded = 0x0302,
    CheckpointCorrupted = 0x0303,
    SwapNotFound = 0x0304,

    // L3: FFI
    NullPointer = 0x0401,
    InvalidLength = 0x0402,
    BufferTooSmall = 0x0403,
    UnsupportedVersion = 0x0404,
    InternalPanic = 0x04FF,

    // L4: Adapter
    AdapterCallFailed = 0x0501,
    AdapterTimeout = 0x0502,
    NetworkUnreachable = 0x0503,
}

impl ErrorCode {
    /// Numeric representation associated with this error.
    pub const fn code(self) -> i32 {
        self as i32
    }

    /// Error domain for this error code.
    pub const fn domain(self) -> ErrorDomain {
        match self {
            Self::InvalidScalar
            | Self::InvalidPoint
            | Self::DuplicateRingMember
            | Self::PresigVerificationFailed
            | Self::TauExtractionFailed
            | Self::EnvelopeDecryptionFailed
            | Self::EnvelopeTampered => ErrorDomain::Core,
            Self::UnknownEventTopic
            | Self::TruncatedEventData
            | Self::RpcError
            | Self::ReorgDetected => ErrorDomain::Chain,
            Self::InvalidStateTransition
            | Self::DeadlineExceeded
            | Self::CheckpointCorrupted
            | Self::SwapNotFound => ErrorDomain::Orchestrator,
            Self::NullPointer
            | Self::InvalidLength
            | Self::BufferTooSmall
            | Self::UnsupportedVersion
            | Self::InternalPanic => ErrorDomain::Ffi,
            Self::AdapterCallFailed | Self::AdapterTimeout | Self::NetworkUnreachable => {
                ErrorDomain::Adapter
            }
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?} (0x{:04X})", self.code())
    }
}

impl std::error::Error for ErrorCode {}

/// Adapter-originated error context propagated by orchestration layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterError {
    /// Stable kit-level classification.
    pub code: ErrorCode,
    /// Human-readable context string.
    pub message: String,
    /// Optional raw host-side error code.
    pub adapter_code: Option<i32>,
}

impl AdapterError {
    /// Construct an adapter error with a stable kit error code and message.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            adapter_code: None,
        }
    }

    /// Attach a host-native adapter error code.
    pub fn with_adapter_code(mut self, adapter_code: i32) -> Self {
        self.adapter_code = Some(adapter_code);
        self
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.adapter_code {
            Some(adapter_code) => write!(
                f,
                "{}: {} (adapter_code={adapter_code})",
                self.code, self.message
            ),
            None => write!(f, "{}: {}", self.code, self.message),
        }
    }
}

impl std::error::Error for AdapterError {}

impl From<ErrorCode> for AdapterError {
    fn from(code: ErrorCode) -> Self {
        Self::new(code, code.to_string())
    }
}

impl From<AdapterError> for ErrorCode {
    fn from(error: AdapterError) -> Self {
        error.code
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AdapterError, ErrorCode, ErrorDomain, ABI_WIRE_VERSION, VERSION, VERSION_MAJOR,
        VERSION_MINOR, VERSION_PATCH,
    };

    #[test]
    fn stable_numeric_values_match_design_contract() {
        assert_eq!(ErrorCode::InvalidScalar as i32, 0x0101);
        assert_eq!(ErrorCode::ReorgDetected as i32, 0x0204);
        assert_eq!(ErrorCode::SwapNotFound as i32, 0x0304);
        assert_eq!(ErrorCode::InternalPanic as i32, 0x04FF);
        assert_eq!(ErrorCode::NetworkUnreachable as i32, 0x0503);
    }

    #[test]
    fn domain_mapping_is_correct() {
        assert_eq!(ErrorCode::InvalidPoint.domain(), ErrorDomain::Core);
        assert_eq!(ErrorCode::RpcError.domain(), ErrorDomain::Chain);
        assert_eq!(
            ErrorCode::InvalidStateTransition.domain(),
            ErrorDomain::Orchestrator
        );
        assert_eq!(ErrorCode::BufferTooSmall.domain(), ErrorDomain::Ffi);
        assert_eq!(ErrorCode::AdapterTimeout.domain(), ErrorDomain::Adapter);
    }

    #[test]
    fn adapter_error_conversions_preserve_error_code() {
        let adapter_error: AdapterError = ErrorCode::RpcError.into();
        assert_eq!(adapter_error.code, ErrorCode::RpcError);
        assert!(adapter_error.message.contains("RpcError"));

        let error_code: ErrorCode = AdapterError::new(ErrorCode::SwapNotFound, "missing").into();
        assert_eq!(error_code, ErrorCode::SwapNotFound);
    }

    #[test]
    fn adapter_error_display_includes_optional_host_code() {
        let rendered = AdapterError::new(ErrorCode::AdapterCallFailed, "callback failure")
            .with_adapter_code(1234)
            .to_string();
        assert!(rendered.contains("AdapterCallFailed"));
        assert!(rendered.contains("callback failure"));
        assert!(rendered.contains("1234"));
    }

    #[test]
    fn semantic_version_constants_are_consistent() {
        assert_eq!(VERSION_MAJOR, 0);
        assert_eq!(VERSION_MINOR, 0);
        assert_eq!(VERSION_PATCH, 1);
        assert_eq!(VERSION, "0.0.1");
        assert_eq!(ABI_WIRE_VERSION, 1);
    }
}
