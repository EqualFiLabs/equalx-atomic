#[repr(u16)]
#[derive(Copy, Clone, Debug)]
pub enum EswpError {
    MagicMismatch = 1001,
    VersionUnsupported = 1002,
    BackendMismatch = 1003,
    RingInvalid = 1004,
    RespIndexUnadmitted = 1005,
    PreHashMismatch = 1006,
    FinalSigInvalid = 1007,
    EncodingNoncanonical = 1008,
    CtxMismatch = 1009,
    CtxUnsupported = 1010,
}
