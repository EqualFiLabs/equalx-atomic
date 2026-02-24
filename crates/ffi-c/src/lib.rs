use adaptor_clsag::{
    complete as adaptor_complete, extract_t as adaptor_extract_t,
    make_pre_sig as adaptor_make_pre_sig, verify as adaptor_verify,
    wire::{ClsagFinalSigContainer, ClsagPreSig},
    ClsagCtx, EswpError, FinalSig, PreSig, SettlementCtx, SignerWitness, BACKEND_ID_CLSAG,
    WIRE_VERSION as CLSAG_WIRE_VERSION,
};
use alloy_primitives::{Address as AlloyAddress, Bytes, B256, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use equalx_error::{
    AdapterError as HostAdapterError, ErrorCode as KitErrorCode, ABI_WIRE_VERSION, VERSION_MAJOR,
    VERSION_MINOR, VERSION_PATCH,
};
use equalx_sdk::error::ErrorCode;
use equalx_sdk::transport::{EvmCall, EvmMessageSigner, EvmTransport, EvmViewTransport};
use equalx_sdk::{
    compute_key_image as sdk_compute_key_image, derive_subaddress as sdk_derive_subaddress,
    generate_evm_keypair as sdk_generate_evm_keypair,
    generate_monero_keypair as sdk_generate_monero_keypair,
    sign_evm_message as sdk_sign_evm_message,
};
use equalx_sdk::{
    decode_events as sdk_decode_events, prepare_refund as sdk_prepare_refund,
    Address as SdkAddress, Backend as SdkBackend, EscrowClient, EscrowEvent, EscrowLog,
    EscrowRefundArgs, LockErc20Args, LockEthArgs, PostTxHashArgs, QuoteBoardClient,
    QuoteCommitment, RefundParams, Result as SdkResult, SettleArgs,
    SettlementCtx as SdkSettlementCtx, TxHash,
};
use host_adapter::{
    EvmExecutionAdapter, KeyIdentityAdapter, LogEntry, LogFilter, MoneroExecutionAdapter,
    NodeHealth, PersistenceAdapter, SpendState, SwapLifecycleEvent, TimeNetworkAdapter, TxReceipt,
    UxEventAdapter,
};
use libc::{c_char, c_int, c_uchar, c_uint, c_void};
use monero_oxide::ringct::clsag::Clsag;
use once_cell::sync::Lazy;
use orchestrator::{
    MoneroContext, OrchestratorConfig, ReservationId, ReservationParams, SwapOrchestrator,
};
#[cfg(test)]
use std::ffi::CStr;
use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    ffi::CString,
    io::Cursor,
    panic::{self, AssertUnwindSafe},
    ptr, slice, str,
    sync::{Arc, Mutex},
    thread::{self, ThreadId},
};
use watcher::evm::{
    decode_atomic_reservation_created as watcher_decode_atomic_reservation_created,
    decode_hashlock_set as watcher_decode_hashlock_set,
    decode_reservation_created as watcher_decode_reservation_created,
    decode_reservation_refunded as watcher_decode_reservation_refunded,
    decode_reservation_settled as watcher_decode_reservation_settled,
    decode_taker_tranche_opened as watcher_decode_taker_tranche_opened,
    decode_taker_tranche_reserved as watcher_decode_taker_tranche_reserved,
    decode_tranche_opened as watcher_decode_tranche_opened,
    decode_tranche_reserved as watcher_decode_tranche_reserved,
};

type RingEntries = Vec<[u8; 32]>;
type CommitmentEntries = Vec<[u8; 32]>;

const ADAPTOR_SCALAR_LEN: usize = 32;

#[repr(C)]
pub struct EswpEscrowLog {
    pub kind: c_uchar,
    pub backend: c_uchar,
    pub swap_id: [u8; 32],
    pub amount_be: [u8; 32],
}

#[repr(C)]
pub struct EswpEscrowEvent {
    pub digest: [u8; 32],
    pub swap_id: [u8; 32],
    pub amount_be: [u8; 32],
    pub backend: c_uchar,
    pub kind: c_uchar,
}

#[repr(C)]
pub struct CapabilityDescriptor {
    pub version_major: u16,
    pub version_minor: u16,
    pub version_patch: u16,
    pub backends: u32,
    pub api_groups: u32,
    pub wire_version: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EswpReservationCreatedEvent {
    pub reservation_id: [u8; 32],
    pub taker: [u8; 20],
    pub desk: [u8; 20],
    pub amount_be: [u8; 32],
    pub counter_be: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EswpHashlockSetEvent {
    pub reservation_id: [u8; 32],
    pub hashlock: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EswpAtomicReservationCreatedEvent {
    pub reservation_id: [u8; 32],
    pub desk_id: [u8; 32],
    pub taker: [u8; 20],
    pub asset: [u8; 20],
    pub amount_be: [u8; 32],
    pub settlement_digest: [u8; 32],
    pub expiry: u64,
    pub created_at: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EswpTrancheOpenedEvent {
    pub tranche_id: [u8; 32],
    pub desk_id: [u8; 32],
    pub maker: [u8; 20],
    pub asset: [u8; 20],
    pub price_numerator_be: [u8; 32],
    pub price_denominator_be: [u8; 32],
    pub total_liquidity_be: [u8; 32],
    pub min_fill_be: [u8; 32],
    pub fee_bps: u16,
    pub fee_payer: u8,
    pub expiry: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EswpTakerTrancheOpenedEvent {
    pub tranche_id: [u8; 32],
    pub desk_id: [u8; 32],
    pub taker: [u8; 20],
    pub asset: [u8; 20],
    pub price_numerator_be: [u8; 32],
    pub price_denominator_be: [u8; 32],
    pub total_liquidity_be: [u8; 32],
    pub min_fill_be: [u8; 32],
    pub fee_bps: u16,
    pub fee_payer: u8,
    pub expiry: u64,
    pub posting_fee_be: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EswpTrancheReservedEvent {
    pub tranche_id: [u8; 32],
    pub reservation_id: [u8; 32],
    pub actor: [u8; 20],
    pub amount_be: [u8; 32],
    pub remaining_liquidity_be: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EswpSettleEvent {
    pub reservation_id: [u8; 32],
    pub value: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EswpOrchestratorConfig {
    pub checkpoint_version: u8,
    pub maker_timeout_secs: u64,
    pub taker_timeout_secs: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EswpDeadlineEvent {
    pub reservation_id: [u8; 32],
    pub deadline: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CEvmCallbacks {
    pub send_raw_tx: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            tx_ptr: *const c_uchar,
            tx_len: c_uint,
            out_hash32: *mut c_uchar,
        ) -> c_int,
    >,
    pub estimate_gas: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            call_data_ptr: *const c_uchar,
            call_data_len: c_uint,
            out_gas: *mut u64,
        ) -> c_int,
    >,
    pub replace_tx: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            original_hash32: *const c_uchar,
            new_gas: u64,
            out_hash32: *mut c_uchar,
        ) -> c_int,
    >,
    pub get_receipt: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            tx_hash32: *const c_uchar,
            out_receipt_ptr: *mut c_uchar,
            out_receipt_capacity: c_uint,
            out_receipt_len: *mut c_uint,
        ) -> c_int,
    >,
    pub get_logs: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            filter_ptr: *const c_uchar,
            filter_len: c_uint,
            out_logs_ptr: *mut c_uchar,
            out_logs_capacity: c_uint,
            out_logs_len: *mut c_uint,
        ) -> c_int,
    >,
    pub chain_id:
        Option<unsafe extern "C" fn(user_data: *mut c_void, out_chain_id: *mut u64) -> c_int>,
    pub block_number:
        Option<unsafe extern "C" fn(user_data: *mut c_void, out_block: *mut u64) -> c_int>,
    pub gas_price: Option<
        unsafe extern "C" fn(user_data: *mut c_void, out_gas_price_be16: *mut c_uchar) -> c_int,
    >,
    pub user_data: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CMoneroCallbacks {
    pub broadcast_tx: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            tx_ptr: *const c_uchar,
            tx_len: c_uint,
            out_hash32: *mut c_uchar,
        ) -> c_int,
    >,
    pub is_key_image_spent: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            key_images_ptr: *const c_uchar,
            key_images_count: c_uint,
            out_states_ptr: *mut c_uchar,
            out_states_capacity: c_uint,
            out_states_len: *mut c_uint,
        ) -> c_int,
    >,
    pub get_tx_confirmations: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            tx_hash32: *const c_uchar,
            out_has_value: *mut c_uchar,
            out_confirmations: *mut u64,
        ) -> c_int,
    >,
    pub node_health: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            out_health_ptr: *mut c_uchar,
            out_health_capacity: c_uint,
            out_health_len: *mut c_uint,
        ) -> c_int,
    >,
    pub user_data: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CKeyCallbacks {
    pub evm_address:
        Option<unsafe extern "C" fn(user_data: *mut c_void, out_addr20: *mut c_uchar) -> c_int>,
    pub sign_evm_message: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            digest32: *const c_uchar,
            out_sig_ptr: *mut c_uchar,
            out_sig_capacity: c_uint,
            out_sig_len: *mut c_uint,
        ) -> c_int,
    >,
    pub monero_spend_public_key:
        Option<unsafe extern "C" fn(user_data: *mut c_void, out_key32: *mut c_uchar) -> c_int>,
    pub monero_view_public_key:
        Option<unsafe extern "C" fn(user_data: *mut c_void, out_key32: *mut c_uchar) -> c_int>,
    pub monero_derive_subaddress: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            major: u32,
            minor: u32,
            out_addr_ptr: *mut c_uchar,
            out_addr_capacity: c_uint,
            out_addr_len: *mut c_uint,
        ) -> c_int,
    >,
    pub monero_compute_key_image: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            output_pubkey32: *const c_uchar,
            output_index: u64,
            out_key_image32: *mut c_uchar,
        ) -> c_int,
    >,
    pub user_data: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CPersistenceCallbacks {
    pub save_checkpoint: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            reservation_id32: *const c_uchar,
            state_ptr: *const c_uchar,
            state_len: c_uint,
        ) -> c_int,
    >,
    pub load_checkpoint: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            reservation_id32: *const c_uchar,
            out_ptr: *mut c_uchar,
            out_capacity: c_uint,
            out_len: *mut c_uint,
        ) -> c_int,
    >,
    pub list_active_swaps: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            out_ids_ptr: *mut c_uchar,
            out_ids_capacity: c_uint,
            out_ids_len: *mut c_uint,
        ) -> c_int,
    >,
    pub delete_swap: Option<
        unsafe extern "C" fn(user_data: *mut c_void, reservation_id32: *const c_uchar) -> c_int,
    >,
    pub user_data: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CTimeNetworkCallbacks {
    pub current_block_number:
        Option<unsafe extern "C" fn(user_data: *mut c_void, out_block: *mut u64) -> c_int>,
    pub current_timestamp:
        Option<unsafe extern "C" fn(user_data: *mut c_void, out_ts: *mut u64) -> c_int>,
    pub is_evm_reachable:
        Option<unsafe extern "C" fn(user_data: *mut c_void, out_value: *mut c_uchar) -> c_int>,
    pub is_monero_reachable:
        Option<unsafe extern "C" fn(user_data: *mut c_void, out_value: *mut c_uchar) -> c_int>,
    pub user_data: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CUxCallbacks {
    pub on_event: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            event_ptr: *const c_uchar,
            event_len: c_uint,
        ) -> c_int,
    >,
    pub user_data: *mut c_void,
}

#[derive(Debug)]
enum FfiError {
    NullPointer,
    LengthInvalid,
    Decode,
    SecretsInvalid,
    RingIndexOutOfRange,
    RingSizeUnsupported,
    CapacityInsufficient,
    InvalidCommand,
    NotFound,
    InternalPanic,
    Eswp(EswpError),
    Sdk(ErrorCode),
    Kit(KitErrorCode),
}

impl From<EswpError> for FfiError {
    fn from(value: EswpError) -> Self {
        Self::Eswp(value)
    }
}

impl From<ErrorCode> for FfiError {
    fn from(value: ErrorCode) -> Self {
        Self::Sdk(value)
    }
}

impl From<KitErrorCode> for FfiError {
    fn from(value: KitErrorCode) -> Self {
        Self::Kit(value)
    }
}

fn quote_commitment_from_adaptor(adaptor_hash: [u8; 32]) -> QuoteCommitment {
    QuoteCommitment {
        adaptor_hash,
        m_digest: [0u8; 32],
        envelope: Bytes::new(),
    }
}

impl FfiError {
    fn code(&self) -> c_int {
        match self {
            Self::NullPointer => 1,
            Self::LengthInvalid => 2,
            Self::Decode => 3,
            Self::SecretsInvalid => 4,
            Self::RingIndexOutOfRange => 5,
            Self::RingSizeUnsupported => 6,
            Self::CapacityInsufficient => 7,
            Self::InvalidCommand => KitErrorCode::InvalidLength.code(),
            Self::NotFound => KitErrorCode::SwapNotFound.code(),
            Self::InternalPanic => KitErrorCode::InternalPanic.code(),
            Self::Eswp(err) => *err as c_int,
            Self::Sdk(err) => err.code() as c_int,
            Self::Kit(err) => err.code(),
        }
    }
}

const BACKEND_MASK_CLSAG: u32 = 1 << 0;
const API_GROUP_KEY_REGISTRY: u32 = 1 << 0;
const API_GROUP_MAILBOX: u32 = 1 << 1;
const API_GROUP_ATOMIC_DESK: u32 = 1 << 2;
const API_GROUP_ESCROW: u32 = 1 << 3;
const API_GROUP_EVENT_DECODE: u32 = 1 << 4;
const API_GROUP_ORCHESTRATOR: u32 = 1 << 5;

#[derive(Default)]
struct L3State {
    key_registry: HashMap<[u8; 20], [u8; 33]>,
    mailbox: HashMap<[u8; 32], Vec<Vec<u8>>>,
    reservations: HashMap<[u8; 32], EswpAtomicReservationCreatedEvent>,
    desks: HashSet<[u8; 32]>,
}

static L3_STATE: Lazy<Mutex<L3State>> = Lazy::new(|| Mutex::new(L3State::default()));
static BUFFER_ALLOCS: Lazy<Mutex<HashMap<usize, usize>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static STRING_ALLOCS: Lazy<Mutex<HashSet<usize>>> = Lazy::new(|| Mutex::new(HashSet::new()));

fn ffi_guard<F>(f: F) -> c_int
where
    F: FnOnce() -> Result<(), FfiError>,
{
    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => 0,
        Ok(Err(err)) => err.code(),
        Err(_) => FfiError::InternalPanic.code(),
    }
}

fn map_callback_code(code: c_int, context: &str) -> HostAdapterError {
    if code == 0 {
        return HostAdapterError::new(KitErrorCode::AdapterCallFailed, context);
    }
    let stable = match code {
        x if x == KitErrorCode::AdapterCallFailed.code() => KitErrorCode::AdapterCallFailed,
        x if x == KitErrorCode::AdapterTimeout.code() => KitErrorCode::AdapterTimeout,
        x if x == KitErrorCode::NetworkUnreachable.code() => KitErrorCode::NetworkUnreachable,
        x if x == KitErrorCode::NullPointer.code() => KitErrorCode::NullPointer,
        x if x == KitErrorCode::InvalidLength.code() => KitErrorCode::InvalidLength,
        x if x == KitErrorCode::BufferTooSmall.code() => KitErrorCode::BufferTooSmall,
        _ => KitErrorCode::AdapterCallFailed,
    };
    HostAdapterError::new(stable, format!("{context} (callback_code={code})"))
        .with_adapter_code(code)
}

fn encode_lifecycle_event(event: &SwapLifecycleEvent) -> Result<Vec<u8>, HostAdapterError> {
    let rendered = format!("{event:?}");
    if rendered.is_empty() {
        return Err(HostAdapterError::new(
            KitErrorCode::AdapterCallFailed,
            "serialize lifecycle event yielded empty payload",
        ));
    }
    Ok(rendered.into_bytes())
}

fn register_buffer_alloc(ptr: *mut c_uchar, len: usize) {
    BUFFER_ALLOCS
        .lock()
        .expect("buffer alloc mutex poisoned")
        .insert(ptr as usize, len);
}

fn register_string_alloc(ptr: *mut c_char) {
    STRING_ALLOCS
        .lock()
        .expect("string alloc mutex poisoned")
        .insert(ptr as usize);
}

fn parse_topics(topics_ptr: *const c_uchar, topics_len: c_uint) -> Result<Vec<B256>, FfiError> {
    let count = topics_len as usize;
    if count == 0 {
        return Err(FfiError::LengthInvalid);
    }
    let bytes = read_bytes(topics_ptr, count * 32)?;
    let mut out = Vec::with_capacity(count);
    for chunk in bytes.chunks_exact(32) {
        let mut word = [0u8; 32];
        word.copy_from_slice(chunk);
        out.push(B256::from(word));
    }
    Ok(out)
}

struct DecodedPre {
    pre: PreSig,
    ctx: ClsagCtx,
    msg: Vec<u8>,
}

struct DecodedFinal {
    final_sig: FinalSig,
    pre_hash: [u8; 32],
    ctx: SettlementCtx,
    resp_index: usize,
}

fn parse_ring_bytes(bytes: &[u8]) -> Result<(RingEntries, CommitmentEntries), FfiError> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(32) {
        return Err(FfiError::LengthInvalid);
    }

    if bytes.len().is_multiple_of(64) {
        let n = bytes.len() / 64;
        if n == 0 || n > u8::MAX as usize {
            return Err(FfiError::RingSizeUnsupported);
        }
        let mut keys: RingEntries = Vec::with_capacity(n);
        let mut commitments: CommitmentEntries = Vec::with_capacity(n);
        for chunk in bytes.chunks_exact(64) {
            let (pk_bytes, commitment_bytes) = chunk.split_at(32);
            let mut key = [0u8; 32];
            key.copy_from_slice(pk_bytes);
            let mut commitment = [0u8; 32];
            commitment.copy_from_slice(commitment_bytes);
            keys.push(key);
            commitments.push(commitment);
        }
        Ok((keys, commitments))
    } else {
        let n = bytes.len() / 32;
        if n == 0 || n > u8::MAX as usize {
            return Err(FfiError::RingSizeUnsupported);
        }
        let mut keys: RingEntries = Vec::with_capacity(n);
        for chunk in bytes.chunks_exact(32) {
            let mut key = [0u8; 32];
            key.copy_from_slice(chunk);
            keys.push(key);
        }
        Ok((keys, Vec::new()))
    }
}

struct SettlementCtxParts {
    chain_tag: String,
    position_key: [u8; 32],
    settle_digest: [u8; 32],
}

fn parse_settlement_ctx(bytes: &[u8]) -> Result<SettlementCtxParts, FfiError> {
    let mut cursor = 0usize;

    let chain_len = *bytes.get(cursor).ok_or(FfiError::LengthInvalid)? as usize;
    cursor += 1;
    if bytes.len() < cursor + chain_len {
        return Err(FfiError::LengthInvalid);
    }
    let chain_tag = str::from_utf8(&bytes[cursor..cursor + chain_len])
        .map_err(|_| FfiError::from(EswpError::EncodingNoncanonical))?
        .to_owned();
    cursor += chain_len;

    let position_len = *bytes.get(cursor).ok_or(FfiError::LengthInvalid)? as usize;
    cursor += 1;
    if position_len != 32 {
        return Err(FfiError::from(EswpError::CtxUnsupported));
    }
    if bytes.len() < cursor + position_len {
        return Err(FfiError::LengthInvalid);
    }
    let mut position_key = [0u8; 32];
    position_key.copy_from_slice(&bytes[cursor..cursor + position_len]);
    cursor += position_len;

    let settle_len = *bytes.get(cursor).ok_or(FfiError::LengthInvalid)? as usize;
    cursor += 1;
    if settle_len != 32 {
        return Err(FfiError::from(EswpError::CtxUnsupported));
    }
    if bytes.len() < cursor + settle_len {
        return Err(FfiError::LengthInvalid);
    }
    let mut settle_digest = [0u8; 32];
    settle_digest.copy_from_slice(&bytes[cursor..cursor + settle_len]);
    cursor += settle_len;

    if cursor != bytes.len() {
        return Err(FfiError::LengthInvalid);
    }

    Ok(SettlementCtxParts {
        chain_tag,
        position_key,
        settle_digest,
    })
}

fn decode_clsag_settlement_ctx(bytes: &[u8]) -> Result<SettlementCtx, FfiError> {
    let parts = parse_settlement_ctx(bytes)?;
    Ok(SettlementCtx {
        chain_tag: parts.chain_tag,
        position_key: parts.position_key,
        settle_digest: parts.settle_digest,
    })
}

fn decode_sdk_settlement_ctx(bytes: &[u8]) -> Result<SdkSettlementCtx, FfiError> {
    let parts = parse_settlement_ctx(bytes)?;
    SdkSettlementCtx::new(parts.chain_tag, parts.position_key, parts.settle_digest)
        .map_err(FfiError::from)
}

fn derive_witness(i_star: usize) -> SignerWitness {
    let mut x = [0u8; 32];
    x[..8].copy_from_slice(&((i_star + 1) as u64).to_le_bytes());
    let mut mask = [0u8; 32];
    mask[..8].copy_from_slice(&((i_star + 1) as u64).to_le_bytes());
    SignerWitness {
        x,
        mask,
        amount: 0,
        i_star,
    }
}

fn take_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], FfiError> {
    if bytes.len() < *cursor + N {
        return Err(FfiError::LengthInvalid);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*cursor..*cursor + N]);
    *cursor += N;
    Ok(out)
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, FfiError> {
    let raw = take_array::<4>(bytes, cursor)?;
    Ok(u32::from_le_bytes(raw))
}

fn encode_pre_bytes(
    msg: &[u8],
    ctx: &ClsagCtx,
    pre: &PreSig,
    swap_id: &[u8; 32],
    tau: &[u8; 32],
) -> Result<Vec<u8>, FfiError> {
    let ring_size = u8::try_from(ctx.n).map_err(|_| FfiError::RingSizeUnsupported)?;
    let ring_bytes: Vec<u8> = ctx.ring_keys.iter().flat_map(|key| key.to_vec()).collect();

    let commitments_len =
        u32::try_from(ctx.ring_commitments.len()).map_err(|_| FfiError::LengthInvalid)?;
    let responses_len = u32::try_from(pre.s_tilde.len()).map_err(|_| FfiError::LengthInvalid)?;

    let mut proof = Vec::new();
    proof.extend_from_slice(swap_id);
    proof.extend_from_slice(&ctx.key_image);
    proof.extend_from_slice(&commitments_len.to_le_bytes());
    for commitment in &ctx.ring_commitments {
        proof.extend_from_slice(commitment);
    }
    proof.extend_from_slice(&pre.c1_tilde);
    proof.extend_from_slice(&pre.d_tilde);
    proof.extend_from_slice(&pre.pseudo_out);
    proof.extend_from_slice(&responses_len.to_le_bytes());
    for response in &pre.s_tilde {
        proof.extend_from_slice(response);
    }
    proof.extend_from_slice(&(ADAPTOR_SCALAR_LEN as u32).to_le_bytes());
    proof.extend_from_slice(tau);

    let presig = ClsagPreSig {
        magic: adaptor_clsag::wire::MAGIC_CLSAG_PRESIG,
        wire_version: CLSAG_WIRE_VERSION,
        backend: BACKEND_ID_CLSAG,
        ring_size,
        resp_index: u8::try_from(pre.j).map_err(|_| FfiError::RingIndexOutOfRange)?,
        reserved0: 0,
        m: msg.to_vec(),
        ring_bytes,
        pre_hash: pre.pre_hash,
        ctx: pre.ctx.clone(),
        proof_bytes_sans_resp: proof,
    };

    presig.encode().map_err(FfiError::from)
}

fn decode_pre_bytes(bytes: &[u8]) -> Result<DecodedPre, FfiError> {
    let container = ClsagPreSig::decode(bytes).map_err(FfiError::from)?;
    let ring_size = container.ring_size as usize;
    if ring_size == 0 {
        return Err(FfiError::LengthInvalid);
    }
    if container.ring_bytes.len() != ring_size * 32 {
        return Err(FfiError::LengthInvalid);
    }
    let ring_keys: Vec<[u8; 32]> = container
        .ring_bytes
        .chunks_exact(32)
        .map(|chunk| {
            let mut key = [0u8; 32];
            key.copy_from_slice(chunk);
            key
        })
        .collect();

    let mut cursor = 0usize;
    let proof = &container.proof_bytes_sans_resp;
    let _swap_id = take_array::<32>(proof, &mut cursor)?;
    let key_image = take_array::<32>(proof, &mut cursor)?;
    let commitments_len =
        usize::try_from(read_u32(proof, &mut cursor)?).map_err(|_| FfiError::LengthInvalid)?;
    let mut ring_commitments = Vec::new();
    if commitments_len > 0 {
        if commitments_len != ring_size {
            return Err(FfiError::LengthInvalid);
        }
        for _ in 0..commitments_len {
            ring_commitments.push(take_array::<32>(proof, &mut cursor)?);
        }
    }
    let c1_tilde = take_array::<32>(proof, &mut cursor)?;
    let d_tilde = take_array::<32>(proof, &mut cursor)?;
    let pseudo_out = take_array::<32>(proof, &mut cursor)?;
    let responses_len =
        usize::try_from(read_u32(proof, &mut cursor)?).map_err(|_| FfiError::LengthInvalid)?;
    if responses_len != ring_size {
        return Err(FfiError::LengthInvalid);
    }
    let mut s_tilde = Vec::with_capacity(responses_len);
    for _ in 0..responses_len {
        s_tilde.push(take_array::<32>(proof, &mut cursor)?);
    }
    let tau_length = read_u32(proof, &mut cursor)?;
    if tau_length != ADAPTOR_SCALAR_LEN as u32 {
        return Err(FfiError::LengthInvalid);
    }
    let _tau = take_array::<32>(proof, &mut cursor)?;
    if cursor != proof.len() {
        return Err(FfiError::Decode);
    }

    let ctx = ClsagCtx {
        ring_keys,
        ring_commitments,
        key_image,
        n: ring_size,
    };

    let pre = PreSig {
        c1_tilde,
        s_tilde,
        d_tilde,
        pseudo_out,
        j: container.resp_index as usize,
        ctx: container.ctx.clone(),
        pre_hash: container.pre_hash,
    };

    Ok(DecodedPre {
        pre,
        ctx,
        msg: container.m,
    })
}

fn encode_final_bytes(pre: &PreSig, final_sig: &FinalSig) -> Result<Vec<u8>, FfiError> {
    let mut clsag_bytes = Vec::new();
    final_sig
        .clsag
        .write(&mut clsag_bytes)
        .map_err(|_| FfiError::Decode)?;

    let mut final_bytes = clsag_bytes;
    final_bytes.extend_from_slice(&final_sig.pseudo_out);

    let container = ClsagFinalSigContainer {
        magic: adaptor_clsag::wire::MAGIC_CLSAG_FINAL,
        wire_version: CLSAG_WIRE_VERSION,
        backend: BACKEND_ID_CLSAG,
        resp_index: u8::try_from(pre.j).map_err(|_| FfiError::RingIndexOutOfRange)?,
        final_sig: final_bytes,
        pre_hash: pre.pre_hash,
        ctx: pre.ctx.clone(),
    };

    container.encode().map_err(FfiError::from)
}

fn decode_final_bytes(bytes: &[u8], decoys: usize) -> Result<DecodedFinal, FfiError> {
    let container = ClsagFinalSigContainer::decode(bytes).map_err(FfiError::from)?;
    if container.final_sig.len() < 32 {
        return Err(FfiError::LengthInvalid);
    }
    let split_at = container.final_sig.len() - 32;
    let (clsag_bytes, pseudo_bytes) = container.final_sig.split_at(split_at);
    let mut cursor = Cursor::new(clsag_bytes);
    let clsag = Clsag::read(decoys, &mut cursor).map_err(|_| FfiError::Decode)?;
    if usize::try_from(cursor.position()).map_err(|_| FfiError::Decode)? != clsag_bytes.len() {
        return Err(FfiError::Decode);
    }
    let mut pseudo_out = [0u8; 32];
    pseudo_out.copy_from_slice(pseudo_bytes);

    Ok(DecodedFinal {
        final_sig: FinalSig { clsag, pseudo_out },
        pre_hash: container.pre_hash,
        ctx: container.ctx,
        resp_index: container.resp_index as usize,
    })
}

fn ctx_equal(a: &SettlementCtx, b: &SettlementCtx) -> bool {
    a.chain_tag == b.chain_tag
        && a.position_key == b.position_key
        && a.settle_digest == b.settle_digest
}

fn read_bytes<'a>(ptr: *const c_uchar, len: usize) -> Result<&'a [u8], FfiError> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(FfiError::NullPointer);
    }
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

fn read_fixed<const N: usize>(ptr: *const c_uchar) -> Result<[u8; N], FfiError> {
    let bytes = read_bytes(ptr, N)?;
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn backend_from_id(id: u8) -> Result<SdkBackend, FfiError> {
    match id {
        x if x == SdkBackend::Clsag as u8 => Ok(SdkBackend::Clsag),
        _ => Err(FfiError::from(ErrorCode::BridgeBackendUnsupported)),
    }
}

fn u256_from_be(bytes: &[u8; 32]) -> U256 {
    U256::from_be_bytes(*bytes)
}

fn u256_to_be(value: &U256) -> [u8; 32] {
    let b: B256 = (*value).into();
    b.into()
}

fn write_u256_be(dst: *mut c_uchar, value: &U256) {
    let be = u256_to_be(value);
    unsafe {
        std::ptr::copy_nonoverlapping(be.as_ptr(), dst, be.len());
    }
}

#[derive(Clone)]
struct CaptureTransport {
    call: Arc<Mutex<Option<EvmCall>>>,
}

impl Default for CaptureTransport {
    fn default() -> Self {
        Self {
            call: Arc::new(Mutex::new(None)),
        }
    }
}

impl CaptureTransport {
    fn take(&self) -> Option<EvmCall> {
        self.call.lock().unwrap().take()
    }
}

impl EvmTransport for CaptureTransport {
    fn send(&self, call: EvmCall) -> SdkResult<B256> {
        *self.call.lock().unwrap() = Some(call);
        Ok(B256::ZERO)
    }
}

#[derive(Clone)]
struct CaptureSignerTransport {
    call: Arc<Mutex<Option<EvmCall>>>,
    signer: PrivateKeySigner,
}

impl CaptureSignerTransport {
    fn new(signer: PrivateKeySigner) -> Self {
        Self {
            call: Arc::new(Mutex::new(None)),
            signer,
        }
    }

    fn take(&self) -> Option<EvmCall> {
        self.call.lock().unwrap().take()
    }
}

impl EvmTransport for CaptureSignerTransport {
    fn send(&self, call: EvmCall) -> SdkResult<B256> {
        *self.call.lock().unwrap() = Some(call);
        Ok(B256::ZERO)
    }
}

impl EvmViewTransport for CaptureSignerTransport {
    fn call_view(&self, call: EvmCall) -> SdkResult<Bytes> {
        *self.call.lock().unwrap() = Some(call);
        Ok(Bytes::new())
    }
}

impl EvmMessageSigner for CaptureSignerTransport {
    fn sign_hash(&self, digest: B256) -> SdkResult<Bytes> {
        let signature = self
            .signer
            .sign_hash_sync(&digest)
            .map_err(|_| ErrorCode::SignatureInvalid)?;
        Ok(Bytes::from(signature.as_bytes().to_vec()))
    }

    fn signer_address(&self) -> AlloyAddress {
        self.signer.address()
    }
}

fn capture_escrow_call<F>(escrow: SdkAddress, f: F) -> Result<EvmCall, FfiError>
where
    F: FnOnce(EscrowClient<CaptureTransport>) -> SdkResult<TxHash>,
{
    let transport = CaptureTransport::default();
    let client = EscrowClient::new(escrow, transport.clone());
    f(client).map_err(FfiError::from)?;
    transport.take().ok_or(FfiError::Decode)
}

fn read_address(ptr: *const c_uchar) -> Result<SdkAddress, FfiError> {
    let bytes = read_fixed::<20>(ptr)?;
    Ok(AlloyAddress::from_slice(&bytes))
}

#[derive(Clone)]
pub struct FfiHostAdapters {
    key: CKeyCallbacks,
    evm: CEvmCallbacks,
    monero: CMoneroCallbacks,
    persistence: CPersistenceCallbacks,
    time: CTimeNetworkCallbacks,
    ux: CUxCallbacks,
    owner_thread: ThreadId,
}

impl FfiHostAdapters {
    fn new(
        key: CKeyCallbacks,
        evm: CEvmCallbacks,
        monero: CMoneroCallbacks,
        persistence: CPersistenceCallbacks,
        time: CTimeNetworkCallbacks,
        ux: CUxCallbacks,
    ) -> Self {
        Self {
            key,
            evm,
            monero,
            persistence,
            time,
            ux,
            owner_thread: thread::current().id(),
        }
    }

    fn ensure_thread(&self, context: &str) -> host_adapter::Result<()> {
        if thread::current().id() != self.owner_thread {
            return Err(HostAdapterError::new(
                KitErrorCode::AdapterCallFailed,
                format!("{context}: callback invoked on non-owner thread"),
            ));
        }
        Ok(())
    }

    fn call_with_unwind<T, F>(&self, context: &str, f: F) -> host_adapter::Result<T>
    where
        F: FnOnce() -> host_adapter::Result<T>,
    {
        self.ensure_thread(context)?;
        match panic::catch_unwind(AssertUnwindSafe(f)) {
            Ok(result) => result,
            Err(_) => Err(HostAdapterError::new(
                KitErrorCode::InternalPanic,
                format!("{context}: callback panicked"),
            )),
        }
    }

    fn require_callback<T>(&self, value: Option<T>, context: &str) -> host_adapter::Result<T> {
        value.ok_or_else(|| {
            HostAdapterError::new(
                KitErrorCode::AdapterCallFailed,
                format!("{context}: callback not configured"),
            )
        })
    }
}

impl KeyIdentityAdapter for FfiHostAdapters {
    fn evm_address(&self) -> host_adapter::Result<[u8; 20]> {
        let cb = self.require_callback(self.key.evm_address, "key.evm_address")?;
        self.call_with_unwind("key.evm_address", || unsafe {
            let mut out = [0u8; 20];
            let rc = cb(self.key.user_data, out.as_mut_ptr());
            if rc == 0 {
                Ok(out)
            } else {
                Err(map_callback_code(rc, "key.evm_address"))
            }
        })
    }

    fn sign_evm_message(&self, digest: [u8; 32]) -> host_adapter::Result<Vec<u8>> {
        let cb = self.require_callback(self.key.sign_evm_message, "key.sign_evm_message")?;
        self.call_with_unwind("key.sign_evm_message", || unsafe {
            let mut out = vec![0u8; 128];
            let mut out_len = 0u32;
            let rc = cb(
                self.key.user_data,
                digest.as_ptr(),
                out.as_mut_ptr(),
                out.len() as c_uint,
                &mut out_len,
            );
            if rc != 0 {
                return Err(map_callback_code(rc, "key.sign_evm_message"));
            }
            let len = out_len as usize;
            if len > out.len() {
                return Err(HostAdapterError::new(
                    KitErrorCode::InvalidLength,
                    "key.sign_evm_message: callback returned invalid length",
                ));
            }
            out.truncate(len);
            Ok(out)
        })
    }

    fn monero_spend_public_key(&self) -> host_adapter::Result<[u8; 32]> {
        let cb = self.require_callback(
            self.key.monero_spend_public_key,
            "key.monero_spend_public_key",
        )?;
        self.call_with_unwind("key.monero_spend_public_key", || unsafe {
            let mut out = [0u8; 32];
            let rc = cb(self.key.user_data, out.as_mut_ptr());
            if rc == 0 {
                Ok(out)
            } else {
                Err(map_callback_code(rc, "key.monero_spend_public_key"))
            }
        })
    }

    fn monero_view_public_key(&self) -> host_adapter::Result<[u8; 32]> {
        let cb = self.require_callback(
            self.key.monero_view_public_key,
            "key.monero_view_public_key",
        )?;
        self.call_with_unwind("key.monero_view_public_key", || unsafe {
            let mut out = [0u8; 32];
            let rc = cb(self.key.user_data, out.as_mut_ptr());
            if rc == 0 {
                Ok(out)
            } else {
                Err(map_callback_code(rc, "key.monero_view_public_key"))
            }
        })
    }

    fn monero_derive_subaddress(&self, major: u32, minor: u32) -> host_adapter::Result<Vec<u8>> {
        let cb = self.require_callback(
            self.key.monero_derive_subaddress,
            "key.monero_derive_subaddress",
        )?;
        self.call_with_unwind("key.monero_derive_subaddress", || unsafe {
            let mut out = vec![0u8; 256];
            let mut out_len = 0u32;
            let rc = cb(
                self.key.user_data,
                major,
                minor,
                out.as_mut_ptr(),
                out.len() as c_uint,
                &mut out_len,
            );
            if rc != 0 {
                return Err(map_callback_code(rc, "key.monero_derive_subaddress"));
            }
            let len = out_len as usize;
            if len > out.len() {
                return Err(HostAdapterError::new(
                    KitErrorCode::InvalidLength,
                    "key.monero_derive_subaddress: callback returned invalid length",
                ));
            }
            out.truncate(len);
            Ok(out)
        })
    }

    fn monero_compute_key_image(
        &self,
        output_pubkey: &[u8; 32],
        output_index: u64,
    ) -> host_adapter::Result<[u8; 32]> {
        let cb = self.require_callback(
            self.key.monero_compute_key_image,
            "key.monero_compute_key_image",
        )?;
        self.call_with_unwind("key.monero_compute_key_image", || unsafe {
            let mut out = [0u8; 32];
            let rc = cb(
                self.key.user_data,
                output_pubkey.as_ptr(),
                output_index,
                out.as_mut_ptr(),
            );
            if rc == 0 {
                Ok(out)
            } else {
                Err(map_callback_code(rc, "key.monero_compute_key_image"))
            }
        })
    }
}

fn encode_host_evm_call(call: &host_adapter::EvmCall) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + call.data.len());
    out.extend_from_slice(&call.to);
    out.extend_from_slice(&call.value_wei.to_le_bytes());
    out.extend_from_slice(&(call.data.len() as u32).to_le_bytes());
    out.extend_from_slice(&call.data);
    out.extend_from_slice(&call.gas_limit.unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&call.max_fee_per_gas.unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&call.max_priority_fee_per_gas.unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&call.nonce.unwrap_or(0).to_le_bytes());
    out
}

impl EvmExecutionAdapter for FfiHostAdapters {
    fn send_raw_tx(&self, signed_tx: &[u8]) -> host_adapter::Result<[u8; 32]> {
        let cb = self.require_callback(self.evm.send_raw_tx, "evm.send_raw_tx")?;
        self.call_with_unwind("evm.send_raw_tx", || unsafe {
            let mut out = [0u8; 32];
            let rc = cb(
                self.evm.user_data,
                signed_tx.as_ptr(),
                signed_tx.len() as c_uint,
                out.as_mut_ptr(),
            );
            if rc == 0 {
                Ok(out)
            } else {
                Err(map_callback_code(rc, "evm.send_raw_tx"))
            }
        })
    }

    fn estimate_gas(&self, call: &host_adapter::EvmCall) -> host_adapter::Result<u64> {
        let cb = self.require_callback(self.evm.estimate_gas, "evm.estimate_gas")?;
        self.call_with_unwind("evm.estimate_gas", || unsafe {
            let payload = encode_host_evm_call(call);
            let mut out = 0u64;
            let rc = cb(
                self.evm.user_data,
                payload.as_ptr(),
                payload.len() as c_uint,
                &mut out,
            );
            if rc == 0 {
                Ok(out)
            } else {
                Err(map_callback_code(rc, "evm.estimate_gas"))
            }
        })
    }

    fn replace_tx(&self, original_hash: [u8; 32], new_gas: u64) -> host_adapter::Result<[u8; 32]> {
        let cb = self.require_callback(self.evm.replace_tx, "evm.replace_tx")?;
        self.call_with_unwind("evm.replace_tx", || unsafe {
            let mut out = [0u8; 32];
            let rc = cb(
                self.evm.user_data,
                original_hash.as_ptr(),
                new_gas,
                out.as_mut_ptr(),
            );
            if rc == 0 {
                Ok(out)
            } else {
                Err(map_callback_code(rc, "evm.replace_tx"))
            }
        })
    }

    fn get_receipt(&self, tx_hash: [u8; 32]) -> host_adapter::Result<Option<TxReceipt>> {
        let cb = match self.evm.get_receipt {
            Some(cb) => cb,
            None => return Ok(None),
        };
        self.call_with_unwind("evm.get_receipt", || unsafe {
            let mut buf = [0u8; 96];
            let mut out_len = 0u32;
            let rc = cb(
                self.evm.user_data,
                tx_hash.as_ptr(),
                buf.as_mut_ptr(),
                buf.len() as c_uint,
                &mut out_len,
            );
            if rc != 0 {
                return Err(map_callback_code(rc, "evm.get_receipt"));
            }
            if out_len == 0 {
                return Ok(None);
            }
            if out_len as usize != 81 {
                return Err(HostAdapterError::new(
                    KitErrorCode::InvalidLength,
                    "evm.get_receipt: expected 81-byte receipt payload",
                ));
            }
            let mut cursor = 0usize;
            let tx_hash = {
                let mut v = [0u8; 32];
                v.copy_from_slice(&buf[cursor..cursor + 32]);
                cursor += 32;
                v
            };
            let block_number = {
                let mut v = [0u8; 8];
                v.copy_from_slice(&buf[cursor..cursor + 8]);
                cursor += 8;
                u64::from_le_bytes(v)
            };
            let block_hash = {
                let mut v = [0u8; 32];
                v.copy_from_slice(&buf[cursor..cursor + 32]);
                cursor += 32;
                v
            };
            let success = buf[cursor] != 0;
            cursor += 1;
            let mut gas_bytes = [0u8; 8];
            gas_bytes.copy_from_slice(&buf[cursor..cursor + 8]);
            let gas_used = u64::from_le_bytes(gas_bytes);
            Ok(Some(TxReceipt {
                tx_hash,
                block_number,
                block_hash,
                success,
                gas_used,
            }))
        })
    }

    fn get_logs(&self, _filter: &LogFilter) -> host_adapter::Result<Vec<LogEntry>> {
        Ok(Vec::new())
    }

    fn chain_id(&self) -> host_adapter::Result<u64> {
        let cb = match self.evm.chain_id {
            Some(cb) => cb,
            None => return Ok(1),
        };
        self.call_with_unwind("evm.chain_id", || unsafe {
            let mut out = 0u64;
            let rc = cb(self.evm.user_data, &mut out);
            if rc == 0 {
                Ok(out)
            } else {
                Err(map_callback_code(rc, "evm.chain_id"))
            }
        })
    }

    fn block_number(&self) -> host_adapter::Result<u64> {
        let cb = match self.evm.block_number {
            Some(cb) => cb,
            None => return Ok(0),
        };
        self.call_with_unwind("evm.block_number", || unsafe {
            let mut out = 0u64;
            let rc = cb(self.evm.user_data, &mut out);
            if rc == 0 {
                Ok(out)
            } else {
                Err(map_callback_code(rc, "evm.block_number"))
            }
        })
    }

    fn gas_price(&self) -> host_adapter::Result<u128> {
        let cb = match self.evm.gas_price {
            Some(cb) => cb,
            None => return Ok(0),
        };
        self.call_with_unwind("evm.gas_price", || unsafe {
            let mut be = [0u8; 16];
            let rc = cb(self.evm.user_data, be.as_mut_ptr());
            if rc == 0 {
                Ok(u128::from_be_bytes(be))
            } else {
                Err(map_callback_code(rc, "evm.gas_price"))
            }
        })
    }
}

impl MoneroExecutionAdapter for FfiHostAdapters {
    fn broadcast_tx(&self, tx_blob: &[u8]) -> host_adapter::Result<[u8; 32]> {
        let cb = self.require_callback(self.monero.broadcast_tx, "monero.broadcast_tx")?;
        self.call_with_unwind("monero.broadcast_tx", || unsafe {
            let mut out = [0u8; 32];
            let rc = cb(
                self.monero.user_data,
                tx_blob.as_ptr(),
                tx_blob.len() as c_uint,
                out.as_mut_ptr(),
            );
            if rc == 0 {
                Ok(out)
            } else {
                Err(map_callback_code(rc, "monero.broadcast_tx"))
            }
        })
    }

    fn is_key_image_spent(&self, key_images: &[[u8; 32]]) -> host_adapter::Result<Vec<SpendState>> {
        let cb = match self.monero.is_key_image_spent {
            Some(cb) => cb,
            None => return Ok(vec![SpendState::Unspent; key_images.len()]),
        };
        self.call_with_unwind("monero.is_key_image_spent", || unsafe {
            let mut flattened = Vec::with_capacity(key_images.len() * 32);
            for key in key_images {
                flattened.extend_from_slice(key);
            }
            let mut out_states = vec![0u8; key_images.len()];
            let mut out_len = 0u32;
            let rc = cb(
                self.monero.user_data,
                flattened.as_ptr(),
                key_images.len() as c_uint,
                out_states.as_mut_ptr(),
                out_states.len() as c_uint,
                &mut out_len,
            );
            if rc != 0 {
                return Err(map_callback_code(rc, "monero.is_key_image_spent"));
            }
            if out_len as usize > out_states.len() {
                return Err(HostAdapterError::new(
                    KitErrorCode::InvalidLength,
                    "monero.is_key_image_spent: callback returned invalid length",
                ));
            }
            out_states.truncate(out_len as usize);
            let states = out_states
                .into_iter()
                .map(|value| match value {
                    1 => SpendState::InPool,
                    2 => SpendState::Spent,
                    _ => SpendState::Unspent,
                })
                .collect();
            Ok(states)
        })
    }

    fn get_tx_confirmations(&self, tx_hash: &[u8; 32]) -> host_adapter::Result<Option<u64>> {
        let cb = match self.monero.get_tx_confirmations {
            Some(cb) => cb,
            None => return Ok(None),
        };
        self.call_with_unwind("monero.get_tx_confirmations", || unsafe {
            let mut has = 0u8;
            let mut confirmations = 0u64;
            let rc = cb(
                self.monero.user_data,
                tx_hash.as_ptr(),
                &mut has,
                &mut confirmations,
            );
            if rc != 0 {
                return Err(map_callback_code(rc, "monero.get_tx_confirmations"));
            }
            if has == 0 {
                Ok(None)
            } else {
                Ok(Some(confirmations))
            }
        })
    }

    fn node_health(&self) -> host_adapter::Result<NodeHealth> {
        let cb = match self.monero.node_health {
            Some(cb) => cb,
            None => return Ok(NodeHealth::Healthy { height: 0 }),
        };
        self.call_with_unwind("monero.node_health", || unsafe {
            let mut buf = [0u8; 128];
            let mut out_len = 0u32;
            let rc = cb(
                self.monero.user_data,
                buf.as_mut_ptr(),
                buf.len() as c_uint,
                &mut out_len,
            );
            if rc != 0 {
                return Err(map_callback_code(rc, "monero.node_health"));
            }
            if out_len == 0 {
                return Ok(NodeHealth::Healthy { height: 0 });
            }
            match buf[0] {
                0 => {
                    if (out_len as usize) < 9 {
                        return Err(HostAdapterError::new(
                            KitErrorCode::InvalidLength,
                            "monero.node_health: invalid healthy payload length",
                        ));
                    }
                    let mut h = [0u8; 8];
                    h.copy_from_slice(&buf[1..9]);
                    Ok(NodeHealth::Healthy {
                        height: u64::from_le_bytes(h),
                    })
                }
                1 => Ok(NodeHealth::Degraded {
                    reason: "degraded".to_owned(),
                }),
                _ => Ok(NodeHealth::Unreachable {
                    reason: "unreachable".to_owned(),
                }),
            }
        })
    }
}

impl PersistenceAdapter for FfiHostAdapters {
    fn save_checkpoint(&self, reservation_id: &[u8; 32], state: &[u8]) -> host_adapter::Result<()> {
        let cb = self.require_callback(
            self.persistence.save_checkpoint,
            "persistence.save_checkpoint",
        )?;
        self.call_with_unwind("persistence.save_checkpoint", || unsafe {
            let rc = cb(
                self.persistence.user_data,
                reservation_id.as_ptr(),
                state.as_ptr(),
                state.len() as c_uint,
            );
            if rc == 0 {
                Ok(())
            } else {
                Err(map_callback_code(rc, "persistence.save_checkpoint"))
            }
        })
    }

    fn load_checkpoint(&self, reservation_id: &[u8; 32]) -> host_adapter::Result<Option<Vec<u8>>> {
        let cb = match self.persistence.load_checkpoint {
            Some(cb) => cb,
            None => return Ok(None),
        };
        self.call_with_unwind("persistence.load_checkpoint", || unsafe {
            let mut out = vec![0u8; 512 * 1024];
            let mut out_len = 0u32;
            let rc = cb(
                self.persistence.user_data,
                reservation_id.as_ptr(),
                out.as_mut_ptr(),
                out.len() as c_uint,
                &mut out_len,
            );
            if rc != 0 {
                return Err(map_callback_code(rc, "persistence.load_checkpoint"));
            }
            if out_len == 0 {
                return Ok(None);
            }
            let len = out_len as usize;
            if len > out.len() {
                return Err(HostAdapterError::new(
                    KitErrorCode::InvalidLength,
                    "persistence.load_checkpoint: callback returned invalid length",
                ));
            }
            out.truncate(len);
            Ok(Some(out))
        })
    }

    fn list_active_swaps(&self) -> host_adapter::Result<Vec<[u8; 32]>> {
        let cb = match self.persistence.list_active_swaps {
            Some(cb) => cb,
            None => return Ok(Vec::new()),
        };
        self.call_with_unwind("persistence.list_active_swaps", || unsafe {
            let mut out = vec![0u8; 32 * 1024];
            let mut out_len = 0u32;
            let rc = cb(
                self.persistence.user_data,
                out.as_mut_ptr(),
                out.len() as c_uint,
                &mut out_len,
            );
            if rc != 0 {
                return Err(map_callback_code(rc, "persistence.list_active_swaps"));
            }
            let len = out_len as usize;
            if len % 32 != 0 || len > out.len() {
                return Err(HostAdapterError::new(
                    KitErrorCode::InvalidLength,
                    "persistence.list_active_swaps: invalid payload length",
                ));
            }
            out.truncate(len);
            let ids = out
                .chunks_exact(32)
                .map(|chunk| {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(chunk);
                    id
                })
                .collect();
            Ok(ids)
        })
    }

    fn delete_swap(&self, reservation_id: &[u8; 32]) -> host_adapter::Result<()> {
        let cb = self.require_callback(self.persistence.delete_swap, "persistence.delete_swap")?;
        self.call_with_unwind("persistence.delete_swap", || unsafe {
            let rc = cb(self.persistence.user_data, reservation_id.as_ptr());
            if rc == 0 {
                Ok(())
            } else {
                Err(map_callback_code(rc, "persistence.delete_swap"))
            }
        })
    }
}

impl TimeNetworkAdapter for FfiHostAdapters {
    fn current_block_number(&self) -> host_adapter::Result<u64> {
        let cb = match self.time.current_block_number {
            Some(cb) => cb,
            None => return Ok(0),
        };
        self.call_with_unwind("time.current_block_number", || unsafe {
            let mut out = 0u64;
            let rc = cb(self.time.user_data, &mut out);
            if rc == 0 {
                Ok(out)
            } else {
                Err(map_callback_code(rc, "time.current_block_number"))
            }
        })
    }

    fn current_timestamp(&self) -> host_adapter::Result<u64> {
        let cb = match self.time.current_timestamp {
            Some(cb) => cb,
            None => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|err| {
                        HostAdapterError::new(
                            KitErrorCode::AdapterCallFailed,
                            format!("time.current_timestamp: {err}"),
                        )
                    })?;
                return Ok(now.as_secs());
            }
        };
        self.call_with_unwind("time.current_timestamp", || unsafe {
            let mut out = 0u64;
            let rc = cb(self.time.user_data, &mut out);
            if rc == 0 {
                Ok(out)
            } else {
                Err(map_callback_code(rc, "time.current_timestamp"))
            }
        })
    }

    fn is_evm_reachable(&self) -> host_adapter::Result<bool> {
        let cb = match self.time.is_evm_reachable {
            Some(cb) => cb,
            None => return Ok(true),
        };
        self.call_with_unwind("time.is_evm_reachable", || unsafe {
            let mut out = 0u8;
            let rc = cb(self.time.user_data, &mut out);
            if rc == 0 {
                Ok(out != 0)
            } else {
                Err(map_callback_code(rc, "time.is_evm_reachable"))
            }
        })
    }

    fn is_monero_reachable(&self) -> host_adapter::Result<bool> {
        let cb = match self.time.is_monero_reachable {
            Some(cb) => cb,
            None => return Ok(true),
        };
        self.call_with_unwind("time.is_monero_reachable", || unsafe {
            let mut out = 0u8;
            let rc = cb(self.time.user_data, &mut out);
            if rc == 0 {
                Ok(out != 0)
            } else {
                Err(map_callback_code(rc, "time.is_monero_reachable"))
            }
        })
    }
}

impl UxEventAdapter for FfiHostAdapters {
    fn on_event(&self, event: SwapLifecycleEvent) {
        let cb = match self.ux.on_event {
            Some(cb) => cb,
            None => return,
        };
        let payload = match encode_lifecycle_event(&event) {
            Ok(payload) => payload,
            Err(_) => return,
        };
        let _ = self.call_with_unwind("ux.on_event", || unsafe {
            let rc = cb(self.ux.user_data, payload.as_ptr(), payload.len() as c_uint);
            if rc == 0 {
                Ok(())
            } else {
                Err(map_callback_code(rc, "ux.on_event"))
            }
        });
    }
}

pub struct FfiOrchestratorHandle {
    orchestrator: SwapOrchestrator<FfiHostAdapters>,
    owner_thread: ThreadId,
}

fn read_orchestrator_handle<'a>(
    handle: *mut FfiOrchestratorHandle,
) -> Result<&'a mut FfiOrchestratorHandle, FfiError> {
    if handle.is_null() {
        return Err(FfiError::NullPointer);
    }
    let handle = unsafe { &mut *handle };
    if thread::current().id() != handle.owner_thread {
        return Err(FfiError::from(KitErrorCode::AdapterCallFailed));
    }
    Ok(handle)
}

fn write_call_outputs(
    call: &EvmCall,
    out_data_ptr: *mut c_uchar,
    out_data_capacity: c_uint,
    out_data_len: *mut c_uint,
    out_value_ptr: *mut c_uchar,
    out_gas_limit: *mut u64,
) -> Result<(), FfiError> {
    if out_data_ptr.is_null()
        || out_data_len.is_null()
        || out_value_ptr.is_null()
        || out_gas_limit.is_null()
    {
        return Err(FfiError::NullPointer);
    }
    let data = call.data.as_ref();
    if data.len() > out_data_capacity as usize {
        return Err(FfiError::CapacityInsufficient);
    }
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), out_data_ptr, data.len());
    }
    unsafe {
        *out_data_len = data.len() as c_uint;
    }
    write_u256_be(out_value_ptr, &call.value);
    unsafe {
        *out_gas_limit = call.gas_limit.unwrap_or(0);
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn eswp_wire_version() -> c_uint {
    ABI_WIRE_VERSION as c_uint
}
#[no_mangle]
pub extern "C" fn eswp_backend_clsag_id() -> c_uchar {
    BACKEND_ID_CLSAG
}

#[no_mangle]
/// # Safety
/// `out_spend32` and `out_view32` must be valid, caller-owned pointers to 32-byte buffers.
pub unsafe extern "C" fn eswp_generate_monero_keypair(
    out_spend32: *mut c_uchar,
    out_view32: *mut c_uchar,
) -> c_int {
    if out_spend32.is_null() || out_view32.is_null() {
        return FfiError::NullPointer.code();
    }
    match sdk_generate_monero_keypair() {
        Ok((spend, view)) => {
            std::ptr::copy_nonoverlapping(spend.as_ptr(), out_spend32, spend.len());
            std::ptr::copy_nonoverlapping(view.as_ptr(), out_view32, view.len());
            0
        }
        Err(err) => FfiError::from(err).code(),
    }
}

#[no_mangle]
/// # Safety
/// All pointer arguments must reference caller-owned memory. `out_address_len` must be writable
/// and `out_address_capacity` specifies the bytes available at `out_address_ptr`. The derived
/// address is copied as ASCII bytes without a trailing NUL terminator.
pub unsafe extern "C" fn eswp_monero_derive_subaddress(
    view_ptr: *const c_uchar,
    spend_ptr: *const c_uchar,
    index: c_uint,
    out_address_ptr: *mut c_uchar,
    out_address_capacity: c_uint,
    out_address_len: *mut c_uint,
    out_derived_spend32: *mut c_uchar,
) -> c_int {
    if view_ptr.is_null()
        || spend_ptr.is_null()
        || out_address_ptr.is_null()
        || out_address_len.is_null()
        || out_derived_spend32.is_null()
    {
        return FfiError::NullPointer.code();
    }

    let view = match read_fixed::<32>(view_ptr) {
        Ok(bytes) => bytes,
        Err(err) => return err.code(),
    };
    let spend = match read_fixed::<32>(spend_ptr) {
        Ok(bytes) => bytes,
        Err(err) => return err.code(),
    };

    let (address, derived) = match sdk_derive_subaddress(&view, &spend, index) {
        Ok(result) => result,
        Err(err) => return FfiError::from(err).code(),
    };
    let address_bytes = address.as_bytes();
    let capacity = out_address_capacity as usize;
    if capacity < address_bytes.len() {
        return FfiError::CapacityInsufficient.code();
    }

    std::ptr::copy_nonoverlapping(address_bytes.as_ptr(), out_address_ptr, address_bytes.len());
    *out_address_len = address_bytes.len() as c_uint;
    std::ptr::copy_nonoverlapping(derived.as_ptr(), out_derived_spend32, derived.len());

    0
}

#[no_mangle]
/// # Safety
/// Input pointers must reference 32-byte buffers and `out_key_image32` must be writable.
pub unsafe extern "C" fn eswp_monero_compute_key_image(
    tx_pub_ptr: *const c_uchar,
    spend_ptr: *const c_uchar,
    out_key_image32: *mut c_uchar,
) -> c_int {
    if tx_pub_ptr.is_null() || spend_ptr.is_null() || out_key_image32.is_null() {
        return FfiError::NullPointer.code();
    }
    let tx_pub = match read_fixed::<32>(tx_pub_ptr) {
        Ok(bytes) => bytes,
        Err(err) => return err.code(),
    };
    let spend = match read_fixed::<32>(spend_ptr) {
        Ok(bytes) => bytes,
        Err(err) => return err.code(),
    };
    match sdk_compute_key_image(&tx_pub, &spend) {
        Ok(img) => {
            std::ptr::copy_nonoverlapping(img.as_ptr(), out_key_image32, img.len());
            0
        }
        Err(err) => FfiError::from(err).code(),
    }
}

#[no_mangle]
/// # Safety
/// `out_priv32` and `out_addr20` must be writable buffers owned by the caller.
pub unsafe extern "C" fn eswp_generate_evm_keypair(
    out_priv32: *mut c_uchar,
    out_addr20: *mut c_uchar,
) -> c_int {
    if out_priv32.is_null() || out_addr20.is_null() {
        return FfiError::NullPointer.code();
    }
    match sdk_generate_evm_keypair() {
        Ok((priv_key, address)) => {
            std::ptr::copy_nonoverlapping(priv_key.as_ptr(), out_priv32, priv_key.len());
            let addr_bytes: [u8; 20] = address.into();
            std::ptr::copy_nonoverlapping(addr_bytes.as_ptr(), out_addr20, addr_bytes.len());
            0
        }
        Err(err) => FfiError::from(err).code(),
    }
}

#[no_mangle]
/// # Safety
/// `priv_ptr` and `msg_ptr` must reference 32-byte inputs and `out_sig65` must have room for 65 bytes.
pub unsafe extern "C" fn eswp_sign_evm_message(
    priv_ptr: *const c_uchar,
    msg_ptr: *const c_uchar,
    out_sig65: *mut c_uchar,
) -> c_int {
    if priv_ptr.is_null() || msg_ptr.is_null() || out_sig65.is_null() {
        return FfiError::NullPointer.code();
    }
    let priv_key = match read_fixed::<32>(priv_ptr) {
        Ok(bytes) => bytes,
        Err(err) => return err.code(),
    };
    let message = match read_fixed::<32>(msg_ptr) {
        Ok(bytes) => bytes,
        Err(err) => return err.code(),
    };
    match sdk_sign_evm_message(&priv_key, &message) {
        Ok(sig) => {
            std::ptr::copy_nonoverlapping(sig.as_ptr(), out_sig65, sig.len());
            0
        }
        Err(err) => FfiError::from(err).code(),
    }
}

#[no_mangle]
/// # Safety
/// `msg_ptr`, `ring_ptr`, `swap_id_ptr`, and `ctx_ptr` must reference readable buffers of
/// the stated lengths. `out_bytes` must point to a buffer large enough to receive the
/// pre-signature bytes, and `out_len` must be writable.
pub unsafe extern "C" fn eswp_clsag_make_pre_sig(
    msg_ptr: *const c_uchar,
    msg_len: c_uint,
    ring_ptr: *const c_uchar,
    ring_len: c_uint,
    i_star: c_uint,
    swap_id_ptr: *const c_uchar,
    ctx_ptr: *const c_uchar,
    ctx_len: c_uint,
    out_bytes: *mut c_uchar,
    out_len: *mut c_uint,
) -> c_int {
    if msg_ptr.is_null()
        || ring_ptr.is_null()
        || swap_id_ptr.is_null()
        || ctx_ptr.is_null()
        || out_bytes.is_null()
        || out_len.is_null()
    {
        return FfiError::NullPointer.code();
    }
    let msg = slice::from_raw_parts(msg_ptr, msg_len as usize);
    let ring_bytes = slice::from_raw_parts(ring_ptr, ring_len as usize);
    let (ring_keys, ring_commitments) = match parse_ring_bytes(ring_bytes) {
        Ok(result) => result,
        Err(err) => return err.code(),
    };
    let ring_size = ring_keys.len();
    if ring_size < 5 {
        return FfiError::from(EswpError::RingInvalid).code();
    }

    let i_star = i_star as usize;
    if i_star >= ring_size {
        return FfiError::RingIndexOutOfRange.code();
    }

    let swap_id = slice::from_raw_parts(swap_id_ptr, 32);
    let mut swap_id_bytes = [0u8; 32];
    swap_id_bytes.copy_from_slice(swap_id);

    let ctx_bytes = slice::from_raw_parts(ctx_ptr, ctx_len as usize);
    let sctx = match decode_clsag_settlement_ctx(ctx_bytes) {
        Ok(ctx) => ctx,
        Err(err) => return err.code(),
    };

    let witness = derive_witness(i_star);
    let key_image = witness.key_image_bytes();
    let clsag_ctx = ClsagCtx {
        ring_keys,
        ring_commitments,
        key_image,
        n: ring_size,
    };

    let (pre, tau) = match adaptor_make_pre_sig(&clsag_ctx, &witness, msg, &swap_id_bytes, sctx) {
        Ok(value) => value,
        Err(err) => return FfiError::from(err).code(),
    };

    let encoded = match encode_pre_bytes(msg, &clsag_ctx, &pre, &swap_id_bytes, &tau) {
        Ok(bytes) => bytes,
        Err(err) => return err.code(),
    };

    unsafe {
        *out_len = encoded.len() as c_uint;
        std::ptr::copy_nonoverlapping(encoded.as_ptr(), out_bytes, encoded.len());
    }

    0
}

#[no_mangle]
/// # Safety
/// All pointer arguments must be non-null, with `pre_ptr` and `secret_ptr`
/// referencing readable buffers of the stated lengths, and `out_ptr`/`out_len`
/// writable for the produced signature bytes and length.
pub unsafe extern "C" fn eswp_clsag_complete(
    pre_ptr: *const c_uchar,
    pre_len: c_uint,
    secret_ptr: *const c_uchar,
    secret_len: c_uint,
    out_ptr: *mut c_uchar,
    out_len: *mut c_uint,
) -> c_int {
    if pre_ptr.is_null() || secret_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
        return FfiError::NullPointer.code();
    }

    let pre_bytes = slice::from_raw_parts(pre_ptr, pre_len as usize);
    let secrets = slice::from_raw_parts(secret_ptr, secret_len as usize);
    if secrets.len() != ADAPTOR_SCALAR_LEN {
        return FfiError::SecretsInvalid.code();
    }

    let decoded_pre = match decode_pre_bytes(pre_bytes) {
        Ok(decoded) => decoded,
        Err(err) => return err.code(),
    };

    let mut tau = [0u8; 32];
    tau.copy_from_slice(secrets);

    let final_sig = adaptor_complete(&decoded_pre.pre, &tau);
    let encoded = match encode_final_bytes(&decoded_pre.pre, &final_sig) {
        Ok(bytes) => bytes,
        Err(err) => return err.code(),
    };

    unsafe {
        *out_len = encoded.len() as c_uint;
        std::ptr::copy_nonoverlapping(encoded.as_ptr(), out_ptr, encoded.len());
    }

    0
}

#[no_mangle]
/// # Safety
/// `out_ok` must be a valid, writable pointer.
pub unsafe extern "C" fn eswp_clsag_verify(
    pre_ptr: *const c_uchar,
    pre_len: c_uint,
    final_ptr: *const c_uchar,
    final_len: c_uint,
    out_ok: *mut bool,
) -> c_int {
    if pre_ptr.is_null() || final_ptr.is_null() || out_ok.is_null() {
        return FfiError::NullPointer.code();
    }

    let pre_bytes = slice::from_raw_parts(pre_ptr, pre_len as usize);
    let final_bytes = slice::from_raw_parts(final_ptr, final_len as usize);

    let decoded_pre = match decode_pre_bytes(pre_bytes) {
        Ok(decoded) => decoded,
        Err(err) => {
            unsafe {
                *out_ok = false;
            }
            return err.code();
        }
    };
    let decoys = decoded_pre.pre.s_tilde.len();
    let decoded_final = match decode_final_bytes(final_bytes, decoys) {
        Ok(decoded) => decoded,
        Err(err) => {
            unsafe {
                *out_ok = false;
            }
            return err.code();
        }
    };

    if decoded_final.resp_index != decoded_pre.pre.j {
        unsafe {
            *out_ok = false;
        }
        return FfiError::from(EswpError::RespIndexUnadmitted).code();
    }
    if decoded_final.pre_hash != decoded_pre.pre.pre_hash {
        unsafe {
            *out_ok = false;
        }
        return FfiError::from(EswpError::PreHashMismatch).code();
    }
    if !ctx_equal(&decoded_pre.pre.ctx, &decoded_final.ctx) {
        unsafe {
            *out_ok = false;
        }
        return FfiError::from(EswpError::CtxMismatch).code();
    }

    let ok = adaptor_verify(&decoded_pre.ctx, &decoded_pre.msg, &decoded_final.final_sig);
    unsafe {
        *out_ok = ok;
    }
    if ok {
        0
    } else {
        EswpError::FinalSigInvalid as c_int
    }
}

#[no_mangle]
/// # Safety
/// `pre_ptr` must reference `pre_len` readable bytes and `out_scalar32` must
/// point to a writable buffer large enough to receive 32 bytes.
pub unsafe extern "C" fn eswp_clsag_extract_t(
    pre_ptr: *const c_uchar,
    pre_len: c_uint,
    final_ptr: *const c_uchar,
    final_len: c_uint,
    out_scalar32: *mut c_uchar,
) -> c_int {
    if pre_ptr.is_null() || final_ptr.is_null() || out_scalar32.is_null() {
        return FfiError::NullPointer.code();
    }

    let pre_bytes = slice::from_raw_parts(pre_ptr, pre_len as usize);
    let final_bytes = slice::from_raw_parts(final_ptr, final_len as usize);

    let decoded_pre = match decode_pre_bytes(pre_bytes) {
        Ok(decoded) => decoded,
        Err(err) => return err.code(),
    };
    let decoys = decoded_pre.pre.s_tilde.len();
    let decoded_final = match decode_final_bytes(final_bytes, decoys) {
        Ok(decoded) => decoded,
        Err(err) => return err.code(),
    };

    if decoded_final.resp_index != decoded_pre.pre.j {
        return FfiError::from(EswpError::RespIndexUnadmitted).code();
    }
    if decoded_final.pre_hash != decoded_pre.pre.pre_hash {
        return FfiError::from(EswpError::PreHashMismatch).code();
    }
    if !ctx_equal(&decoded_pre.pre.ctx, &decoded_final.ctx) {
        return FfiError::from(EswpError::CtxMismatch).code();
    }

    let t = adaptor_extract_t(&decoded_pre.pre, &decoded_final.final_sig);
    unsafe {
        std::ptr::copy_nonoverlapping(t.as_ptr(), out_scalar32, t.len());
    }
    0
}

#[no_mangle]
/// # Safety
/// The caller owns all buffers. `out_tx_ptr` must have space for `out_tx_capacity` bytes and
/// `out_tx_len` / `out_lock_time` must be writable.
pub unsafe extern "C" fn eswp_prepare_refund(
    ctx_ptr: *const c_uchar,
    ctx_len: c_uint,
    swap_id_ptr: *const c_uchar,
    xmr_lock_height: u64,
    eth_expiry: u64,
    delta: u64,
    template_ptr: *const c_uchar,
    template_len: c_uint,
    out_tx_ptr: *mut c_uchar,
    out_tx_capacity: c_uint,
    out_tx_len: *mut c_uint,
    out_lock_time: *mut u64,
) -> c_int {
    if ctx_ptr.is_null()
        || swap_id_ptr.is_null()
        || out_tx_ptr.is_null()
        || out_tx_len.is_null()
        || out_lock_time.is_null()
    {
        return FfiError::NullPointer.code();
    }
    let ctx_bytes = match read_bytes(ctx_ptr, ctx_len as usize) {
        Ok(bytes) => bytes,
        Err(err) => return err.code(),
    };
    let ctx = match decode_sdk_settlement_ctx(ctx_bytes) {
        Ok(ctx) => ctx,
        Err(err) => return err.code(),
    };
    let swap_id = match read_fixed::<32>(swap_id_ptr) {
        Ok(bytes) => bytes,
        Err(err) => return err.code(),
    };
    let template = match read_bytes(template_ptr, template_len as usize) {
        Ok(bytes) => bytes.to_vec(),
        Err(err) => return err.code(),
    };

    let params = RefundParams {
        swap_id,
        xmr_lock_height,
        eth_expiry,
        delta,
        template,
    };
    let refund = match sdk_prepare_refund(&ctx, params) {
        Ok(data) => data,
        Err(err) => return FfiError::from(err).code(),
    };

    let capacity = out_tx_capacity as usize;
    if capacity < refund.tx_bytes.len() {
        return FfiError::CapacityInsufficient.code();
    }
    std::ptr::copy_nonoverlapping(refund.tx_bytes.as_ptr(), out_tx_ptr, refund.tx_bytes.len());
    *out_tx_len = refund.tx_bytes.len() as c_uint;
    *out_lock_time = refund.lock_time;
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use proptest::prelude::*;
    use serde::Deserialize;
    use std::{
        collections::HashMap,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    #[derive(Deserialize)]
    struct RoundTripVector {
        message_hex: String,
        swap_id_hex: String,
        settlement: SettlementVector,
        clsag_ctx: ClsagCtxVector,
        witness: WitnessVector,
    }

    #[derive(Deserialize)]
    struct SettlementVector {
        chain_tag: String,
        position_key_hex: String,
        settle_digest_hex: String,
    }

    #[derive(Deserialize)]
    struct ClsagCtxVector {
        ring_keys_hex: Vec<String>,
        ring_commitments_hex: Vec<String>,
        key_image_hex: String,
        n: usize,
    }

    #[derive(Deserialize)]
    struct WitnessVector {
        x_hex: String,
        mask_hex: String,
        amount: u64,
        i_star: usize,
    }

    fn load_roundtrip_vector() -> RoundTripVector {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/clsag/roundtrip.json");
        let json = std::fs::read_to_string(path).expect("roundtrip vector readable");
        serde_json::from_str(&json).expect("roundtrip vector parse")
    }

    fn hex_to_vec(hex_str: &str) -> Vec<u8> {
        hex::decode(hex_str).expect("hex decode")
    }

    fn hex_to_array<const N: usize>(hex_str: &str) -> [u8; N] {
        let bytes = hex_to_vec(hex_str);
        assert_eq!(bytes.len(), N, "expected {N} bytes");
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        arr
    }

    fn sample_fixture() -> (ClsagCtx, SettlementCtx, SignerWitness, Vec<u8>, [u8; 32]) {
        let vector = load_roundtrip_vector();
        let settlement = SettlementCtx {
            chain_tag: vector.settlement.chain_tag,
            position_key: hex_to_array(&vector.settlement.position_key_hex),
            settle_digest: hex_to_array(&vector.settlement.settle_digest_hex),
        };
        let ctx = ClsagCtx {
            ring_keys: vector
                .clsag_ctx
                .ring_keys_hex
                .iter()
                .map(|h| hex_to_array::<32>(h))
                .collect(),
            ring_commitments: vector
                .clsag_ctx
                .ring_commitments_hex
                .iter()
                .map(|h| hex_to_array::<32>(h))
                .collect(),
            key_image: hex_to_array::<32>(&vector.clsag_ctx.key_image_hex),
            n: vector.clsag_ctx.n,
        };
        let witness = SignerWitness {
            x: hex_to_array::<32>(&vector.witness.x_hex),
            mask: hex_to_array::<32>(&vector.witness.mask_hex),
            amount: vector.witness.amount,
            i_star: vector.witness.i_star,
        };
        let message = hex_to_vec(&vector.message_hex);
        let swap_id = hex_to_array::<32>(&vector.swap_id_hex);
        (ctx, settlement, witness, message, swap_id)
    }

    #[test]
    fn complete_and_extract_roundtrip_matches_core_logic() {
        let (ctx, settlement, witness, message, swap_id) = sample_fixture();
        let (pre, tau) =
            adaptor_make_pre_sig(&ctx, &witness, &message, &swap_id, settlement.clone()).unwrap();
        let final_sig = adaptor_complete(&pre, &tau);
        let pre_bytes = encode_pre_bytes(&message, &ctx, &pre, &swap_id, &tau).unwrap();
        let expected_final = encode_final_bytes(&pre, &final_sig).unwrap();

        let mut out_buf = vec![0u8; expected_final.len() + 16];
        let mut out_len: c_uint = 0;
        let rc = unsafe {
            eswp_clsag_complete(
                pre_bytes.as_ptr(),
                pre_bytes.len() as c_uint,
                tau.as_ptr(),
                tau.len() as c_uint,
                out_buf.as_mut_ptr(),
                &mut out_len,
            )
        };
        assert_eq!(rc, 0, "eswp_clsag_complete should succeed");
        let produced = &out_buf[..out_len as usize];
        assert_eq!(produced, expected_final.as_slice());

        let mut recovered = [0u8; 32];
        let rc = unsafe {
            eswp_clsag_extract_t(
                pre_bytes.as_ptr(),
                pre_bytes.len() as c_uint,
                expected_final.as_ptr(),
                expected_final.len() as c_uint,
                recovered.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0, "eswp_clsag_extract_t should succeed");
        assert_eq!(recovered, tau);
    }

    #[derive(Default)]
    struct CallbackState {
        checkpoints: Mutex<HashMap<[u8; 32], Vec<u8>>>,
        events: AtomicU64,
    }

    unsafe extern "C" fn cb_send_raw_tx(
        _user_data: *mut c_void,
        _tx_ptr: *const c_uchar,
        _tx_len: c_uint,
        out_hash32: *mut c_uchar,
    ) -> c_int {
        if out_hash32.is_null() {
            return KitErrorCode::NullPointer.code();
        }
        let mut hash = [0u8; 32];
        hash[0] = 0xAB;
        ptr::copy_nonoverlapping(hash.as_ptr(), out_hash32, 32);
        0
    }

    unsafe extern "C" fn cb_broadcast_tx(
        _user_data: *mut c_void,
        _tx_ptr: *const c_uchar,
        _tx_len: c_uint,
        out_hash32: *mut c_uchar,
    ) -> c_int {
        if out_hash32.is_null() {
            return KitErrorCode::NullPointer.code();
        }
        let mut hash = [0u8; 32];
        hash[0] = 0xCD;
        ptr::copy_nonoverlapping(hash.as_ptr(), out_hash32, 32);
        0
    }

    unsafe extern "C" fn cb_block_number(_user_data: *mut c_void, out_block: *mut u64) -> c_int {
        if out_block.is_null() {
            return KitErrorCode::NullPointer.code();
        }
        *out_block = 123;
        0
    }

    unsafe extern "C" fn cb_current_timestamp(_user_data: *mut c_void, out_ts: *mut u64) -> c_int {
        if out_ts.is_null() {
            return KitErrorCode::NullPointer.code();
        }
        *out_ts = 1_700_000_001;
        0
    }

    unsafe extern "C" fn cb_save_checkpoint(
        user_data: *mut c_void,
        reservation_id32: *const c_uchar,
        state_ptr: *const c_uchar,
        state_len: c_uint,
    ) -> c_int {
        if user_data.is_null() || reservation_id32.is_null() || state_ptr.is_null() {
            return KitErrorCode::NullPointer.code();
        }
        let state = &*(user_data as *const CallbackState);
        let mut reservation = [0u8; 32];
        reservation.copy_from_slice(slice::from_raw_parts(reservation_id32, 32));
        let payload = slice::from_raw_parts(state_ptr, state_len as usize).to_vec();
        state
            .checkpoints
            .lock()
            .expect("test checkpoint mutex")
            .insert(reservation, payload);
        0
    }

    unsafe extern "C" fn cb_load_checkpoint(
        user_data: *mut c_void,
        reservation_id32: *const c_uchar,
        out_ptr: *mut c_uchar,
        out_capacity: c_uint,
        out_len: *mut c_uint,
    ) -> c_int {
        if user_data.is_null() || reservation_id32.is_null() || out_len.is_null() {
            return KitErrorCode::NullPointer.code();
        }
        let state = &*(user_data as *const CallbackState);
        let mut reservation = [0u8; 32];
        reservation.copy_from_slice(slice::from_raw_parts(reservation_id32, 32));
        let guard = state.checkpoints.lock().expect("test checkpoint mutex");
        let bytes = match guard.get(&reservation) {
            Some(bytes) => bytes,
            None => {
                *out_len = 0;
                return 0;
            }
        };
        if out_ptr.is_null() || (out_capacity as usize) < bytes.len() {
            return KitErrorCode::BufferTooSmall.code();
        }
        ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr, bytes.len());
        *out_len = bytes.len() as c_uint;
        0
    }

    unsafe extern "C" fn cb_delete_swap(
        user_data: *mut c_void,
        reservation_id32: *const c_uchar,
    ) -> c_int {
        if user_data.is_null() || reservation_id32.is_null() {
            return KitErrorCode::NullPointer.code();
        }
        let state = &*(user_data as *const CallbackState);
        let mut reservation = [0u8; 32];
        reservation.copy_from_slice(slice::from_raw_parts(reservation_id32, 32));
        state
            .checkpoints
            .lock()
            .expect("test checkpoint mutex")
            .remove(&reservation);
        0
    }

    unsafe extern "C" fn cb_list_active_swaps(
        user_data: *mut c_void,
        out_ids_ptr: *mut c_uchar,
        out_ids_capacity: c_uint,
        out_ids_len: *mut c_uint,
    ) -> c_int {
        if user_data.is_null() || out_ids_len.is_null() {
            return KitErrorCode::NullPointer.code();
        }
        let state = &*(user_data as *const CallbackState);
        let guard = state.checkpoints.lock().expect("test checkpoint mutex");
        let total = guard.len() * 32;
        if out_ids_ptr.is_null() && total > 0 {
            return KitErrorCode::NullPointer.code();
        }
        if total > out_ids_capacity as usize {
            return KitErrorCode::BufferTooSmall.code();
        }
        let mut cursor = 0usize;
        for id in guard.keys() {
            ptr::copy_nonoverlapping(id.as_ptr(), out_ids_ptr.add(cursor), 32);
            cursor += 32;
        }
        *out_ids_len = total as c_uint;
        0
    }

    unsafe extern "C" fn cb_on_event(
        user_data: *mut c_void,
        _event_ptr: *const c_uchar,
        _event_len: c_uint,
    ) -> c_int {
        if user_data.is_null() {
            return KitErrorCode::NullPointer.code();
        }
        let state = &*(user_data as *const CallbackState);
        state.events.fetch_add(1, Ordering::SeqCst);
        0
    }

    fn callback_tables(
        user_data: *mut c_void,
    ) -> (
        CKeyCallbacks,
        CEvmCallbacks,
        CMoneroCallbacks,
        CPersistenceCallbacks,
        CTimeNetworkCallbacks,
        CUxCallbacks,
    ) {
        (
            CKeyCallbacks {
                evm_address: None,
                sign_evm_message: None,
                monero_spend_public_key: None,
                monero_view_public_key: None,
                monero_derive_subaddress: None,
                monero_compute_key_image: None,
                user_data,
            },
            CEvmCallbacks {
                send_raw_tx: Some(cb_send_raw_tx),
                estimate_gas: None,
                replace_tx: None,
                get_receipt: None,
                get_logs: None,
                chain_id: None,
                block_number: Some(cb_block_number),
                gas_price: None,
                user_data,
            },
            CMoneroCallbacks {
                broadcast_tx: Some(cb_broadcast_tx),
                is_key_image_spent: None,
                get_tx_confirmations: None,
                node_health: None,
                user_data,
            },
            CPersistenceCallbacks {
                save_checkpoint: Some(cb_save_checkpoint),
                load_checkpoint: Some(cb_load_checkpoint),
                list_active_swaps: Some(cb_list_active_swaps),
                delete_swap: Some(cb_delete_swap),
                user_data,
            },
            CTimeNetworkCallbacks {
                current_block_number: None,
                current_timestamp: Some(cb_current_timestamp),
                is_evm_reachable: None,
                is_monero_reachable: None,
                user_data,
            },
            CUxCallbacks {
                on_event: Some(cb_on_event),
                user_data,
            },
        )
    }

    #[test]
    fn ffi_callback_thread_affinity_and_user_data_lifetime() {
        let state = Box::new(CallbackState::default());
        let raw_state = Box::into_raw(state) as *mut c_void;

        let (key, evm, monero, persistence, time, ux) = callback_tables(raw_state);
        let mut handle: *mut FfiOrchestratorHandle = ptr::null_mut();
        let rc = unsafe {
            eswp_orchestrator_new(
                &key,
                &evm,
                &monero,
                &persistence,
                &time,
                &ux,
                ptr::null(),
                &mut handle,
            )
        };
        assert_eq!(rc, 0);
        assert!(!handle.is_null());

        let reservation = [0x11u8; 32];
        let mut out = [0u8; 32];
        let rc = unsafe {
            eswp_orchestrator_step(
                handle,
                reservation.as_ptr(),
                1,
                ptr::null(),
                0,
                out.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0);

        let handle_addr = handle as usize;
        let reservation_copy = reservation;
        let join = std::thread::spawn(move || unsafe {
            let mut out = [0u8; 32];
            eswp_orchestrator_step(
                handle_addr as *mut FfiOrchestratorHandle,
                reservation_copy.as_ptr(),
                2,
                ptr::null(),
                0,
                out.as_mut_ptr(),
            )
        });
        let rc = join.join().expect("thread join");
        assert_ne!(rc, 0);

        unsafe {
            eswp_orchestrator_free(handle);
        }

        let state = unsafe { Box::from_raw(raw_state as *mut CallbackState) };
        assert!(!state
            .checkpoints
            .lock()
            .expect("test checkpoint mutex")
            .is_empty());
        assert!(state.events.load(Ordering::SeqCst) > 0);
    }

    #[test]
    fn ffi_ownership_contract_allows_safe_double_free() {
        let reservation = [0x22u8; 32];
        let envelope = [0xAAu8; 8];
        let rc = unsafe {
            eswp_publish_context(
                reservation.as_ptr(),
                envelope.as_ptr(),
                envelope.len() as c_uint,
            )
        };
        assert_eq!(rc, 0);

        let mut ptr_out: *mut c_uchar = ptr::null_mut();
        let mut len_out: c_uint = 0;
        let rc = unsafe { eswp_fetch_messages(reservation.as_ptr(), &mut ptr_out, &mut len_out) };
        assert_eq!(rc, 0);
        assert!(!ptr_out.is_null());
        assert!(len_out > 0);

        unsafe {
            eswp_free_buffer(ptr_out, len_out);
            eswp_free_buffer(ptr_out, len_out);
        }
        assert!(BUFFER_ALLOCS
            .lock()
            .expect("buffer alloc mutex poisoned")
            .is_empty());

        let mut msg_ptr: *mut c_char = ptr::null_mut();
        let rc = unsafe { eswp_error_message(1234, &mut msg_ptr) };
        assert_eq!(rc, 0);
        assert!(!msg_ptr.is_null());
        unsafe {
            let _ = CStr::from_ptr(msg_ptr);
            eswp_free_string(msg_ptr);
            eswp_free_string(msg_ptr);
        }
        assert!(STRING_ALLOCS
            .lock()
            .expect("string alloc mutex poisoned")
            .is_empty());
    }

    proptest! {
        #[test]
        fn property1_ffi_boundary_safety(
            random_len in 0u32..128,
            random_bytes in prop::collection::vec(any::<u8>(), 0..256),
        ) {
            let mut cap = CapabilityDescriptor {
                version_major: 0,
                version_minor: 0,
                version_patch: 0,
                backends: 0,
                api_groups: 0,
                wire_version: 0,
            };
            prop_assert_ne!(unsafe { eswp_capability_query(ptr::null_mut()) }, 0);
            prop_assert_eq!(unsafe { eswp_capability_query(&mut cap) }, 0);

            prop_assert_ne!(
                unsafe { eswp_register_enc_pub(ptr::null(), random_bytes.as_ptr(), random_len) },
                0
            );
            prop_assert_ne!(
                unsafe { eswp_get_enc_pub(ptr::null(), ptr::null_mut(), ptr::null_mut()) },
                0
            );
            prop_assert_ne!(
                unsafe { eswp_is_registered(ptr::null(), ptr::null_mut()) },
                0
            );

            prop_assert_ne!(
                unsafe { eswp_publish_context(ptr::null(), random_bytes.as_ptr(), random_len) },
                0
            );
            prop_assert_ne!(
                unsafe { eswp_publish_presig(ptr::null(), random_bytes.as_ptr(), random_len) },
                0
            );
            prop_assert_ne!(
                unsafe { eswp_publish_final_sig(ptr::null(), random_bytes.as_ptr(), random_len) },
                0
            );
            prop_assert_ne!(
                unsafe { eswp_fetch_messages(ptr::null(), ptr::null_mut(), ptr::null_mut()) },
                0
            );

            prop_assert_ne!(unsafe { eswp_register_desk(ptr::null()) }, 0);
            prop_assert_ne!(
                unsafe {
                    eswp_reserve_atomic_swap(
                        ptr::null(),
                        ptr::null(),
                        ptr::null(),
                        ptr::null(),
                        ptr::null(),
                        ptr::null(),
                        0,
                        0,
                    )
                },
                0
            );
            prop_assert_ne!(
                unsafe { eswp_get_reservation(ptr::null(), ptr::null_mut()) },
                0
            );

            let mut event = EswpHashlockSetEvent::default();
            prop_assert_ne!(
                unsafe {
                    eswp_decode_hashlock_set(
                        ptr::null(),
                        1,
                        random_bytes.as_ptr(),
                        random_len,
                        &mut event,
                    )
                },
                0
            );

            let mut out_handle: *mut FfiOrchestratorHandle = ptr::null_mut();
            prop_assert_ne!(
                unsafe {
                    eswp_orchestrator_new(
                        ptr::null(),
                        ptr::null(),
                        ptr::null(),
                        ptr::null(),
                        ptr::null(),
                        ptr::null(),
                        ptr::null(),
                        &mut out_handle,
                    )
                },
                0
            );
            prop_assert_ne!(
                unsafe {
                    eswp_orchestrator_resume(
                        ptr::null_mut(),
                        ptr::null(),
                        ptr::null_mut(),
                        ptr::null_mut(),
                    )
                },
                0
            );
            prop_assert_ne!(
                unsafe {
                    eswp_orchestrator_step(
                        ptr::null_mut(),
                        ptr::null(),
                        9999,
                        random_bytes.as_ptr(),
                        random_len,
                        ptr::null_mut(),
                    )
                },
                0
            );
            prop_assert_ne!(
                unsafe {
                    eswp_orchestrator_check_deadlines(
                        ptr::null_mut(),
                        ptr::null_mut(),
                        0,
                        ptr::null_mut(),
                    )
                },
                0
            );
        }
    }
}

fn gas_option(value: u64) -> Option<u64> {
    if value == 0 {
        None
    } else {
        Some(value)
    }
}

#[no_mangle]
/// # Safety
/// Caller provides all buffers. `out_data_ptr` must have capacity `out_data_capacity`.
pub unsafe extern "C" fn eswp_escrow_lock_eth_call(
    escrow_ptr: *const c_uchar,
    swap_id_ptr: *const c_uchar,
    taker_ptr: *const c_uchar,
    adaptor_hash_ptr: *const c_uchar,
    maker_ptr: *const c_uchar,
    amount_be_ptr: *const c_uchar,
    tip_be_ptr: *const c_uchar,
    expiry: u64,
    backend_id: c_uchar,
    settle_digest_ptr: *const c_uchar,
    gas_limit: u64,
    out_data_ptr: *mut c_uchar,
    out_data_capacity: c_uint,
    out_data_len: *mut c_uint,
    out_value_ptr: *mut c_uchar,
    out_gas_limit: *mut u64,
) -> c_int {
    if escrow_ptr.is_null()
        || swap_id_ptr.is_null()
        || taker_ptr.is_null()
        || adaptor_hash_ptr.is_null()
        || maker_ptr.is_null()
        || amount_be_ptr.is_null()
        || tip_be_ptr.is_null()
        || settle_digest_ptr.is_null()
    {
        return FfiError::NullPointer.code();
    }
    let escrow = match read_address(escrow_ptr) {
        Ok(addr) => addr,
        Err(err) => return err.code(),
    };
    let swap_id = match read_fixed::<32>(swap_id_ptr) {
        Ok(bytes) => bytes,
        Err(err) => return err.code(),
    };
    let taker = match read_address(taker_ptr) {
        Ok(addr) => addr,
        Err(err) => return err.code(),
    };
    let adaptor_hash = match read_fixed::<32>(adaptor_hash_ptr) {
        Ok(bytes) => bytes,
        Err(err) => return err.code(),
    };
    let maker = match read_address(maker_ptr) {
        Ok(addr) => addr,
        Err(err) => return err.code(),
    };
    let amount = match read_fixed::<32>(amount_be_ptr) {
        Ok(bytes) => u256_from_be(&bytes),
        Err(err) => return err.code(),
    };
    let tip = match read_fixed::<32>(tip_be_ptr) {
        Ok(bytes) => u256_from_be(&bytes),
        Err(err) => return err.code(),
    };
    let backend = match backend_from_id(backend_id) {
        Ok(b) => b,
        Err(err) => return err.code(),
    };
    let settle_digest = match read_fixed::<32>(settle_digest_ptr) {
        Ok(bytes) => bytes,
        Err(err) => return err.code(),
    };

    let args = LockEthArgs {
        swap_id,
        taker,
        maker,
        amount,
        tip,
        expiry,
        backend,
        settle_digest,
        quote_commitment: quote_commitment_from_adaptor(adaptor_hash),
        gas_limit: gas_option(gas_limit),
    };

    let call = match capture_escrow_call(escrow, move |client| client.lock_eth(args)) {
        Ok(call) => call,
        Err(err) => return err.code(),
    };
    match write_call_outputs(
        &call,
        out_data_ptr,
        out_data_capacity,
        out_data_len,
        out_value_ptr,
        out_gas_limit,
    ) {
        Ok(_) => 0,
        Err(err) => err.code(),
    }
}

#[no_mangle]
/// # Safety
/// Caller owns all buffers; `swap_id_ptr` must reference 32 readable bytes.
pub unsafe extern "C" fn eswp_escrow_refund_call(
    escrow_ptr: *const c_uchar,
    swap_id_ptr: *const c_uchar,
    gas_limit: u64,
    out_data_ptr: *mut c_uchar,
    out_data_capacity: c_uint,
    out_data_len: *mut c_uint,
    out_value_ptr: *mut c_uchar,
    out_gas_limit: *mut u64,
) -> c_int {
    if escrow_ptr.is_null() || swap_id_ptr.is_null() {
        return FfiError::NullPointer.code();
    }
    let escrow = match read_address(escrow_ptr) {
        Ok(addr) => addr,
        Err(err) => return err.code(),
    };
    let swap_id = match read_fixed::<32>(swap_id_ptr) {
        Ok(bytes) => bytes,
        Err(err) => return err.code(),
    };
    let args = EscrowRefundArgs {
        swap_id,
        gas_limit: gas_option(gas_limit),
    };
    let call = match capture_escrow_call(escrow, move |client| client.refund(args)) {
        Ok(call) => call,
        Err(err) => return err.code(),
    };
    match write_call_outputs(
        &call,
        out_data_ptr,
        out_data_capacity,
        out_data_len,
        out_value_ptr,
        out_gas_limit,
    ) {
        Ok(_) => 0,
        Err(err) => err.code(),
    }
}

#[no_mangle]
/// # Safety
/// Caller provides `logs_ptr` (optional when `logs_len` is zero) and an output slice with enough
/// capacity to hold all decoded events.
pub unsafe extern "C" fn eswp_decode_escrow_events(
    ctx_ptr: *const c_uchar,
    ctx_len: c_uint,
    logs_ptr: *const EswpEscrowLog,
    logs_len: c_uint,
    out_events_ptr: *mut EswpEscrowEvent,
    out_events_capacity: c_uint,
    out_events_written: *mut c_uint,
) -> c_int {
    if ctx_ptr.is_null() || out_events_ptr.is_null() || out_events_written.is_null() {
        return FfiError::NullPointer.code();
    }
    let ctx_bytes = match read_bytes(ctx_ptr, ctx_len as usize) {
        Ok(bytes) => bytes,
        Err(err) => return err.code(),
    };
    let ctx = match decode_sdk_settlement_ctx(ctx_bytes) {
        Ok(ctx) => ctx,
        Err(err) => return err.code(),
    };
    let logs_slice = if logs_len == 0 {
        &[]
    } else if logs_ptr.is_null() {
        return FfiError::NullPointer.code();
    } else {
        slice::from_raw_parts(logs_ptr, logs_len as usize)
    };
    let mut logs = Vec::with_capacity(logs_slice.len());
    for raw in logs_slice {
        let amount = u256_from_be(&raw.amount_be);
        logs.push(EscrowLog {
            kind: raw.kind,
            swap_id: raw.swap_id,
            amount,
            backend: raw.backend,
        });
    }

    let events = match sdk_decode_events(&ctx, &logs) {
        Ok(evts) => evts,
        Err(err) => return FfiError::from(err).code(),
    };
    if events.len() > out_events_capacity as usize {
        return FfiError::CapacityInsufficient.code();
    }
    let out_slice = slice::from_raw_parts_mut(out_events_ptr, out_events_capacity as usize);
    for (idx, evt) in events.iter().enumerate() {
        let dest = &mut out_slice[idx];
        dest.digest = evt.digest;
        match &evt.event {
            EscrowEvent::SwapLocked {
                swap_id,
                amount,
                backend,
            } => {
                dest.kind = 0;
                dest.swap_id = *swap_id;
                dest.amount_be = u256_to_be(amount);
                dest.backend = *backend as c_uchar;
            }
            EscrowEvent::SwapSettled { swap_id, backend } => {
                dest.kind = 1;
                dest.swap_id = *swap_id;
                dest.amount_be = [0u8; 32];
                dest.backend = *backend as c_uchar;
            }
            EscrowEvent::SwapRefunded { swap_id, backend } => {
                dest.kind = 2;
                dest.swap_id = *swap_id;
                dest.amount_be = [0u8; 32];
                dest.backend = *backend as c_uchar;
            }
        }
    }
    *out_events_written = events.len() as c_uint;
    0
}

#[no_mangle]
/// # Safety
/// Caller provides the QuoteBoard address, inputs, and output buffers used to receive the
/// calldata/value pair required for posting the tx hash on-chain.
pub unsafe extern "C" fn eswp_post_tx_hash_call(
    board_ptr: *const c_uchar,
    swap_id_ptr: *const c_uchar,
    monero_tx_hash_ptr: *const c_uchar,
    tau_pub_ptr: *const c_uchar,
    tau_pub_len: c_uint,
    evm_privkey_ptr: *const c_uchar,
    gas_limit: u64,
    out_data_ptr: *mut c_uchar,
    out_data_capacity: c_uint,
    out_data_len: *mut c_uint,
    out_value_ptr: *mut c_uchar,
    out_gas_limit: *mut u64,
) -> c_int {
    if board_ptr.is_null()
        || swap_id_ptr.is_null()
        || monero_tx_hash_ptr.is_null()
        || evm_privkey_ptr.is_null()
    {
        return FfiError::NullPointer.code();
    }
    let board = match read_address(board_ptr) {
        Ok(addr) => addr,
        Err(err) => return err.code(),
    };
    let swap_id = match read_fixed::<32>(swap_id_ptr) {
        Ok(bytes) => bytes,
        Err(err) => return err.code(),
    };
    let monero_tx_hash = match read_fixed::<32>(monero_tx_hash_ptr) {
        Ok(bytes) => bytes,
        Err(err) => return err.code(),
    };
    let tau_slice = match read_bytes(tau_pub_ptr, tau_pub_len as usize) {
        Ok(bytes) => bytes.to_vec(),
        Err(err) => return err.code(),
    };
    let priv_key_bytes = match read_fixed::<32>(evm_privkey_ptr) {
        Ok(bytes) => bytes,
        Err(err) => return err.code(),
    };
    let signer = match PrivateKeySigner::from_slice(&priv_key_bytes) {
        Ok(signer) => signer,
        Err(_) => return FfiError::from(ErrorCode::SignatureInvalid).code(),
    };
    let transport = CaptureSignerTransport::new(signer);
    let client = QuoteBoardClient::new(board, transport.clone());
    let args = PostTxHashArgs {
        swap_id,
        monero_tx_hash,
        tau_pub: &tau_slice,
    };
    if let Err(err) = client.post_tx_hash(args) {
        return FfiError::from(err).code();
    }
    let mut call = match transport.take() {
        Some(call) => call,
        None => return FfiError::Decode.code(),
    };
    if gas_limit != 0 {
        call.gas_limit = Some(gas_limit);
    }
    match write_call_outputs(
        &call,
        out_data_ptr,
        out_data_capacity,
        out_data_len,
        out_value_ptr,
        out_gas_limit,
    ) {
        Ok(_) => 0,
        Err(err) => err.code(),
    }
}

#[no_mangle]
/// # Safety
/// Caller must allocate output buffers. Inputs must reference readable buffers of the stated sizes.
pub unsafe extern "C" fn eswp_escrow_settle_call(
    escrow_ptr: *const c_uchar,
    swap_id_ptr: *const c_uchar,
    adaptor_secret_ptr: *const c_uchar,
    min_received_be_ptr: *const c_uchar,
    gas_limit: u64,
    out_data_ptr: *mut c_uchar,
    out_data_capacity: c_uint,
    out_data_len: *mut c_uint,
    out_value_ptr: *mut c_uchar,
    out_gas_limit: *mut u64,
) -> c_int {
    if escrow_ptr.is_null()
        || swap_id_ptr.is_null()
        || adaptor_secret_ptr.is_null()
        || min_received_be_ptr.is_null()
    {
        return FfiError::NullPointer.code();
    }
    let escrow = match read_address(escrow_ptr) {
        Ok(addr) => addr,
        Err(err) => return err.code(),
    };
    let swap_id = match read_fixed::<32>(swap_id_ptr) {
        Ok(bytes) => bytes,
        Err(err) => return err.code(),
    };
    let adaptor_secret = match read_fixed::<32>(adaptor_secret_ptr) {
        Ok(bytes) => bytes,
        Err(err) => return err.code(),
    };
    let min_received = match read_fixed::<32>(min_received_be_ptr) {
        Ok(bytes) => u256_from_be(&bytes),
        Err(err) => return err.code(),
    };
    let args = SettleArgs {
        swap_id,
        adaptor_secret,
        min_received,
        gas_limit: gas_option(gas_limit),
    };
    let call = match capture_escrow_call(escrow, move |client| client.settle(args)) {
        Ok(call) => call,
        Err(err) => return err.code(),
    };
    match write_call_outputs(
        &call,
        out_data_ptr,
        out_data_capacity,
        out_data_len,
        out_value_ptr,
        out_gas_limit,
    ) {
        Ok(_) => 0,
        Err(err) => err.code(),
    }
}

#[no_mangle]
/// # Safety
/// Caller provides buffers for outputs. `permit_ptr` may be null when `permit_len` is zero.
pub unsafe extern "C" fn eswp_escrow_lock_erc20_call(
    escrow_ptr: *const c_uchar,
    swap_id_ptr: *const c_uchar,
    taker_ptr: *const c_uchar,
    token_ptr: *const c_uchar,
    amount_be_ptr: *const c_uchar,
    tip_be_ptr: *const c_uchar,
    adaptor_hash_ptr: *const c_uchar,
    maker_ptr: *const c_uchar,
    expiry: u64,
    backend_id: c_uchar,
    settle_digest_ptr: *const c_uchar,
    permit_ptr: *const c_uchar,
    permit_len: c_uint,
    gas_limit: u64,
    out_data_ptr: *mut c_uchar,
    out_data_capacity: c_uint,
    out_data_len: *mut c_uint,
    out_value_ptr: *mut c_uchar,
    out_gas_limit: *mut u64,
) -> c_int {
    if escrow_ptr.is_null()
        || swap_id_ptr.is_null()
        || taker_ptr.is_null()
        || token_ptr.is_null()
        || amount_be_ptr.is_null()
        || tip_be_ptr.is_null()
        || adaptor_hash_ptr.is_null()
        || maker_ptr.is_null()
        || settle_digest_ptr.is_null()
    {
        return FfiError::NullPointer.code();
    }
    let escrow = match read_address(escrow_ptr) {
        Ok(addr) => addr,
        Err(err) => return err.code(),
    };
    let swap_id = match read_fixed::<32>(swap_id_ptr) {
        Ok(bytes) => bytes,
        Err(err) => return err.code(),
    };
    let taker = match read_address(taker_ptr) {
        Ok(addr) => addr,
        Err(err) => return err.code(),
    };
    let token = match read_address(token_ptr) {
        Ok(addr) => addr,
        Err(err) => return err.code(),
    };
    let amount = match read_fixed::<32>(amount_be_ptr) {
        Ok(bytes) => u256_from_be(&bytes),
        Err(err) => return err.code(),
    };
    let tip = match read_fixed::<32>(tip_be_ptr) {
        Ok(bytes) => u256_from_be(&bytes),
        Err(err) => return err.code(),
    };
    let adaptor_hash = match read_fixed::<32>(adaptor_hash_ptr) {
        Ok(bytes) => bytes,
        Err(err) => return err.code(),
    };
    let maker = match read_address(maker_ptr) {
        Ok(addr) => addr,
        Err(err) => return err.code(),
    };
    let backend = match backend_from_id(backend_id) {
        Ok(b) => b,
        Err(err) => return err.code(),
    };
    let settle_digest = match read_fixed::<32>(settle_digest_ptr) {
        Ok(bytes) => bytes,
        Err(err) => return err.code(),
    };
    let permit_bytes = match read_bytes(permit_ptr, permit_len as usize) {
        Ok(bytes) => bytes.to_vec(),
        Err(err) => return err.code(),
    };

    let args = LockErc20Args {
        swap_id,
        taker,
        token,
        amount,
        tip,
        maker,
        expiry,
        backend,
        settle_digest,
        quote_commitment: quote_commitment_from_adaptor(adaptor_hash),
        permit: Bytes::from(permit_bytes),
        gas_limit: gas_option(gas_limit),
    };

    let call = match capture_escrow_call(escrow, move |client| client.lock_erc20(args)) {
        Ok(call) => call,
        Err(err) => return err.code(),
    };
    match write_call_outputs(
        &call,
        out_data_ptr,
        out_data_capacity,
        out_data_len,
        out_value_ptr,
        out_gas_limit,
    ) {
        Ok(_) => 0,
        Err(err) => err.code(),
    }
}

fn write_owned_bytes(
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_uint,
    mut data: Vec<u8>,
) -> Result<(), FfiError> {
    if out_ptr.is_null() || out_len.is_null() {
        return Err(FfiError::NullPointer);
    }
    data.shrink_to_fit();
    let len = data.len();
    let boxed = data.into_boxed_slice();
    let ptr = Box::into_raw(boxed) as *mut c_uchar;
    unsafe {
        *out_ptr = ptr;
        *out_len = len as c_uint;
    }
    register_buffer_alloc(ptr, len);
    Ok(())
}

fn write_owned_string(out_ptr: *mut *mut c_char, value: &str) -> Result<(), FfiError> {
    if out_ptr.is_null() {
        return Err(FfiError::NullPointer);
    }
    let cstring = CString::new(value).map_err(|_| FfiError::Decode)?;
    let ptr = cstring.into_raw();
    unsafe {
        *out_ptr = ptr;
    }
    register_string_alloc(ptr);
    Ok(())
}

fn read_reservation_id(ptr: *const c_uchar) -> Result<ReservationId, FfiError> {
    read_fixed::<32>(ptr)
}

fn decode_created_at(
    payload_ptr: *const c_uchar,
    payload_len: c_uint,
) -> Result<Option<u64>, FfiError> {
    if payload_len == 0 {
        return Ok(None);
    }
    if payload_len != 8 {
        return Err(FfiError::LengthInvalid);
    }
    let bytes = read_bytes(payload_ptr, payload_len as usize)?;
    let mut ts = [0u8; 8];
    ts.copy_from_slice(bytes);
    Ok(Some(u64::from_le_bytes(ts)))
}

fn decode_context_payload(
    payload_ptr: *const c_uchar,
    payload_len: c_uint,
) -> Result<MoneroContext, FfiError> {
    let payload = read_bytes(payload_ptr, payload_len as usize)?;
    if payload.len() < 34 {
        return Err(FfiError::LengthInvalid);
    }
    let mut context_hash = [0u8; 32];
    context_hash.copy_from_slice(&payload[0..32]);
    let mut wire = [0u8; 2];
    wire.copy_from_slice(&payload[32..34]);
    let wire_version = u16::from_le_bytes(wire);
    Ok(MoneroContext {
        context_hash,
        wire_version,
        envelope: None,
    })
}

fn address_to_array(addr: AlloyAddress) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(addr.as_slice());
    out
}

#[no_mangle]
/// # Safety
/// [out] `out_descriptor` must be a valid writable pointer to a caller-allocated
/// `CapabilityDescriptor` structure.
pub unsafe extern "C" fn eswp_capability_query(out_descriptor: *mut CapabilityDescriptor) -> c_int {
    ffi_guard(|| {
        if out_descriptor.is_null() {
            return Err(FfiError::NullPointer);
        }
        *out_descriptor = CapabilityDescriptor {
            version_major: VERSION_MAJOR,
            version_minor: VERSION_MINOR,
            version_patch: VERSION_PATCH,
            backends: BACKEND_MASK_CLSAG,
            api_groups: API_GROUP_KEY_REGISTRY
                | API_GROUP_MAILBOX
                | API_GROUP_ATOMIC_DESK
                | API_GROUP_ESCROW
                | API_GROUP_EVENT_DECODE
                | API_GROUP_ORCHESTRATOR,
            wire_version: ABI_WIRE_VERSION,
        };
        Ok(())
    })
}

#[no_mangle]
/// # Safety
/// [in] `owner_ptr` points to a 20-byte owner address.
/// [in] `pubkey_ptr` points to `pubkey_len` bytes and must be 33 bytes.
pub unsafe extern "C" fn eswp_register_enc_pub(
    owner_ptr: *const c_uchar,
    pubkey_ptr: *const c_uchar,
    pubkey_len: c_uint,
) -> c_int {
    ffi_guard(|| {
        let owner = read_fixed::<20>(owner_ptr)?;
        if pubkey_len != 33 {
            return Err(FfiError::LengthInvalid);
        }
        let pubkey = read_bytes(pubkey_ptr, pubkey_len as usize)?;
        let mut key = [0u8; 33];
        key.copy_from_slice(pubkey);
        L3_STATE
            .lock()
            .expect("l3 state mutex poisoned")
            .key_registry
            .insert(owner, key);
        Ok(())
    })
}

#[no_mangle]
/// # Safety
/// [in] `owner_ptr` points to a 20-byte owner address.
/// [out][owned] on success, `out_pubkey_ptr` receives a library-owned buffer and `out_pubkey_len`
/// receives its size; free with `eswp_free_buffer`.
pub unsafe extern "C" fn eswp_get_enc_pub(
    owner_ptr: *const c_uchar,
    out_pubkey_ptr: *mut *mut c_uchar,
    out_pubkey_len: *mut c_uint,
) -> c_int {
    ffi_guard(|| {
        let owner = read_fixed::<20>(owner_ptr)?;
        let state = L3_STATE.lock().expect("l3 state mutex poisoned");
        let pubkey = match state.key_registry.get(&owner) {
            Some(pubkey) => pubkey,
            None => return Err(FfiError::NotFound),
        };
        write_owned_bytes(out_pubkey_ptr, out_pubkey_len, pubkey.to_vec())
    })
}

#[no_mangle]
/// # Safety
/// [in] `owner_ptr` points to a 20-byte owner address.
/// [out] `out_registered` must be writable.
pub unsafe extern "C" fn eswp_is_registered(
    owner_ptr: *const c_uchar,
    out_registered: *mut c_uchar,
) -> c_int {
    ffi_guard(|| {
        if out_registered.is_null() {
            return Err(FfiError::NullPointer);
        }
        let owner = read_fixed::<20>(owner_ptr)?;
        let state = L3_STATE.lock().expect("l3 state mutex poisoned");
        *out_registered = if state.key_registry.contains_key(&owner) {
            1
        } else {
            0
        };
        Ok(())
    })
}

fn publish_mailbox_message(
    reservation_id_ptr: *const c_uchar,
    envelope_ptr: *const c_uchar,
    envelope_len: c_uint,
) -> Result<(), FfiError> {
    let reservation_id = read_reservation_id(reservation_id_ptr)?;
    let envelope = read_bytes(envelope_ptr, envelope_len as usize)?;
    let mut state = L3_STATE.lock().expect("l3 state mutex poisoned");
    state
        .mailbox
        .entry(reservation_id)
        .or_default()
        .push(envelope.to_vec());
    Ok(())
}

#[no_mangle]
/// # Safety
/// [in] `reservation_id_ptr` points to 32 bytes.
/// [in] `envelope_ptr` points to `envelope_len` bytes.
pub unsafe extern "C" fn eswp_publish_context(
    reservation_id_ptr: *const c_uchar,
    envelope_ptr: *const c_uchar,
    envelope_len: c_uint,
) -> c_int {
    ffi_guard(|| publish_mailbox_message(reservation_id_ptr, envelope_ptr, envelope_len))
}

#[no_mangle]
/// # Safety
/// [in] `reservation_id_ptr` points to 32 bytes.
/// [in] `envelope_ptr` points to `envelope_len` bytes.
pub unsafe extern "C" fn eswp_publish_presig(
    reservation_id_ptr: *const c_uchar,
    envelope_ptr: *const c_uchar,
    envelope_len: c_uint,
) -> c_int {
    ffi_guard(|| publish_mailbox_message(reservation_id_ptr, envelope_ptr, envelope_len))
}

#[no_mangle]
/// # Safety
/// [in] `reservation_id_ptr` points to 32 bytes.
/// [in] `envelope_ptr` points to `envelope_len` bytes.
pub unsafe extern "C" fn eswp_publish_final_sig(
    reservation_id_ptr: *const c_uchar,
    envelope_ptr: *const c_uchar,
    envelope_len: c_uint,
) -> c_int {
    ffi_guard(|| publish_mailbox_message(reservation_id_ptr, envelope_ptr, envelope_len))
}

#[no_mangle]
/// # Safety
/// [in] `reservation_id_ptr` points to 32 bytes.
/// [out][owned] `out_messages_ptr` receives a library-owned encoded message blob and
/// `out_messages_len` its size; free via `eswp_free_buffer`.
pub unsafe extern "C" fn eswp_fetch_messages(
    reservation_id_ptr: *const c_uchar,
    out_messages_ptr: *mut *mut c_uchar,
    out_messages_len: *mut c_uint,
) -> c_int {
    ffi_guard(|| {
        let reservation_id = read_reservation_id(reservation_id_ptr)?;
        let state = L3_STATE.lock().expect("l3 state mutex poisoned");
        let messages = state
            .mailbox
            .get(&reservation_id)
            .cloned()
            .unwrap_or_default();
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&(messages.len() as u32).to_le_bytes());
        for message in messages {
            encoded.extend_from_slice(&(message.len() as u32).to_le_bytes());
            encoded.extend_from_slice(&message);
        }
        write_owned_bytes(out_messages_ptr, out_messages_len, encoded)
    })
}

#[no_mangle]
/// # Safety
/// [in] `desk_id_ptr` points to 32 bytes.
pub unsafe extern "C" fn eswp_register_desk(desk_id_ptr: *const c_uchar) -> c_int {
    ffi_guard(|| {
        let desk_id = read_fixed::<32>(desk_id_ptr)?;
        L3_STATE
            .lock()
            .expect("l3 state mutex poisoned")
            .desks
            .insert(desk_id);
        Ok(())
    })
}

#[no_mangle]
/// # Safety
/// [in] all pointer inputs must point to fixed-size buffers:
/// reservation (32), desk_id (32), taker (20), asset (20), amount (32), settlement_digest (32).
pub unsafe extern "C" fn eswp_reserve_atomic_swap(
    reservation_id_ptr: *const c_uchar,
    desk_id_ptr: *const c_uchar,
    taker_ptr: *const c_uchar,
    asset_ptr: *const c_uchar,
    amount_be_ptr: *const c_uchar,
    settlement_digest_ptr: *const c_uchar,
    expiry: u64,
    created_at: u64,
) -> c_int {
    ffi_guard(|| {
        let reservation_id = read_reservation_id(reservation_id_ptr)?;
        let desk_id = read_fixed::<32>(desk_id_ptr)?;
        let taker = read_fixed::<20>(taker_ptr)?;
        let asset = read_fixed::<20>(asset_ptr)?;
        let amount_be = read_fixed::<32>(amount_be_ptr)?;
        let settlement_digest = read_fixed::<32>(settlement_digest_ptr)?;
        let reservation = EswpAtomicReservationCreatedEvent {
            reservation_id,
            desk_id,
            taker,
            asset,
            amount_be,
            settlement_digest,
            expiry,
            created_at,
        };
        L3_STATE
            .lock()
            .expect("l3 state mutex poisoned")
            .reservations
            .insert(reservation_id, reservation);
        Ok(())
    })
}

#[no_mangle]
/// # Safety
/// [in] `reservation_id_ptr` points to 32 bytes.
/// [out] `out_reservation` must be writable.
pub unsafe extern "C" fn eswp_get_reservation(
    reservation_id_ptr: *const c_uchar,
    out_reservation: *mut EswpAtomicReservationCreatedEvent,
) -> c_int {
    ffi_guard(|| {
        if out_reservation.is_null() {
            return Err(FfiError::NullPointer);
        }
        let reservation_id = read_reservation_id(reservation_id_ptr)?;
        let state = L3_STATE.lock().expect("l3 state mutex poisoned");
        let reservation = match state.reservations.get(&reservation_id) {
            Some(reservation) => reservation,
            None => return Err(FfiError::NotFound),
        };
        *out_reservation = *reservation;
        Ok(())
    })
}

#[no_mangle]
/// # Safety
/// [in] `topics_ptr` points to `topics_len * 32` bytes.
/// [in] `data_ptr` points to `data_len` bytes (nullable when `data_len == 0`).
/// [out] `out_event` is caller-allocated and writable.
pub unsafe extern "C" fn eswp_decode_reservation_created(
    topics_ptr: *const c_uchar,
    topics_len: c_uint,
    data_ptr: *const c_uchar,
    data_len: c_uint,
    out_event: *mut EswpReservationCreatedEvent,
) -> c_int {
    ffi_guard(|| {
        if out_event.is_null() {
            return Err(FfiError::NullPointer);
        }
        let topics = parse_topics(topics_ptr, topics_len)?;
        let data = read_bytes(data_ptr, data_len as usize)?;
        let decoded =
            watcher_decode_reservation_created(&topics, data).map_err(|_| FfiError::Decode)?;
        *out_event = EswpReservationCreatedEvent {
            reservation_id: decoded.reservation_id.into(),
            taker: address_to_array(decoded.taker),
            desk: address_to_array(decoded.desk),
            amount_be: u256_to_be(&decoded.amount),
            counter_be: u256_to_be(&decoded.counter),
        };
        Ok(())
    })
}

#[no_mangle]
/// # Safety
/// [in] `topics_ptr` points to `topics_len * 32` bytes.
/// [in] `data_ptr` points to `data_len` bytes.
/// [out] `out_event` is caller-allocated and writable.
pub unsafe extern "C" fn eswp_decode_hashlock_set(
    topics_ptr: *const c_uchar,
    topics_len: c_uint,
    data_ptr: *const c_uchar,
    data_len: c_uint,
    out_event: *mut EswpHashlockSetEvent,
) -> c_int {
    ffi_guard(|| {
        if out_event.is_null() {
            return Err(FfiError::NullPointer);
        }
        let topics = parse_topics(topics_ptr, topics_len)?;
        let data = read_bytes(data_ptr, data_len as usize)?;
        let decoded = watcher_decode_hashlock_set(&topics, data).map_err(|_| FfiError::Decode)?;
        *out_event = EswpHashlockSetEvent {
            reservation_id: decoded.reservation_id.into(),
            hashlock: decoded.hashlock,
        };
        Ok(())
    })
}

#[no_mangle]
/// # Safety
/// [in] `topics_ptr` points to `topics_len * 32` bytes.
/// [in] `data_ptr` points to `data_len` bytes.
/// [out] `out_event` is caller-allocated and writable.
pub unsafe extern "C" fn eswp_decode_atomic_reservation_created(
    topics_ptr: *const c_uchar,
    topics_len: c_uint,
    data_ptr: *const c_uchar,
    data_len: c_uint,
    out_event: *mut EswpAtomicReservationCreatedEvent,
) -> c_int {
    ffi_guard(|| {
        if out_event.is_null() {
            return Err(FfiError::NullPointer);
        }
        let topics = parse_topics(topics_ptr, topics_len)?;
        let data = read_bytes(data_ptr, data_len as usize)?;
        let decoded = watcher_decode_atomic_reservation_created(&topics, data)
            .map_err(|_| FfiError::Decode)?;
        *out_event = EswpAtomicReservationCreatedEvent {
            reservation_id: decoded.reservation_id.into(),
            desk_id: decoded.desk_id.into(),
            taker: address_to_array(decoded.taker),
            asset: address_to_array(decoded.asset),
            amount_be: u256_to_be(&decoded.amount),
            settlement_digest: decoded.settlement_digest,
            expiry: decoded.expiry,
            created_at: decoded.created_at,
        };
        Ok(())
    })
}

#[no_mangle]
/// # Safety
/// [in] `topics_ptr` points to `topics_len * 32` bytes.
/// [in] `data_ptr` points to `data_len` bytes.
/// [out] `out_event` is caller-allocated and writable.
pub unsafe extern "C" fn eswp_decode_tranche_opened(
    topics_ptr: *const c_uchar,
    topics_len: c_uint,
    data_ptr: *const c_uchar,
    data_len: c_uint,
    out_event: *mut EswpTrancheOpenedEvent,
) -> c_int {
    ffi_guard(|| {
        if out_event.is_null() {
            return Err(FfiError::NullPointer);
        }
        let topics = parse_topics(topics_ptr, topics_len)?;
        let data = read_bytes(data_ptr, data_len as usize)?;
        let decoded = watcher_decode_tranche_opened(&topics, data).map_err(|_| FfiError::Decode)?;
        *out_event = EswpTrancheOpenedEvent {
            tranche_id: decoded.tranche_id.into(),
            desk_id: decoded.desk_id.into(),
            maker: address_to_array(decoded.maker),
            asset: address_to_array(decoded.asset),
            price_numerator_be: u256_to_be(&decoded.price_numerator),
            price_denominator_be: u256_to_be(&decoded.price_denominator),
            total_liquidity_be: u256_to_be(&decoded.total_liquidity),
            min_fill_be: u256_to_be(&decoded.min_fill),
            fee_bps: decoded.fee_bps,
            fee_payer: decoded.fee_payer,
            expiry: decoded.expiry,
        };
        Ok(())
    })
}

#[no_mangle]
/// # Safety
/// [in] `topics_ptr` points to `topics_len * 32` bytes.
/// [in] `data_ptr` points to `data_len` bytes.
/// [out] `out_event` is caller-allocated and writable.
pub unsafe extern "C" fn eswp_decode_taker_tranche_opened(
    topics_ptr: *const c_uchar,
    topics_len: c_uint,
    data_ptr: *const c_uchar,
    data_len: c_uint,
    out_event: *mut EswpTakerTrancheOpenedEvent,
) -> c_int {
    ffi_guard(|| {
        if out_event.is_null() {
            return Err(FfiError::NullPointer);
        }
        let topics = parse_topics(topics_ptr, topics_len)?;
        let data = read_bytes(data_ptr, data_len as usize)?;
        let decoded =
            watcher_decode_taker_tranche_opened(&topics, data).map_err(|_| FfiError::Decode)?;
        *out_event = EswpTakerTrancheOpenedEvent {
            tranche_id: decoded.tranche_id.into(),
            desk_id: decoded.desk_id.into(),
            taker: address_to_array(decoded.taker),
            asset: address_to_array(decoded.asset),
            price_numerator_be: u256_to_be(&decoded.price_numerator),
            price_denominator_be: u256_to_be(&decoded.price_denominator),
            total_liquidity_be: u256_to_be(&decoded.total_liquidity),
            min_fill_be: u256_to_be(&decoded.min_fill),
            fee_bps: decoded.fee_bps,
            fee_payer: decoded.fee_payer,
            expiry: decoded.expiry,
            posting_fee_be: u256_to_be(&decoded.posting_fee),
        };
        Ok(())
    })
}

#[no_mangle]
/// # Safety
/// [in] `topics_ptr` points to `topics_len * 32` bytes.
/// [in] `data_ptr` points to `data_len` bytes.
/// [out] `out_event` is caller-allocated and writable.
pub unsafe extern "C" fn eswp_decode_tranche_reserved(
    topics_ptr: *const c_uchar,
    topics_len: c_uint,
    data_ptr: *const c_uchar,
    data_len: c_uint,
    out_event: *mut EswpTrancheReservedEvent,
) -> c_int {
    ffi_guard(|| {
        if out_event.is_null() {
            return Err(FfiError::NullPointer);
        }
        let topics = parse_topics(topics_ptr, topics_len)?;
        let data = read_bytes(data_ptr, data_len as usize)?;
        let decoded =
            watcher_decode_tranche_reserved(&topics, data).map_err(|_| FfiError::Decode)?;
        *out_event = EswpTrancheReservedEvent {
            tranche_id: decoded.tranche_id.into(),
            reservation_id: decoded.reservation_id.into(),
            actor: address_to_array(decoded.taker),
            amount_be: u256_to_be(&decoded.amount),
            remaining_liquidity_be: u256_to_be(&decoded.remaining_liquidity),
        };
        Ok(())
    })
}

#[no_mangle]
/// # Safety
/// [in] `topics_ptr` points to `topics_len * 32` bytes.
/// [in] `data_ptr` points to `data_len` bytes.
/// [out] `out_event` is caller-allocated and writable.
pub unsafe extern "C" fn eswp_decode_taker_tranche_reserved(
    topics_ptr: *const c_uchar,
    topics_len: c_uint,
    data_ptr: *const c_uchar,
    data_len: c_uint,
    out_event: *mut EswpTrancheReservedEvent,
) -> c_int {
    ffi_guard(|| {
        if out_event.is_null() {
            return Err(FfiError::NullPointer);
        }
        let topics = parse_topics(topics_ptr, topics_len)?;
        let data = read_bytes(data_ptr, data_len as usize)?;
        let decoded =
            watcher_decode_taker_tranche_reserved(&topics, data).map_err(|_| FfiError::Decode)?;
        *out_event = EswpTrancheReservedEvent {
            tranche_id: decoded.tranche_id.into(),
            reservation_id: decoded.reservation_id.into(),
            actor: address_to_array(decoded.maker),
            amount_be: u256_to_be(&decoded.amount),
            remaining_liquidity_be: u256_to_be(&decoded.remaining_liquidity),
        };
        Ok(())
    })
}

#[no_mangle]
/// # Safety
/// [in] `topics_ptr` points to `topics_len * 32` bytes.
/// [in] `data_ptr` points to `data_len` bytes.
/// [out] `out_event` is caller-allocated and writable.
pub unsafe extern "C" fn eswp_decode_settled(
    topics_ptr: *const c_uchar,
    topics_len: c_uint,
    data_ptr: *const c_uchar,
    data_len: c_uint,
    out_event: *mut EswpSettleEvent,
) -> c_int {
    ffi_guard(|| {
        if out_event.is_null() {
            return Err(FfiError::NullPointer);
        }
        let topics = parse_topics(topics_ptr, topics_len)?;
        let data = read_bytes(data_ptr, data_len as usize)?;
        let (reservation_id, tau) =
            watcher_decode_reservation_settled(&topics, data).map_err(|_| FfiError::Decode)?;
        *out_event = EswpSettleEvent {
            reservation_id: reservation_id.into(),
            value: tau,
        };
        Ok(())
    })
}

#[no_mangle]
/// # Safety
/// [in] `topics_ptr` points to `topics_len * 32` bytes.
/// [in] `data_ptr` points to `data_len` bytes.
/// [out] `out_event` is caller-allocated and writable.
pub unsafe extern "C" fn eswp_decode_refunded(
    topics_ptr: *const c_uchar,
    topics_len: c_uint,
    data_ptr: *const c_uchar,
    data_len: c_uint,
    out_event: *mut EswpSettleEvent,
) -> c_int {
    ffi_guard(|| {
        if out_event.is_null() {
            return Err(FfiError::NullPointer);
        }
        let topics = parse_topics(topics_ptr, topics_len)?;
        let data = read_bytes(data_ptr, data_len as usize)?;
        let (reservation_id, evidence) =
            watcher_decode_reservation_refunded(&topics, data).map_err(|_| FfiError::Decode)?;
        *out_event = EswpSettleEvent {
            reservation_id: reservation_id.into(),
            value: evidence,
        };
        Ok(())
    })
}

#[no_mangle]
/// # Safety
/// [in] all callback pointers are borrowed for orchestrator lifetime.
/// [out] `out_handle` receives an owned orchestrator handle; release via `eswp_orchestrator_free`.
pub unsafe extern "C" fn eswp_orchestrator_new(
    key_callbacks: *const CKeyCallbacks,
    evm_callbacks: *const CEvmCallbacks,
    monero_callbacks: *const CMoneroCallbacks,
    persistence_callbacks: *const CPersistenceCallbacks,
    time_callbacks: *const CTimeNetworkCallbacks,
    ux_callbacks: *const CUxCallbacks,
    config: *const EswpOrchestratorConfig,
    out_handle: *mut *mut FfiOrchestratorHandle,
) -> c_int {
    ffi_guard(|| {
        if key_callbacks.is_null()
            || evm_callbacks.is_null()
            || monero_callbacks.is_null()
            || persistence_callbacks.is_null()
            || time_callbacks.is_null()
            || ux_callbacks.is_null()
            || out_handle.is_null()
        {
            return Err(FfiError::NullPointer);
        }

        let cfg = if config.is_null() {
            OrchestratorConfig::default()
        } else {
            OrchestratorConfig {
                checkpoint_version: (*config).checkpoint_version,
                maker_timeout_secs: (*config).maker_timeout_secs,
                taker_timeout_secs: (*config).taker_timeout_secs,
            }
        };
        let adapters = FfiHostAdapters::new(
            *key_callbacks,
            *evm_callbacks,
            *monero_callbacks,
            *persistence_callbacks,
            *time_callbacks,
            *ux_callbacks,
        );
        let handle = Box::new(FfiOrchestratorHandle {
            orchestrator: SwapOrchestrator::new(adapters, cfg),
            owner_thread: thread::current().id(),
        });
        *out_handle = Box::into_raw(handle);
        Ok(())
    })
}

#[no_mangle]
/// # Safety
/// [in] `handle` must be a pointer returned by `eswp_orchestrator_new` and freed once.
pub unsafe extern "C" fn eswp_orchestrator_free(handle: *mut FfiOrchestratorHandle) {
    if handle.is_null() {
        return;
    }
    let _ = Box::from_raw(handle);
}

#[no_mangle]
/// # Safety
/// [in] `handle` must be valid.
/// [in] `reservation_id_ptr` points to 32 bytes.
/// [out][owned] `out_state_ptr` receives a library-owned UTF-8 state string; free via `eswp_free_buffer`.
pub unsafe extern "C" fn eswp_orchestrator_resume(
    handle: *mut FfiOrchestratorHandle,
    reservation_id_ptr: *const c_uchar,
    out_state_ptr: *mut *mut c_uchar,
    out_state_len: *mut c_uint,
) -> c_int {
    ffi_guard(|| {
        let handle = read_orchestrator_handle(handle)?;
        let reservation_id = read_reservation_id(reservation_id_ptr)?;
        let state = handle
            .orchestrator
            .resume(reservation_id)
            .map_err(|err| FfiError::from(err.code()))?;
        let rendered = format!("{state:?}");
        write_owned_bytes(out_state_ptr, out_state_len, rendered.into_bytes())
    })
}

pub const ESWP_CMD_MAKER_CREATE_RESERVATION: c_uint = 1;
pub const ESWP_CMD_MAKER_SET_HASHLOCK: c_uint = 2;
pub const ESWP_CMD_MAKER_HANDLE_CONTEXT: c_uint = 3;
pub const ESWP_CMD_MAKER_PUBLISH_PRESIG: c_uint = 4;
pub const ESWP_CMD_MAKER_HANDLE_FINAL_SIG: c_uint = 5;
pub const ESWP_CMD_MAKER_SETTLE: c_uint = 6;
pub const ESWP_CMD_TAKER_ACCEPT_RESERVATION: c_uint = 11;
pub const ESWP_CMD_TAKER_PUBLISH_CONTEXT: c_uint = 12;
pub const ESWP_CMD_TAKER_HANDLE_PRESIG: c_uint = 13;
pub const ESWP_CMD_TAKER_COMPLETE_AND_BROADCAST: c_uint = 14;
pub const ESWP_CMD_TAKER_PUBLISH_FINAL_SIG: c_uint = 15;

#[no_mangle]
/// # Safety
/// [in] `handle` must be valid.
/// [in] `reservation_id_ptr` points to 32 bytes.
/// [in] `payload_ptr` is optional when `payload_len == 0`.
/// [out] `out_result32` may be null when caller ignores command return value.
pub unsafe extern "C" fn eswp_orchestrator_step(
    handle: *mut FfiOrchestratorHandle,
    reservation_id_ptr: *const c_uchar,
    command_id: c_uint,
    payload_ptr: *const c_uchar,
    payload_len: c_uint,
    out_result32: *mut c_uchar,
) -> c_int {
    ffi_guard(|| {
        let handle = read_orchestrator_handle(handle)?;
        let reservation_id = read_reservation_id(reservation_id_ptr)?;
        let mut command_result = [0u8; 32];

        match command_id {
            ESWP_CMD_MAKER_CREATE_RESERVATION => {
                let created_at = decode_created_at(payload_ptr, payload_len)?;
                let result = handle
                    .orchestrator
                    .maker_create_reservation(ReservationParams {
                        reservation_id,
                        created_at,
                    })
                    .map_err(|err| FfiError::from(err.code()))?;
                command_result = result;
            }
            ESWP_CMD_MAKER_SET_HASHLOCK => handle
                .orchestrator
                .maker_set_hashlock(reservation_id)
                .map_err(|err| FfiError::from(err.code()))?,
            ESWP_CMD_MAKER_HANDLE_CONTEXT => handle
                .orchestrator
                .maker_handle_context(reservation_id)
                .map_err(|err| FfiError::from(err.code()))?,
            ESWP_CMD_MAKER_PUBLISH_PRESIG => handle
                .orchestrator
                .maker_publish_presig(reservation_id)
                .map_err(|err| FfiError::from(err.code()))?,
            ESWP_CMD_MAKER_HANDLE_FINAL_SIG => handle
                .orchestrator
                .maker_handle_final_sig(reservation_id)
                .map_err(|err| FfiError::from(err.code()))?,
            ESWP_CMD_MAKER_SETTLE => handle
                .orchestrator
                .maker_settle(reservation_id)
                .map_err(|err| FfiError::from(err.code()))?,
            ESWP_CMD_TAKER_ACCEPT_RESERVATION => handle
                .orchestrator
                .taker_accept_reservation(reservation_id)
                .map_err(|err| FfiError::from(err.code()))?,
            ESWP_CMD_TAKER_PUBLISH_CONTEXT => {
                let context = decode_context_payload(payload_ptr, payload_len)?;
                handle
                    .orchestrator
                    .taker_publish_context(reservation_id, context)
                    .map_err(|err| FfiError::from(err.code()))?
            }
            ESWP_CMD_TAKER_HANDLE_PRESIG => handle
                .orchestrator
                .taker_handle_presig(reservation_id)
                .map_err(|err| FfiError::from(err.code()))?,
            ESWP_CMD_TAKER_COMPLETE_AND_BROADCAST => {
                command_result = handle
                    .orchestrator
                    .taker_complete_and_broadcast(reservation_id)
                    .map_err(|err| FfiError::from(err.code()))?
            }
            ESWP_CMD_TAKER_PUBLISH_FINAL_SIG => {
                if payload_len != 32 {
                    return Err(FfiError::LengthInvalid);
                }
                let monero_tx_id = read_fixed::<32>(payload_ptr)?;
                handle
                    .orchestrator
                    .taker_publish_final_sig(reservation_id, monero_tx_id)
                    .map_err(|err| FfiError::from(err.code()))?
            }
            _ => return Err(FfiError::InvalidCommand),
        }

        if !out_result32.is_null() {
            ptr::copy_nonoverlapping(command_result.as_ptr(), out_result32, 32);
        }

        Ok(())
    })
}

#[no_mangle]
/// # Safety
/// [in] `handle` must be valid.
/// [out] `out_events_ptr` is caller-allocated for `out_events_capacity` entries.
/// [out] `out_events_len` receives the number of written entries.
pub unsafe extern "C" fn eswp_orchestrator_check_deadlines(
    handle: *mut FfiOrchestratorHandle,
    out_events_ptr: *mut EswpDeadlineEvent,
    out_events_capacity: c_uint,
    out_events_len: *mut c_uint,
) -> c_int {
    ffi_guard(|| {
        if out_events_len.is_null() {
            return Err(FfiError::NullPointer);
        }
        let handle = read_orchestrator_handle(handle)?;
        let events = handle
            .orchestrator
            .check_deadlines()
            .map_err(|err| FfiError::from(err.code()))?;
        if events.len() > out_events_capacity as usize {
            return Err(FfiError::CapacityInsufficient);
        }
        if events.is_empty() {
            *out_events_len = 0;
            return Ok(());
        }
        if out_events_ptr.is_null() {
            return Err(FfiError::NullPointer);
        }
        let out_slice = slice::from_raw_parts_mut(out_events_ptr, out_events_capacity as usize);
        for (idx, event) in events.iter().enumerate() {
            out_slice[idx] = EswpDeadlineEvent {
                reservation_id: event.reservation_id,
                deadline: event.deadline,
            };
        }
        *out_events_len = events.len() as c_uint;
        Ok(())
    })
}

#[no_mangle]
/// # Safety
/// [in][owned] `ptr` must be a library-owned buffer returned by this ABI.
/// Passing unknown pointers is ignored.
pub unsafe extern "C" fn eswp_free_buffer(ptr: *mut c_uchar, _len: c_uint) {
    if ptr.is_null() {
        return;
    }
    let len = BUFFER_ALLOCS
        .lock()
        .expect("buffer alloc mutex poisoned")
        .remove(&(ptr as usize));
    if let Some(len) = len {
        let slice_ptr = ptr::slice_from_raw_parts_mut(ptr, len);
        let _ = Box::from_raw(slice_ptr);
    }
}

#[no_mangle]
/// # Safety
/// [in][owned] `ptr` must be a library-owned string returned by this ABI.
/// Passing unknown pointers is ignored.
pub unsafe extern "C" fn eswp_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    let removed = STRING_ALLOCS
        .lock()
        .expect("string alloc mutex poisoned")
        .remove(&(ptr as usize));
    if removed {
        let _ = CString::from_raw(ptr);
    }
}

#[no_mangle]
/// # Safety
/// [in] `error_code` is a numeric error code from this ABI.
/// [out][owned] `out_message` receives a library-owned string; free via `eswp_free_string`.
pub unsafe extern "C" fn eswp_error_message(
    error_code: c_int,
    out_message: *mut *mut c_char,
) -> c_int {
    ffi_guard(|| {
        let text = format!("equalx ffi error {error_code}");
        write_owned_string(out_message, &text)
    })
}
