use adaptor_clsag::{
    complete as adaptor_complete, extract_t as adaptor_extract_t,
    make_pre_sig as adaptor_make_pre_sig, verify as adaptor_verify,
    wire::{ClsagFinalSigContainer, ClsagPreSig},
    ClsagCtx, EswpError, FinalSig, PreSig, SettlementCtx, SignerWitness, BACKEND_ID_CLSAG,
    WIRE_VERSION,
};
use alloy_primitives::{Address as AlloyAddress, Bytes, B256, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
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
use libc::{c_int, c_uchar, c_uint};
use monero_oxide::ringct::clsag::Clsag;
use std::{
    convert::TryFrom,
    io::Cursor,
    slice, str,
    sync::{Arc, Mutex},
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

#[derive(Debug)]
enum FfiError {
    NullPointer,
    LengthInvalid,
    Decode,
    SecretsInvalid,
    RingIndexOutOfRange,
    RingSizeUnsupported,
    CapacityInsufficient,
    Eswp(EswpError),
    Sdk(ErrorCode),
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
            Self::Eswp(err) => *err as c_int,
            Self::Sdk(err) => err.code() as c_int,
        }
    }
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
        wire_version: WIRE_VERSION,
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
        wire_version: WIRE_VERSION,
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
    a.chain_tag == b.chain_tag && a.position_key == b.position_key && a.settle_digest == b.settle_digest
}

unsafe fn read_bytes<'a>(ptr: *const c_uchar, len: usize) -> Result<&'a [u8], FfiError> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(FfiError::NullPointer);
    }
    Ok(slice::from_raw_parts(ptr, len))
}

unsafe fn read_fixed<const N: usize>(ptr: *const c_uchar) -> Result<[u8; N], FfiError> {
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
    let bytes = unsafe { read_fixed::<20>(ptr)? };
    Ok(AlloyAddress::from_slice(&bytes))
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
    WIRE_VERSION as c_uint
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
    use serde::Deserialize;
    use std::path::PathBuf;

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
    gas_limit: u64,
    out_data_ptr: *mut c_uchar,
    out_data_capacity: c_uint,
    out_data_len: *mut c_uint,
    out_value_ptr: *mut c_uchar,
    out_gas_limit: *mut u64,
) -> c_int {
    if escrow_ptr.is_null() || swap_id_ptr.is_null() || adaptor_secret_ptr.is_null() {
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
    let args = SettleArgs {
        swap_id,
        adaptor_secret,
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
