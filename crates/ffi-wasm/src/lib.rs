//! WebAssembly bindings exposing the EqualX SDK surface area.
//!
//! All exported functions copy their inputs and return freshly allocated `Vec<u8>` or
//! serialized objects so that JavaScript callers own the resulting memory. Settlement
//! contexts must be provided using the canonical encoding described in `docs/SDK-SPEC.md`
//! (`chain_tag_len || chain_tag || position_key_len || position_key || 32 || settle_digest`).

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
use equalx_sdk::{
    compute_key_image as sdk_compute_key_image, decode_events as sdk_decode_events,
    derive_subaddress as sdk_derive_subaddress, generate_evm_keypair as sdk_generate_evm_keypair,
    generate_monero_keypair as sdk_generate_monero_keypair, prepare_refund as sdk_prepare_refund,
    sign_evm_message as sdk_sign_evm_message, Address as SdkAddress, Backend as SdkBackend,
    EscrowClient, EscrowEvent, EscrowLog, EscrowRefundArgs, EventResult, EvmCall, EvmMessageSigner,
    EvmTransport, EvmViewTransport, LockErc20Args, LockEthArgs, PostTxHashArgs, QuoteBoardClient,
    QuoteCommitment, RefundParams, Result as SdkResult, SettleArgs,
    SettlementCtx as SdkSettlementCtx, TxHash,
};
use monero_oxide::ringct::clsag::Clsag;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::sync::{Arc, Mutex};
use wasm_bindgen::prelude::*;

const ADAPTOR_SCALAR_LEN: usize = 32;

type RingEntries = Vec<[u8; 32]>;
type CommitmentEntries = Vec<[u8; 32]>;

#[derive(Debug)]
enum WasmError {
    Message(String),
    Eswp(EswpError),
    Sdk(equalx_sdk::error::ErrorCode),
    Length,
    Decode,
}

impl From<EswpError> for WasmError {
    fn from(value: EswpError) -> Self {
        Self::Eswp(value)
    }
}

impl From<equalx_sdk::error::ErrorCode> for WasmError {
    fn from(value: equalx_sdk::error::ErrorCode) -> Self {
        Self::Sdk(value)
    }
}

impl std::fmt::Display for WasmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WasmError::Message(msg) => write!(f, "{msg}"),
            WasmError::Eswp(err) => write!(f, "eswp error: {:?}", err),
            WasmError::Sdk(err) => write!(f, "sdk error: {:?} ({})", err, err.code()),
            WasmError::Length => write!(f, "buffer length invalid"),
            WasmError::Decode => write!(f, "container decode failed"),
        }
    }
}

impl From<WasmError> for JsValue {
    fn from(value: WasmError) -> Self {
        JsValue::from_str(&value.to_string())
    }
}

fn wasm_err(msg: impl Into<String>) -> WasmError {
    WasmError::Message(msg.into())
}

fn quote_commitment_from_adaptor(adaptor_hash: [u8; 32]) -> QuoteCommitment {
    QuoteCommitment {
        adaptor_hash,
        m_digest: [0u8; 32],
        envelope: Bytes::new(),
    }
}

fn parse_ring_bytes(bytes: &[u8]) -> Result<(RingEntries, CommitmentEntries), WasmError> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(32) {
        return Err(wasm_err("ring bytes must be a non-empty multiple of 32"));
    }

    if bytes.len().is_multiple_of(64) {
        let n = bytes.len() / 64;
        if n == 0 || n > u8::MAX as usize {
            return Err(wasm_err("ring size unsupported"));
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
            return Err(wasm_err("ring size unsupported"));
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

fn parse_settlement_ctx(bytes: &[u8]) -> Result<SettlementCtxParts, WasmError> {
    use std::str;

    let mut cursor = 0usize;
    let chain_len = *bytes.get(cursor).ok_or(WasmError::Length)? as usize;
    cursor += 1;
    if bytes.len() < cursor + chain_len {
        return Err(WasmError::Length);
    }
    let chain_tag = str::from_utf8(&bytes[cursor..cursor + chain_len])
        .map_err(|_| wasm_err("chain tag must be utf-8"))?
        .to_owned();
    cursor += chain_len;

    let position_len = *bytes.get(cursor).ok_or(WasmError::Length)? as usize;
    cursor += 1;
    if position_len != 32 {
        return Err(wasm_err("position_key must be 32 bytes"));
    }
    if bytes.len() < cursor + position_len {
        return Err(WasmError::Length);
    }
    let mut position_key = [0u8; 32];
    position_key.copy_from_slice(&bytes[cursor..cursor + position_len]);
    cursor += position_len;

    let settle_len = *bytes.get(cursor).ok_or(WasmError::Length)? as usize;
    cursor += 1;
    if settle_len != 32 {
        return Err(wasm_err("settle digest must be 32 bytes"));
    }
    if bytes.len() < cursor + settle_len {
        return Err(WasmError::Length);
    }
    let mut settle_digest = [0u8; 32];
    settle_digest.copy_from_slice(&bytes[cursor..cursor + settle_len]);
    cursor += settle_len;

    if cursor != bytes.len() {
        return Err(wasm_err("ctx contains trailing bytes"));
    }

    Ok(SettlementCtxParts {
        chain_tag,
        position_key,
        settle_digest,
    })
}

fn decode_clsag_settlement_ctx(bytes: &[u8]) -> Result<SettlementCtx, WasmError> {
    let parts = parse_settlement_ctx(bytes)?;
    Ok(SettlementCtx {
        chain_tag: parts.chain_tag,
        position_key: parts.position_key,
        settle_digest: parts.settle_digest,
    })
}

fn decode_sdk_settlement_ctx(bytes: &[u8]) -> Result<SdkSettlementCtx, WasmError> {
    let parts = parse_settlement_ctx(bytes)?;
    SdkSettlementCtx::new(parts.chain_tag, parts.position_key, parts.settle_digest)
        .map_err(WasmError::from)
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

fn take_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], WasmError> {
    if bytes.len() < *cursor + N {
        return Err(WasmError::Length);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*cursor..*cursor + N]);
    *cursor += N;
    Ok(out)
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, WasmError> {
    let raw = take_array::<4>(bytes, cursor)?;
    Ok(u32::from_le_bytes(raw))
}

fn to_array<const N: usize>(bytes: &[u8], label: &str) -> Result<[u8; N], WasmError> {
    if bytes.len() != N {
        return Err(wasm_err(format!("{label} must be {N} bytes")));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn encode_pre_bytes(
    msg: &[u8],
    ctx: &ClsagCtx,
    pre: &PreSig,
    swap_id: &[u8; 32],
    tau: &[u8; 32],
) -> Result<Vec<u8>, WasmError> {
    let ring_size = u8::try_from(ctx.n).map_err(|_| wasm_err("ring size exceeds u8"))?;
    let ring_bytes: Vec<u8> = ctx.ring_keys.iter().flat_map(|key| key.to_vec()).collect();

    let commitments_len = u32::try_from(ctx.ring_commitments.len())
        .map_err(|_| wasm_err("ring commitments length overflow"))?;
    let responses_len =
        u32::try_from(pre.s_tilde.len()).map_err(|_| wasm_err("response vector overflow"))?;

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
        resp_index: u8::try_from(pre.j).map_err(|_| wasm_err("resp index overflow"))?,
        reserved0: 0,
        m: msg.to_vec(),
        ring_bytes,
        pre_hash: pre.pre_hash,
        ctx: pre.ctx.clone(),
        proof_bytes_sans_resp: proof,
    };

    presig
        .encode()
        .map_err(|err: EswpError| WasmError::from(err))
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

fn decode_pre_bytes(bytes: &[u8]) -> Result<DecodedPre, WasmError> {
    let container = ClsagPreSig::decode(bytes).map_err(WasmError::from)?;
    let ring_size = container.ring_size as usize;
    if ring_size == 0 {
        return Err(WasmError::Length);
    }
    if container.ring_bytes.len() != ring_size * 32 {
        return Err(WasmError::Length);
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
        usize::try_from(read_u32(proof, &mut cursor)?).map_err(|_| WasmError::Length)?;
    let mut ring_commitments = Vec::new();
    if commitments_len > 0 {
        if commitments_len != ring_size {
            return Err(WasmError::Length);
        }
        for _ in 0..commitments_len {
            ring_commitments.push(take_array::<32>(proof, &mut cursor)?);
        }
    }
    let c1_tilde = take_array::<32>(proof, &mut cursor)?;
    let d_tilde = take_array::<32>(proof, &mut cursor)?;
    let pseudo_out = take_array::<32>(proof, &mut cursor)?;
    let responses_len =
        usize::try_from(read_u32(proof, &mut cursor)?).map_err(|_| WasmError::Length)?;
    if responses_len != ring_size {
        return Err(WasmError::Length);
    }
    let mut s_tilde = Vec::with_capacity(responses_len);
    for _ in 0..responses_len {
        s_tilde.push(take_array::<32>(proof, &mut cursor)?);
    }
    let tau_length = read_u32(proof, &mut cursor)?;
    if tau_length != ADAPTOR_SCALAR_LEN as u32 {
        return Err(WasmError::Length);
    }
    let _tau = take_array::<32>(proof, &mut cursor)?;
    if cursor != proof.len() {
        return Err(WasmError::Decode);
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

fn encode_final_bytes(pre: &PreSig, final_sig: &FinalSig) -> Result<Vec<u8>, WasmError> {
    let mut clsag_bytes = Vec::new();
    final_sig
        .clsag
        .write(&mut clsag_bytes)
        .map_err(|_| WasmError::Decode)?;

    let mut final_bytes = clsag_bytes;
    final_bytes.extend_from_slice(&final_sig.pseudo_out);

    let container = ClsagFinalSigContainer {
        magic: adaptor_clsag::wire::MAGIC_CLSAG_FINAL,
        wire_version: WIRE_VERSION,
        backend: BACKEND_ID_CLSAG,
        resp_index: u8::try_from(pre.j).map_err(|_| wasm_err("resp index overflow"))?,
        final_sig: final_bytes,
        pre_hash: pre.pre_hash,
        ctx: pre.ctx.clone(),
    };

    container.encode().map_err(WasmError::from)
}

fn decode_final_bytes(bytes: &[u8], decoys: usize) -> Result<DecodedFinal, WasmError> {
    use std::io::Cursor;

    let container = ClsagFinalSigContainer::decode(bytes).map_err(WasmError::from)?;
    if container.final_sig.len() < 32 {
        return Err(WasmError::Length);
    }
    let split_at = container.final_sig.len() - 32;
    let (clsag_bytes, pseudo_bytes) = container.final_sig.split_at(split_at);
    let mut cursor = Cursor::new(clsag_bytes);
    let clsag = Clsag::read(decoys, &mut cursor).map_err(|_| WasmError::Decode)?;
    if usize::try_from(cursor.position()).map_err(|_| WasmError::Decode)? != clsag_bytes.len() {
        return Err(WasmError::Decode);
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

fn backend_from_id(id: u8) -> Result<SdkBackend, WasmError> {
    match id {
        x if x == SdkBackend::Clsag as u8 => Ok(SdkBackend::Clsag),
        _ => Err(wasm_err("backend unsupported")),
    }
}

fn u256_from_be(bytes: &[u8]) -> Result<U256, WasmError> {
    if bytes.len() != 32 {
        return Err(wasm_err("amount must be 32 bytes (big endian)"));
    }
    Ok(U256::from_be_slice(bytes))
}

fn u256_to_vec(value: &U256) -> Vec<u8> {
    value.to_be_bytes::<32>().to_vec()
}

fn gas_option(value: Option<u64>) -> Option<u64> {
    value.filter(|v| *v != 0)
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
            .map_err(|_| equalx_sdk::error::ErrorCode::SignatureInvalid)?;
        Ok(Bytes::from(signature.as_bytes().to_vec()))
    }

    fn signer_address(&self) -> AlloyAddress {
        self.signer.address()
    }
}

fn capture_escrow_call<F>(escrow: SdkAddress, f: F) -> Result<EvmCall, WasmError>
where
    F: FnOnce(EscrowClient<CaptureTransport>) -> SdkResult<TxHash>,
{
    let transport = CaptureTransport::default();
    let client = EscrowClient::new(escrow, transport.clone());
    f(client).map_err(WasmError::from)?;
    transport.take().ok_or(WasmError::Decode)
}

#[derive(Serialize)]
struct CallResult {
    data: Vec<u8>,
    value_be: Vec<u8>,
    gas_limit: u64,
}

fn call_to_js(call: &EvmCall) -> Result<JsValue, WasmError> {
    let result = CallResult {
        data: call.data.as_ref().to_vec(),
        value_be: u256_to_vec(&call.value),
        gas_limit: call.gas_limit.unwrap_or(0),
    };
    serde_wasm_bindgen::to_value(&result).map_err(|_| WasmError::Decode)
}

#[derive(Serialize)]
struct RefundResult {
    tx_bytes: Vec<u8>,
    lock_time: u64,
}

#[derive(Serialize)]
struct SubaddressResult {
    address: String,
    derived_spend: Vec<u8>,
}

#[derive(Serialize)]
struct EvmKeypair {
    private_key: Vec<u8>,
    address: Vec<u8>,
}

#[derive(Deserialize)]
struct JsEscrowLog {
    kind: u8,
    backend: u8,
    swap_id: Vec<u8>,
    amount_be: Vec<u8>,
}

#[derive(Serialize)]
struct JsEscrowEvent {
    digest: Vec<u8>,
    swap_id: Vec<u8>,
    amount_be: Vec<u8>,
    backend: u8,
    kind: u8,
}

fn parse_logs(value: &JsValue) -> Result<Vec<EscrowLog>, WasmError> {
    let logs: Vec<JsEscrowLog> =
        serde_wasm_bindgen::from_value(value.clone()).map_err(|_| WasmError::Decode)?;
    logs.into_iter()
        .map(|log| {
            let swap_id = to_array::<32>(&log.swap_id, "swap_id")?;
            let amount = u256_from_be(&log.amount_be)?;
            Ok(EscrowLog {
                kind: log.kind,
                swap_id,
                amount,
                backend: log.backend,
            })
        })
        .collect()
}

fn events_to_js(events: &[EventResult]) -> Result<JsValue, WasmError> {
    let out: Vec<JsEscrowEvent> = events
        .iter()
        .map(|evt| match &evt.event {
            EscrowEvent::SwapLocked {
                swap_id,
                amount,
                backend,
            } => JsEscrowEvent {
                digest: evt.digest.to_vec(),
                swap_id: swap_id.to_vec(),
                amount_be: u256_to_vec(amount),
                backend: *backend as u8,
                kind: 0,
            },
            EscrowEvent::SwapSettled { swap_id, backend } => JsEscrowEvent {
                digest: evt.digest.to_vec(),
                swap_id: swap_id.to_vec(),
                amount_be: vec![0u8; 32],
                backend: *backend as u8,
                kind: 1,
            },
            EscrowEvent::SwapRefunded { swap_id, backend } => JsEscrowEvent {
                digest: evt.digest.to_vec(),
                swap_id: swap_id.to_vec(),
                amount_be: vec![0u8; 32],
                backend: *backend as u8,
                kind: 2,
            },
        })
        .collect();
    serde_wasm_bindgen::to_value(&out).map_err(|_| WasmError::Decode)
}

#[wasm_bindgen]
pub fn eswp_wire_version_js() -> u16 {
    WIRE_VERSION
}

#[wasm_bindgen]
pub fn eswp_backend_clsag_id_js() -> u8 {
    BACKEND_ID_CLSAG
}

#[wasm_bindgen]
pub fn eswp_generate_monero_keypair_js() -> Result<Vec<u8>, JsValue> {
    let (spend, view) = sdk_generate_monero_keypair().map_err(WasmError::from)?;
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&spend);
    out.extend_from_slice(&view);
    Ok(out)
}

#[wasm_bindgen]
pub fn eswp_monero_derive_subaddress_js(
    view: &[u8],
    spend: &[u8],
    index: u32,
) -> Result<JsValue, JsValue> {
    let view = to_array::<32>(view, "view key")?;
    let spend = to_array::<32>(spend, "spend key")?;
    let (address, derived) =
        sdk_derive_subaddress(&view, &spend, index).map_err(WasmError::from)?;
    let payload = SubaddressResult {
        address,
        derived_spend: derived.to_vec(),
    };
    serde_wasm_bindgen::to_value(&payload).map_err(|_| WasmError::Decode.into())
}

#[wasm_bindgen]
pub fn eswp_monero_compute_key_image_js(
    tx_pub_key: &[u8],
    spend: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let tx = to_array::<32>(tx_pub_key, "tx pub key")?;
    let spend = to_array::<32>(spend, "spend key")?;
    let key_image = sdk_compute_key_image(&tx, &spend).map_err(WasmError::from)?;
    Ok(key_image.to_vec())
}

#[wasm_bindgen]
pub fn eswp_generate_evm_keypair_js() -> Result<JsValue, JsValue> {
    let (priv_key, address) = sdk_generate_evm_keypair().map_err(WasmError::from)?;
    let payload = EvmKeypair {
        private_key: priv_key.to_vec(),
        address: <[u8; 20]>::from(address).to_vec(),
    };
    serde_wasm_bindgen::to_value(&payload).map_err(|_| WasmError::Decode.into())
}

#[wasm_bindgen]
pub fn eswp_sign_evm_message_js(priv_key: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    let priv_key = to_array::<32>(priv_key, "private key")?;
    let message = to_array::<32>(message, "message")?;
    sdk_sign_evm_message(&priv_key, &message)
        .map(|sig| sig.to_vec())
        .map_err(WasmError::from)
        .map_err(Into::into)
}

#[wasm_bindgen]
pub fn eswp_clsag_make_pre_sig_js(
    msg: &[u8],
    ring: &[u8],
    i_star: u32,
    swap_id: &[u8],
    ctx_bytes: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if swap_id.len() != 32 {
        return Err(wasm_err("swap_id must be 32 bytes").into());
    }

    let (ring_keys, ring_commitments) = parse_ring_bytes(ring)?;
    if ring_keys.len() < 5 {
        return Err(wasm_err("ring must contain at least 5 members").into());
    }

    let ring_size = ring_keys.len();
    let i_star = i_star as usize;
    if i_star >= ring_size {
        return Err(wasm_err("i_star out of range for ring").into());
    }

    let sctx = decode_clsag_settlement_ctx(ctx_bytes)?;

    let mut swap_id_bytes = [0u8; 32];
    swap_id_bytes.copy_from_slice(swap_id);

    let witness = derive_witness(i_star);
    let key_image = witness.key_image_bytes();
    let clsag_ctx = ClsagCtx {
        ring_keys,
        ring_commitments,
        key_image,
        n: ring_size,
    };

    let (pre, tau) = adaptor_make_pre_sig(&clsag_ctx, &witness, msg, &swap_id_bytes, sctx)
        .map_err(WasmError::from)?;

    encode_pre_bytes(msg, &clsag_ctx, &pre, &swap_id_bytes, &tau).map_err(Into::into)
}

#[wasm_bindgen]
pub fn eswp_clsag_complete_js(pre_bytes: &[u8], secret: &[u8]) -> Result<Vec<u8>, JsValue> {
    if secret.len() != ADAPTOR_SCALAR_LEN {
        return Err(wasm_err("secret scalar must be 32 bytes").into());
    }
    let decoded_pre = decode_pre_bytes(pre_bytes)?;
    let mut tau = [0u8; 32];
    tau.copy_from_slice(secret);
    let final_sig = adaptor_complete(&decoded_pre.pre, &tau);
    encode_final_bytes(&decoded_pre.pre, &final_sig).map_err(Into::into)
}

#[wasm_bindgen]
pub fn eswp_clsag_verify_js(pre_bytes: &[u8], final_bytes: &[u8]) -> Result<bool, JsValue> {
    let decoded_pre = decode_pre_bytes(pre_bytes)?;
    let decoys = decoded_pre.pre.s_tilde.len();
    let decoded_final = decode_final_bytes(final_bytes, decoys)?;
    if decoded_final.resp_index != decoded_pre.pre.j {
        return Err(WasmError::from(EswpError::RespIndexUnadmitted).into());
    }
    if decoded_final.pre_hash != decoded_pre.pre.pre_hash {
        return Err(WasmError::from(EswpError::PreHashMismatch).into());
    }
    if decoded_final.ctx != decoded_pre.pre.ctx {
        return Err(WasmError::from(EswpError::CtxMismatch).into());
    }
    let ok = adaptor_verify(&decoded_pre.ctx, &decoded_pre.msg, &decoded_final.final_sig);
    Ok(ok)
}

#[wasm_bindgen]
pub fn eswp_clsag_extract_t_js(pre_bytes: &[u8], final_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    let decoded_pre = decode_pre_bytes(pre_bytes)?;
    let decoys = decoded_pre.pre.s_tilde.len();
    let decoded_final = decode_final_bytes(final_bytes, decoys)?;
    if decoded_final.resp_index != decoded_pre.pre.j {
        return Err(WasmError::from(EswpError::RespIndexUnadmitted).into());
    }
    if decoded_final.pre_hash != decoded_pre.pre.pre_hash {
        return Err(WasmError::from(EswpError::PreHashMismatch).into());
    }
    if decoded_final.ctx != decoded_pre.pre.ctx {
        return Err(WasmError::from(EswpError::CtxMismatch).into());
    }
    let t = adaptor_extract_t(&decoded_pre.pre, &decoded_final.final_sig);
    Ok(t.to_vec())
}

#[wasm_bindgen]
pub fn eswp_prepare_refund_js(
    ctx_bytes: &[u8],
    swap_id: &[u8],
    xmr_lock_height: u64,
    eth_expiry: u64,
    delta: u64,
    template: &[u8],
) -> Result<JsValue, JsValue> {
    let ctx = decode_sdk_settlement_ctx(ctx_bytes)?;
    let swap_id = to_array::<32>(swap_id, "swap_id")?;
    let params = RefundParams {
        swap_id,
        xmr_lock_height,
        eth_expiry,
        delta,
        template: template.to_vec(),
    };
    let refund = sdk_prepare_refund(&ctx, params).map_err(WasmError::from)?;
    let payload = RefundResult {
        tx_bytes: refund.tx_bytes,
        lock_time: refund.lock_time,
    };
    serde_wasm_bindgen::to_value(&payload).map_err(|_| WasmError::Decode.into())
}

fn read_address(bytes: &[u8]) -> Result<SdkAddress, WasmError> {
    if bytes.len() != 20 {
        return Err(wasm_err("address must be 20 bytes"));
    }
    Ok(AlloyAddress::from_slice(bytes))
}

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn eswp_escrow_lock_eth_call_js(
    escrow: &[u8],
    swap_id: &[u8],
    taker: &[u8],
    adaptor_hash: &[u8],
    maker: &[u8],
    amount_be: &[u8],
    tip_be: &[u8],
    expiry: u64,
    backend_id: u8,
    settle_digest: &[u8],
    gas_limit: Option<u64>,
) -> Result<JsValue, JsValue> {
    let escrow_addr = read_address(escrow)?;
    let swap_id = to_array::<32>(swap_id, "swap_id")?;
    let taker = read_address(taker)?;
    let adaptor_hash = to_array::<32>(adaptor_hash, "adaptor_hash")?;
    let maker = read_address(maker)?;
    let amount = u256_from_be(amount_be)?;
    let tip = u256_from_be(tip_be)?;
    let backend = backend_from_id(backend_id)?;
    let settle_digest = to_array::<32>(settle_digest, "settle_digest")?;
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
    let call = capture_escrow_call(escrow_addr, move |client| client.lock_eth(args))?;
    call_to_js(&call).map_err(Into::into)
}

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn eswp_escrow_lock_erc20_call_js(
    escrow: &[u8],
    swap_id: &[u8],
    taker: &[u8],
    token: &[u8],
    amount_be: &[u8],
    tip_be: &[u8],
    adaptor_hash: &[u8],
    maker: &[u8],
    expiry: u64,
    backend_id: u8,
    settle_digest: &[u8],
    permit: &[u8],
    gas_limit: Option<u64>,
) -> Result<JsValue, JsValue> {
    let escrow_addr = read_address(escrow)?;
    let swap_id = to_array::<32>(swap_id, "swap_id")?;
    let taker = read_address(taker)?;
    let token = read_address(token)?;
    let amount = u256_from_be(amount_be)?;
    let tip = u256_from_be(tip_be)?;
    let adaptor_hash = to_array::<32>(adaptor_hash, "adaptor_hash")?;
    let maker = read_address(maker)?;
    let backend = backend_from_id(backend_id)?;
    let settle_digest = to_array::<32>(settle_digest, "settle_digest")?;
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
        permit: Bytes::from(permit.to_vec()),
        gas_limit: gas_option(gas_limit),
    };
    let call = capture_escrow_call(escrow_addr, move |client| client.lock_erc20(args))?;
    call_to_js(&call).map_err(Into::into)
}

#[wasm_bindgen]
pub fn eswp_escrow_settle_call_js(
    escrow: &[u8],
    swap_id: &[u8],
    adaptor_secret: &[u8],
    gas_limit: Option<u64>,
) -> Result<JsValue, JsValue> {
    let escrow_addr = read_address(escrow)?;
    let swap_id = to_array::<32>(swap_id, "swap_id")?;
    let adaptor_secret = to_array::<32>(adaptor_secret, "adaptor_secret")?;
    let args = SettleArgs {
        swap_id,
        adaptor_secret,
        gas_limit: gas_option(gas_limit),
    };
    let call = capture_escrow_call(escrow_addr, move |client| client.settle(args))?;
    call_to_js(&call).map_err(Into::into)
}

#[wasm_bindgen]
pub fn eswp_escrow_refund_call_js(
    escrow: &[u8],
    swap_id: &[u8],
    gas_limit: Option<u64>,
) -> Result<JsValue, JsValue> {
    let escrow_addr = read_address(escrow)?;
    let swap_id = to_array::<32>(swap_id, "swap_id")?;
    let args = EscrowRefundArgs {
        swap_id,
        gas_limit: gas_option(gas_limit),
    };
    let call = capture_escrow_call(escrow_addr, move |client| client.refund(args))?;
    call_to_js(&call).map_err(Into::into)
}

#[wasm_bindgen]
pub fn eswp_decode_escrow_events_js(
    ctx_bytes: &[u8],
    logs_value: JsValue,
) -> Result<JsValue, JsValue> {
    let ctx = decode_sdk_settlement_ctx(ctx_bytes)?;
    let logs = parse_logs(&logs_value)?;
    let events = sdk_decode_events(&ctx, &logs).map_err(WasmError::from)?;
    events_to_js(&events).map_err(Into::into)
}

#[wasm_bindgen]
pub fn eswp_post_tx_hash_call_js(
    board: &[u8],
    swap_id: &[u8],
    monero_tx_hash: &[u8],
    tau_pub: &[u8],
    evm_privkey: &[u8],
    gas_limit: Option<u64>,
) -> Result<JsValue, JsValue> {
    let board_addr = read_address(board)?;
    let swap_id = to_array::<32>(swap_id, "swap_id")?;
    let monero_tx_hash = to_array::<32>(monero_tx_hash, "monero_tx_hash")?;
    let priv_bytes = to_array::<32>(evm_privkey, "evm_privkey")?;
    let signer = PrivateKeySigner::from_slice(&priv_bytes)
        .map_err(|_| wasm_err("invalid EVM private key"))?;
    let transport = CaptureSignerTransport::new(signer);
    let client = QuoteBoardClient::new(board_addr, transport.clone());
    let args = PostTxHashArgs {
        swap_id,
        monero_tx_hash,
        tau_pub,
    };
    client.post_tx_hash(args).map_err(WasmError::from)?;
    let mut call = transport.take().ok_or(WasmError::Decode)?;
    if let Some(gas) = gas_limit {
        call.gas_limit = Some(gas);
    }
    call_to_js(&call).map_err(Into::into)
}
