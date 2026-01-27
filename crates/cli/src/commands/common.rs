use std::sync::{Arc, Mutex};

use alloy_primitives::{keccak256, Address, Bytes, B256};
use anyhow::{anyhow, ensure, Result};
use equalx_sdk::{
    contracts::TxHash,
    error::ErrorCode,
    transport::{EvmCall, EvmTransport, EvmViewTransport},
};

use equalx_sdk::Result as SdkResult;

#[derive(Clone, Default)]
pub struct DryRunTransport {
    last: Arc<Mutex<Option<EvmCall>>>,
}

impl DryRunTransport {
    pub fn last_call(&self) -> Option<EvmCall> {
        self.last.lock().unwrap().clone()
    }
}

impl EvmTransport for DryRunTransport {
    fn send(&self, call: EvmCall) -> SdkResult<B256> {
        *self.last.lock().unwrap() = Some(call.clone());
        Ok(keccak256(&call.data))
    }
}

impl EvmViewTransport for DryRunTransport {
    fn call_view(&self, _call: EvmCall) -> SdkResult<Bytes> {
        Err(ErrorCode::BridgeTransportEvm)
    }
}

pub fn parse_address(value: &str) -> Result<Address> {
    let bytes = parse_hex_vec(value, "address")?;
    ensure!(
        bytes.len() == 20,
        "address must be 20 bytes, got {}",
        bytes.len()
    );
    Ok(Address::from_slice(&bytes))
}

pub fn parse_hex_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    let bytes = parse_hex_vec(value, label)?;
    ensure!(
        bytes.len() == N,
        "{label} must be {N} bytes, got {}",
        bytes.len()
    );
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn parse_hex_vec(value: &str, label: &str) -> Result<Vec<u8>> {
    let trimmed = value.trim().trim_start_matches("0x");
    hex::decode(trimmed).map_err(|e| anyhow!("decode {label}: {e}"))
}

pub fn format_tx_hash(hash: TxHash) -> String {
    format!("0x{}", hex::encode(hash.bytes()))
}

pub fn format_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}
