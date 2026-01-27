use crate::{decompose_transaction, TxBlob, TxSkeleton};
use anyhow::{anyhow, Result};
use hex::decode;
pub use monero_rpc::{
    DescribeTransferParams, DescribeTransferResult, MoneroWalletRpc, SweepSingleParams,
    TransferDestination, TransferParams, TransferResult,
};

/// Bundle containing the wallet RPC transfer response and a parsed tx skeleton.
pub struct WalletTransfer {
    pub tx_blob: TxBlob,
    pub skeleton: TxSkeleton,
    pub transfer: TransferResult,
}

pub fn transfer_and_decompose(
    wallet: &MoneroWalletRpc,
    params: &TransferParams,
) -> Result<WalletTransfer> {
    let response = wallet.transfer(params)?;
    materialize_skeleton(response)
}

pub fn sweep_single_and_decompose(
    wallet: &MoneroWalletRpc,
    params: &SweepSingleParams,
) -> Result<WalletTransfer> {
    let response = wallet.sweep_single(params)?;
    materialize_skeleton(response)
}

pub fn describe_transfer(
    wallet: &MoneroWalletRpc,
    params: &DescribeTransferParams,
) -> Result<DescribeTransferResult> {
    wallet.describe_transfer(params).map_err(Into::into)
}

fn materialize_skeleton(response: TransferResult) -> Result<WalletTransfer> {
    let tx_blob_hex = response
        .tx_blob
        .as_ref()
        .ok_or_else(|| anyhow!("wallet response missing tx_blob; set get_tx_hex=true"))?;
    let tx_blob = decode(tx_blob_hex).map_err(|e| anyhow!("decode tx_blob hex: {e}"))?;
    let skeleton = decompose_transaction(&tx_blob)?;
    Ok(WalletTransfer {
        tx_blob,
        skeleton,
        transfer: response,
    })
}
