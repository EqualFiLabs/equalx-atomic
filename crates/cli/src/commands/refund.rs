use std::time::Duration;

use anyhow::{Context, Result};
use equalx_sdk::{auto_refund, AlloyHttpTransport, AutoRefundConfig, EscrowClient};
use clap::Args;
use hex;

use super::common::{format_tx_hash, parse_address, parse_hex_array, DryRunTransport};

#[derive(Clone, Debug, Args)]
pub struct RefundLocalArgs {
    /// Swap identifier hex (32 bytes).
    #[arg(long, value_name = "HEX64")]
    pub swap_id: String,
    /// ETH expiry timestamp (seconds since Unix epoch).
    #[arg(long, value_name = "SECS")]
    pub eth_expiry: u64,
    /// Extra buffer (seconds) to wait after expiry before refunding.
    #[arg(long, default_value_t = 0, value_name = "SECS")]
    pub buffer_secs: u64,
    /// Polling cadence while waiting for the deadline.
    #[arg(long, default_value_t = 30, value_name = "SECS")]
    pub poll_secs: u64,
    /// Escrow contract address.
    #[arg(long, value_name = "HEX40")]
    pub escrow: String,
    /// Optional gas limit for the refund transaction.
    #[arg(long)]
    pub gas_limit: Option<u64>,
    /// EVM JSON-RPC endpoint (required unless --dry-run).
    #[arg(long)]
    pub evm_rpc: Option<String>,
    /// Private key for the caller (required unless --dry-run).
    #[arg(long, value_name = "HEX64")]
    pub private_key: Option<String>,
    /// Do not submit transactions, only print calldata/value.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
}

pub fn run(args: RefundLocalArgs) -> Result<()> {
    let swap_id = parse_hex_array::<32>(&args.swap_id, "swap_id")?;
    let escrow_addr = parse_address(&args.escrow)?;
    let poll_secs = args.poll_secs.max(1);
    let config = AutoRefundConfig {
        swap_id,
        eth_expiry: args.eth_expiry,
        buffer_secs: args.buffer_secs,
        poll_interval: Duration::from_secs(poll_secs),
        gas_limit: args.gas_limit,
    };

    println!(
        "Monitoring expiry {} with buffer {}s (poll {}s) before refunding",
        args.eth_expiry, args.buffer_secs, poll_secs
    );

    if args.dry_run {
        let transport = DryRunTransport::default();
        let escrow = EscrowClient::new(escrow_addr, transport.clone());
        let tx_hash = auto_refund(&escrow, config)?;
        println!("refund tx hash: {}", format_tx_hash(tx_hash));
        if let Some(call) = transport.last_call() {
            println!(
                "dry-run call -> to: 0x{}, gas_limit: {}, value: {}, data: 0x{}",
                hex::encode(call.to),
                call.gas_limit.unwrap_or(0),
                call.value,
                hex::encode(&call.data)
            );
        }
    } else {
        let rpc = args
            .evm_rpc
            .as_ref()
            .context("--evm-rpc is required unless --dry-run")?;
        let pk = args
            .private_key
            .as_ref()
            .context("--private-key is required unless --dry-run")?;
        let transport = AlloyHttpTransport::new(rpc, pk)?;
        let escrow = EscrowClient::new(escrow_addr, transport);
        let tx_hash = auto_refund(&escrow, config)?;
        println!("refund tx hash: {}", format_tx_hash(tx_hash));
    }

    Ok(())
}
