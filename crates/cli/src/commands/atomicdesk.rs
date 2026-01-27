use std::{
    fmt, fs,
    io::{self, Read},
    path::PathBuf,
    time::Duration,
};

use alloy_primitives::{Address, Bytes, FixedBytes, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types::{BlockNumberOrTag, Filter, Log};
use alloy_sol_types::{sol, SolValue};
use anyhow::{anyhow, Context, Result};
use equalx_sdk::{AlloyHttpTransport, KeyRegistryClient, MailboxClient, PublishEnvelopeArgs};
use clap::{ArgGroup, Args, Subcommand, ValueEnum, ValueHint};
use hex;
use presig_envelope::{
    decrypt_presig, encrypt_presig, DecryptRequest, EncryptRequest, Envelope, EnvelopeContext,
};
use serde_json::{self, json};
use tokio::time::sleep;
use watcher::evm::{
    decode_atomic_reservation_created, decode_hashlock_set, decode_reservation_created,
    decode_reservation_refunded, decode_reservation_settled,
};

use crate::commands::common::{
    format_hex, format_tx_hash, parse_address, parse_hex_array, parse_hex_vec, DryRunTransport,
};

sol! {
    struct TxProofEnvelope {
        bytes32 reservationId;
        bytes32 moneroTxId;
        bytes extra;
    }
}

const VIEW_ONLY_PRIVATE_KEY: &str =
    "0x1000000000000000000000000000000000000000000000000000000000000001";

#[derive(Clone, Debug, Args)]
pub struct AtomicDeskCli {
    #[command(subcommand)]
    command: AtomicDeskCommand,
}

#[derive(Clone, Debug, Subcommand)]
pub enum AtomicDeskCommand {
    /// Build an encrypted taker context envelope
    EncryptContext(EncryptArgs),
    /// Desk publishes the presignature envelope
    PublishPresig(PublishArgs),
    /// Publish a TxProof (reservationId + Monero txid)
    TxProof(TxProofArgs),
    /// Fetch + decrypt a TxProof envelope for a reservation
    DecryptTxProof(DecryptTxProofArgs),
    /// Register an EncPubRegistry key
    RegisterKey(RegisterKeyArgs),
    /// Show a registered EncPubRegistry key
    ShowKey(ShowKeyArgs),
    /// Stream Router + SettlementEscrow events
    Watch(WatchArgs),
}

pub fn run(cli: AtomicDeskCli) -> Result<()> {
    match cli.command {
        AtomicDeskCommand::EncryptContext(args) => handle_encrypt(args),
        AtomicDeskCommand::PublishPresig(args) => handle_publish_presig(args),
        AtomicDeskCommand::TxProof(args) => handle_txproof(args),
        AtomicDeskCommand::DecryptTxProof(args) => handle_decrypt_txproof(args),
        AtomicDeskCommand::RegisterKey(args) => handle_register_key(args),
        AtomicDeskCommand::ShowKey(args) => handle_show_key(args),
        AtomicDeskCommand::Watch(args) => tokio_runtime()?.block_on(handle_watch(args)),
    }
}

fn tokio_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Runtime::new().map_err(|err| anyhow!("runtime init: {err:?}"))
}

#[derive(Clone, Debug, Args)]
#[command(group = ArgGroup::new("presig_source").required(true))]
pub struct EncryptArgs {
    #[command(flatten)]
    context: ContextArgs,
    /// Hex-encoded 33-byte taker pubkey.
    #[arg(long, value_name = "HEX33")]
    taker_pubkey: String,
    /// Optional 32-byte maker ephemeral secret key (hex). Random if omitted.
    #[arg(long, value_name = "HEX32")]
    maker_ephemeral: Option<String>,
    /// Hex string of presig bytes.
    #[arg(long, value_name = "HEX", group = "presig_source")]
    presig_hex: Option<String>,
    /// Path to file containing presig bytes.
    #[arg(long, value_name = "PATH", group = "presig_source")]
    presig_file: Option<PathBuf>,
    /// Read presig from stdin (raw bytes).
    #[arg(long, group = "presig_source")]
    presig_stdin: bool,
    /// Output format.
    #[arg(long, default_value_t = OutputFormat::Json)]
    format: OutputFormat,
    /// Optional file to write output to.
    #[arg(long)]
    output_file: Option<PathBuf>,
    /// Emit derived envelope parts (key/nonce/aad).
    #[arg(long, default_value_t = false)]
    emit_parts: bool,
}

#[derive(Clone, Debug, Args)]
#[command(group = ArgGroup::new("publish_presig").required(true))]
pub struct PublishArgs {
    #[command(flatten)]
    context: ContextArgs,
    /// Hex-encoded 33-byte taker pubkey.
    #[arg(long, value_name = "HEX33")]
    taker_pubkey: String,
    /// Optional 32-byte maker ephemeral secret key (hex). Random if omitted.
    #[arg(long, value_name = "HEX32")]
    maker_ephemeral: Option<String>,
    /// Hex string of presig bytes.
    #[arg(long, value_name = "HEX", group = "publish_presig")]
    presig_hex: Option<String>,
    /// Path to file containing presig bytes.
    #[arg(long, value_name = "PATH", group = "publish_presig")]
    presig_file: Option<PathBuf>,
    /// Read presig from stdin (raw bytes).
    #[arg(long, group = "publish_presig")]
    presig_stdin: bool,
    /// Optional file to dump the raw envelope bytes (hex).
    #[arg(long, value_hint = ValueHint::FilePath)]
    envelope_out: Option<PathBuf>,
    /// Skip broadcasting the transaction (emit envelope only).
    #[arg(long, default_value_t = false)]
    no_broadcast: bool,
    /// Mailbox address (0x-hex).
    #[arg(long, value_name = "HEX40")]
    mailbox: String,
    /// RPC URL for posting.
    #[arg(long)]
    rpc_url: Option<String>,
    /// Private key used to sign the post transaction.
    #[arg(long, value_name = "HEX64")]
    private_key: Option<String>,
    /// Emit derived envelope parts (key/nonce/aad) to stdout for inspection.
    #[arg(long, default_value_t = false)]
    emit_parts: bool,
}

#[derive(Clone, Debug, Args)]
pub struct TxProofArgs {
    #[command(flatten)]
    context: ContextArgs,
    #[arg(long, value_name = "HEX64")]
    monero_tx_id: String,
    #[arg(long, value_name = "HEX33")]
    desk_pubkey: String,
    #[arg(long, value_name = "HEX32")]
    taker_secret: String,
    /// Optional extra metadata (hex-encoded bytes)
    #[arg(long, value_name = "HEX")]
    extra: Option<String>,
    #[arg(long, value_name = "HEX40")]
    mailbox: String,
    #[arg(long)]
    rpc_url: Option<String>,
    #[arg(long, value_name = "HEX64")]
    private_key: Option<String>,
    #[arg(long, default_value_t = false)]
    dry_run: bool,
    /// Optional file to dump the raw envelope bytes (hex).
    #[arg(long, value_hint = ValueHint::FilePath)]
    envelope_out: Option<PathBuf>,
    /// Skip broadcasting the transaction (emit envelope only).
    #[arg(long, default_value_t = false)]
    no_broadcast: bool,
    #[arg(long, default_value_t = false)]
    emit_parts: bool,
}

#[derive(Clone, Debug, Args)]
pub struct DecryptTxProofArgs {
    #[command(flatten)]
    context: ContextArgs,
    #[arg(long, value_name = "HEX40")]
    mailbox: String,
    #[arg(long, value_name = "HEX32")]
    desk_secret: String,
    #[arg(long)]
    rpc_url: Option<String>,
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

#[derive(Clone, Debug, Args)]
pub struct RegisterKeyArgs {
    #[arg(long, value_name = "HEX40")]
    registry: String,
    #[arg(long, value_name = "HEX33")]
    pubkey: String,
    #[arg(long)]
    rpc_url: Option<String>,
    #[arg(long, value_name = "HEX64")]
    private_key: Option<String>,
    #[arg(long, default_value_t = 200_000)]
    gas_limit: u64,
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

#[derive(Clone, Debug, Args)]
pub struct ShowKeyArgs {
    #[arg(long, value_name = "HEX40")]
    registry: String,
    #[arg(long, value_name = "HEX40")]
    owner: String,
    #[arg(long)]
    rpc_url: Option<String>,
}

#[derive(Clone, Debug, Args)]
pub struct WatchArgs {
    #[arg(long, value_name = "HEX40")]
    atomic_desk: String,
    #[arg(long, value_name = "HEX40")]
    settlement_escrow: String,
    #[arg(long)]
    rpc_url: Option<String>,
    #[arg(long, default_value_t = 0)]
    from_block: u64,
    #[arg(long)]
    to_block: Option<u64>,
    #[arg(long, default_value_t = 10)]
    poll_seconds: u64,
    #[arg(long, default_value_t = false)]
    follow: bool,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum OutputFormat {
    Json,
    Hex,
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Hex => write!(f, "hex"),
        }
    }
}

#[derive(Clone, Debug, Args)]
pub struct ContextArgs {
    #[arg(long)]
    chain_id: u64,
    #[arg(long, value_name = "HEX40")]
    escrow: String,
    #[arg(long, value_name = "HEX64")]
    swap_id: String,
    #[arg(long, value_name = "HEX64")]
    settle_digest: String,
    #[arg(long, value_name = "HEX64")]
    m_digest: String,
    #[arg(long, value_name = "HEX40")]
    maker: String,
    #[arg(long, value_name = "HEX40")]
    taker: String,
    #[arg(long, default_value_t = 1)]
    version: u8,
}

#[derive(Clone, Debug)]
struct PresigSource {
    presig_hex: Option<String>,
    presig_file: Option<PathBuf>,
    presig_stdin: bool,
}

impl PresigSource {
    fn from_encrypt(opts: &EncryptArgs) -> Self {
        Self {
            presig_hex: opts.presig_hex.clone(),
            presig_file: opts.presig_file.clone(),
            presig_stdin: opts.presig_stdin,
        }
    }

    fn from_publish(opts: &PublishArgs) -> Self {
        Self {
            presig_hex: opts.presig_hex.clone(),
            presig_file: opts.presig_file.clone(),
            presig_stdin: opts.presig_stdin,
        }
    }
}

fn handle_encrypt(opts: EncryptArgs) -> Result<()> {
    let context = opts.context.to_context()?;
    let taker_pub = parse_hex_array::<33>(&opts.taker_pubkey, "taker_pubkey")?;
    let maker_secret = if let Some(ref hex) = opts.maker_ephemeral {
        Some(parse_hex_array::<32>(hex, "maker_ephemeral")?)
    } else {
        None
    };
    let presig = read_presig(&PresigSource::from_encrypt(&opts))?;
    let req = EncryptRequest {
        taker_pubkey: &taker_pub,
        maker_eph_secret: maker_secret,
        presig: &presig,
        context,
    };
    let enc = encrypt_presig(&req)?;

    if opts.emit_parts {
        println!(
            "maker_eph_public=0x{}",
            hex::encode(enc.envelope.maker_eph_public)
        );
        println!("key=0x{}", hex::encode(enc.parts.key()));
        println!("nonce=0x{}", hex::encode(enc.parts.nonce()));
        println!("aad=0x{}", hex::encode(enc.parts.aad()));
    }

    let swap_id_hex = normalize_hex(&opts.context.swap_id);
    let settle_hex = normalize_hex(&opts.context.settle_digest);
    let output = match opts.format {
        OutputFormat::Json => serde_json::to_string_pretty(&json!({
            "swapId": swap_id_hex,
            "settlementDigest": settle_hex,
            "envelope_hex": format!("0x{}", hex::encode(enc.envelope.to_bytes())),
        }))?,
        OutputFormat::Hex => format!("0x{}", hex::encode(enc.envelope.to_bytes())),
    };

    emit_output(&opts.output_file, &output)?;
    if opts.output_file.is_none() {
        println!("{output}");
    }
    Ok(())
}

fn handle_publish_presig(opts: PublishArgs) -> Result<()> {
    let context = opts.context.to_context()?;
    let taker_pub = parse_hex_array::<33>(&opts.taker_pubkey, "taker_pubkey")?;
    let maker_secret = if let Some(ref hex) = opts.maker_ephemeral {
        Some(parse_hex_array::<32>(hex, "maker_ephemeral")?)
    } else {
        None
    };
    let presig = read_presig(&PresigSource::from_publish(&opts))?;
    let req = EncryptRequest {
        taker_pubkey: &taker_pub,
        maker_eph_secret: maker_secret,
        presig: &presig,
        context,
    };
    let enc = encrypt_presig(&req)?;
    let envelope_bytes = enc.envelope.to_bytes();

    if opts.emit_parts {
        println!(
            "maker_eph_public=0x{}",
            hex::encode(enc.envelope.maker_eph_public)
        );
        println!("key=0x{}", hex::encode(enc.parts.key()));
        println!("nonce=0x{}", hex::encode(enc.parts.nonce()));
        println!("aad=0x{}", hex::encode(enc.parts.aad()));
    }

    if let Some(path) = opts.envelope_out.as_ref() {
        fs::write(path, format_hex(&envelope_bytes))
            .with_context(|| format!("write envelope to {}", path.display()))?;
    }

    let reservation_id = parse_swap_id(&opts.context.swap_id, "reservation_id")?;
    if opts.no_broadcast {
        println!("reservationId={}", format_swap_id(reservation_id.as_slice()));
        println!("envelope={}", format_hex(&envelope_bytes));
        return Ok(());
    }

    let rpc = resolve_rpc_url(opts.rpc_url.clone());
    let pk = resolve_private_key(opts.private_key.clone())?;
    let transport = AlloyHttpTransport::new(&rpc, &pk)?;
    let mailbox_addr = parse_address(&opts.mailbox)?;
    let mailbox = MailboxClient::new(mailbox_addr, transport);
    let tx_hash = mailbox.publish_presig(PublishEnvelopeArgs {
        reservation_id,
        envelope: &envelope_bytes,
        gas_limit: None,
    })?;
    println!("publishPreSig tx={}", format_tx_hash(tx_hash));
    Ok(())
}

fn handle_txproof(opts: TxProofArgs) -> Result<()> {
    let reservation_id = parse_swap_id(&opts.context.swap_id, "reservation_id")?;
    let monero_tx = parse_hex_array::<32>(&opts.monero_tx_id, "monero_tx_id")?;
    let extra = if let Some(ref hex) = opts.extra {
        parse_hex_vec(hex, "extra")?
    } else {
        Vec::new()
    };
    let desk_pub = parse_hex_array::<33>(&opts.desk_pubkey, "desk_pubkey")?;
    let taker_secret = parse_hex_array::<32>(&opts.taker_secret, "taker_secret")?;
    let context = opts.context.to_context()?;
    let plaintext = TxProofEnvelope {
        reservationId: reservation_id,
        moneroTxId: FixedBytes::<32>::from(monero_tx),
        extra: Bytes::from(extra),
    };
    let envelope = encrypt_presig(&EncryptRequest {
        taker_pubkey: &desk_pub,
        maker_eph_secret: Some(taker_secret),
        presig: &plaintext.abi_encode(),
        context,
    })?;

    if opts.emit_parts {
        println!(
            "taker_eph_public=0x{}",
            hex::encode(envelope.envelope.maker_eph_public)
        );
        println!("key=0x{}", hex::encode(envelope.parts.key()));
        println!("nonce=0x{}", hex::encode(envelope.parts.nonce()));
        println!("aad=0x{}", hex::encode(envelope.parts.aad()));
    }

    let envelope_bytes = envelope.envelope.to_bytes();
    if let Some(path) = opts.envelope_out.as_ref() {
        fs::write(path, format_hex(&envelope_bytes))
            .with_context(|| format!("write envelope to {}", path.display()))?;
    }

    let rpc = resolve_rpc_url(opts.rpc_url.clone());
    if opts.dry_run || opts.no_broadcast {
        println!("reservationId={}", format_swap_id(reservation_id.as_slice()));
        println!("moneroTxId=0x{}", hex::encode(monero_tx));
        println!("extra=0x{}", hex::encode(&plaintext.extra));
        println!("envelope={}", format_hex(&envelope_bytes));
        println!("rpc={rpc}");
        return Ok(());
    }

    let pk = resolve_private_key(opts.private_key.clone())?;
    let transport = AlloyHttpTransport::new(&rpc, &pk)?;
    let mailbox_addr = parse_address(&opts.mailbox)?;
    let mailbox = MailboxClient::new(mailbox_addr, transport);

    let tx_hash = mailbox.publish_final_sig(PublishEnvelopeArgs {
        reservation_id,
        envelope: &envelope_bytes,
        gas_limit: None,
    })?;
    println!("txProof tx={}", format_tx_hash(tx_hash));
    Ok(())
}

fn handle_decrypt_txproof(opts: DecryptTxProofArgs) -> Result<()> {
    let reservation_id = parse_swap_id(&opts.context.swap_id, "reservation_id")?;
    let desk_secret = parse_hex_array::<32>(&opts.desk_secret, "desk_secret")?;
    let context = opts.context.to_context()?;
    let rpc = resolve_rpc_url(opts.rpc_url.clone());

    if opts.dry_run {
        println!("reservationId={}", format_swap_id(reservation_id.as_slice()));
        println!("rpc={rpc}");
        return Ok(());
    }

    let transport = AlloyHttpTransport::new(&rpc, VIEW_ONLY_PRIVATE_KEY)?;
    let mailbox_addr = parse_address(&opts.mailbox)?;
    let mailbox = MailboxClient::new(mailbox_addr, transport);
    let envelopes = mailbox.fetch(reservation_id)?;
    let final_bytes = envelopes
        .last()
        .ok_or_else(|| anyhow!("no envelopes found for reservation"))?;
    let envelope = Envelope::from_bytes(final_bytes).context("decode TxProof envelope")?;
    let decrypted = decrypt_presig(&DecryptRequest {
        taker_secret: &desk_secret,
        envelope: &envelope,
        context,
    })
    .context("decrypt TxProof envelope")?;
    let proof = TxProofEnvelope::abi_decode(&decrypted.plaintext, true)
        .context("decode TxProof payload")?;
    println!("reservationId={}", format_swap_id(reservation_id.as_slice()));
    println!("moneroTxId=0x{}", hex::encode(proof.moneroTxId.as_slice()));
    println!("extra=0x{}", hex::encode(&proof.extra));
    Ok(())
}

fn handle_register_key(opts: RegisterKeyArgs) -> Result<()> {
    let registry_addr = parse_address(&opts.registry)?;
    let enc_pub = parse_hex_array::<33>(&opts.pubkey, "pubkey")?;
    if opts.dry_run {
        let transport = DryRunTransport::default();
        let registry = KeyRegistryClient::new(registry_addr, transport.clone());
        let tx_hash = registry.register_enc_pub(&enc_pub, Some(opts.gas_limit))?;
        println!("registerEncPub tx={}", format_tx_hash(tx_hash));
        if let Some(call) = transport.last_call() {
            println!(
                "dry-run call -> to: 0x{}, gas_limit: {}, value: {}, data: 0x{}",
                hex::encode(call.to),
                call.gas_limit.unwrap_or(0),
                call.value,
                hex::encode(&call.data)
            );
        }
        return Ok(());
    }

    let rpc = resolve_rpc_url(opts.rpc_url.clone());
    let pk = resolve_private_key(opts.private_key.clone())?;
    let transport = AlloyHttpTransport::new(&rpc, &pk)?;
    let registry = KeyRegistryClient::new(registry_addr, transport);
    let tx_hash = registry.register_enc_pub(&enc_pub, Some(opts.gas_limit))?;
    println!("registerEncPub tx={}", format_tx_hash(tx_hash));
    Ok(())
}

fn handle_show_key(opts: ShowKeyArgs) -> Result<()> {
    let registry_addr = parse_address(&opts.registry)?;
    let owner = parse_address(&opts.owner)?;
    let rpc = resolve_rpc_url(opts.rpc_url.clone());
    let transport = AlloyHttpTransport::new(&rpc, VIEW_ONLY_PRIVATE_KEY)?;
    let registry = KeyRegistryClient::new(registry_addr, transport);
    let key = registry.get_enc_pub(owner)?;
    if key.is_empty() {
        println!("pubkey=<unset>");
    } else {
        println!("pubkey=0x{}", hex::encode(key));
    }
    Ok(())
}

async fn handle_watch(opts: WatchArgs) -> Result<()> {
    let atomic_desk_addr = parse_address(&opts.atomic_desk)?;
    let escrow_addr = parse_address(&opts.settlement_escrow)?;
    let rpc = resolve_rpc_url(opts.rpc_url.clone());
    let url = reqwest::Url::parse(&rpc)?;
    let provider = ProviderBuilder::new().on_http(url);
    let mut from = BlockNumberOrTag::Number(opts.from_block);

    loop {
        let latest = provider.get_block_number().await?;
        let latest_block: u64 = latest;
        let to = opts
            .to_block
            .map(BlockNumberOrTag::Number)
            .unwrap_or(BlockNumberOrTag::Number(latest_block));

        let atomic_filter = Filter::new()
            .address(atomic_desk_addr)
            .from_block(from)
            .to_block(to);
        for log in provider.get_logs(&atomic_filter).await? {
            decode_atomic_desk_log(&log)?;
        }

        let escrow_filter = Filter::new()
            .address(escrow_addr)
            .from_block(from)
            .to_block(to);
        for log in provider.get_logs(&escrow_filter).await? {
            decode_escrow_log(&log)?;
        }

        if !opts.follow {
            break;
        }
        let next_from = latest_block.saturating_add(1);
        from = BlockNumberOrTag::Number(next_from);
        sleep(Duration::from_secs(opts.poll_seconds)).await;
    }

    Ok(())
}

fn decode_atomic_desk_log(log: &Log) -> Result<()> {
    if let Ok(record) = decode_atomic_reservation_created(log.topics(), log.data().data.as_ref()) {
        let payload = json!({
            "reservationId": format_swap_id(record.reservation_id.as_slice()),
            "deskId": format_hex(record.desk_id.as_slice()),
            "taker": format_address(record.taker),
            "asset": format_address(record.asset),
            "amount": format_u256(record.amount),
            "settlementDigest": format_hex(&record.settlement_digest),
            "expiry": record.expiry,
            "createdAt": record.created_at,
        });
        emit_event(log, "AtomicDeskReservationCreated", payload)?;
    }
    Ok(())
}

fn decode_escrow_log(log: &Log) -> Result<()> {
    if let Ok(record) = decode_reservation_created(log.topics(), log.data().data.as_ref()) {
        let payload = json!({
            "reservationId": format_swap_id(record.reservation_id.as_slice()),
            "taker": format_address(record.taker),
            "desk": format_address(record.desk),
            "amount": format_u256(record.amount),
            "counter": format_u256(record.counter),
        });
        emit_event(log, "ReservationCreated", payload)?;
        return Ok(());
    }
    if let Ok(record) = decode_hashlock_set(log.topics(), log.data().data.as_ref()) {
        let payload = json!({
            "reservationId": format_swap_id(record.reservation_id.as_slice()),
            "hashlock": format_hex(&record.hashlock),
        });
        emit_event(log, "HashlockSet", payload)?;
        return Ok(());
    }
    if let Ok((id, tau)) = decode_reservation_settled(log.topics(), log.data().data.as_ref()) {
        let payload = json!({
            "reservationId": format_swap_id(id.as_slice()),
            "tau": format_hex(&tau),
        });
        emit_event(log, "ReservationSettled", payload)?;
        return Ok(());
    }
    if let Ok((id, evidence)) = decode_reservation_refunded(log.topics(), log.data().data.as_ref())
    {
        let payload = json!({
            "reservationId": format_swap_id(id.as_slice()),
            "evidence": format_hex(&evidence),
        });
        emit_event(log, "ReservationRefunded", payload)?;
        return Ok(());
    }
    Ok(())
}

fn emit_event(log: &Log, event: &str, payload: serde_json::Value) -> Result<()> {
    let entry = json!({
        "event": event,
        "blockNumber": log.block_number,
        "transactionHash": log
            .transaction_hash
            .map(|hash| format_hex(hash.as_slice())),
        "logIndex": log.log_index,
        "transactionIndex": log.transaction_index,
        "removed": log.removed,
        "data": payload,
    });
    println!("{}", serde_json::to_string(&entry)?);
    Ok(())
}

fn resolve_rpc_url(rpc: Option<String>) -> String {
    rpc.unwrap_or_else(|| "http://127.0.0.1:8545".to_string())
}

fn resolve_private_key(pk: Option<String>) -> Result<String> {
    pk.ok_or_else(|| anyhow!("--private-key required"))
}

fn format_address(addr: Address) -> String {
    format!("0x{}", hex::encode(addr.as_slice()))
}

fn format_u256(value: U256) -> String {
    value.to_string()
}

fn format_swap_id(value: &[u8]) -> String {
    format_hex(value)
}

fn emit_output(path: &Option<PathBuf>, data: &str) -> Result<()> {
    if let Some(path) = path {
        fs::write(path, data)?;
    }
    Ok(())
}

fn read_presig(src: &PresigSource) -> Result<Vec<u8>> {
    if let Some(ref hex) = src.presig_hex {
        return hex::decode(hex.trim_start_matches("0x")).context("invalid presig hex");
    }
    if let Some(ref path) = src.presig_file {
        return fs::read(path).context("failed to read presig file");
    }
    if src.presig_stdin {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        return Ok(buf);
    }
    Err(anyhow!("presig source missing"))
}

impl ContextArgs {
    fn to_context(&self) -> Result<EnvelopeContext> {
        Ok(EnvelopeContext {
            chain_id: self.chain_id,
            escrow_address: address_to_array(parse_address(&self.escrow)?),
            swap_id: parse_hex_array::<32>(&self.swap_id, "swap_id")?,
            settle_digest: parse_hex_array::<32>(&self.settle_digest, "settle_digest")?,
            m_digest: parse_hex_array::<32>(&self.m_digest, "m_digest")?,
            maker_address: address_to_array(parse_address(&self.maker)?),
            taker_address: address_to_array(parse_address(&self.taker)?),
            version: self.version,
        })
    }
}

fn parse_swap_id(value: &str, label: &str) -> Result<FixedBytes<32>> {
    let bytes = parse_hex_array::<32>(value, label)?;
    Ok(FixedBytes::<32>::from(bytes))
}

fn address_to_array(addr: Address) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(addr.as_slice());
    out
}

fn normalize_hex(value: &str) -> String {
    if value.starts_with("0x") {
        value.to_string()
    } else {
        format!("0x{}", value)
    }
}
