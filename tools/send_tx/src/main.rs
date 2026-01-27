use anyhow::{Context, Result};
use clap::Parser;
use monero_oxide::transaction::{NotPruned, Transaction as OxTransaction};
use monero_rpc::MoneroRpc;
use std::{fs, thread, time::Duration};

#[derive(Parser, Debug)]
#[command(name = "send_tx", about = "Submit a Monero raw tx blob to a node")]
struct Args {
    /// Base RPC URL, e.g. http://127.0.0.1:18081
    #[arg(long = "rpc")]
    rpc: String,

    /// Optional basic auth "user:pass"
    #[arg(long = "auth", default_value = "")]
    auth: String,

    /// Path to tx blob file, e.g. out/final_tx.bin (from Microtask 5)
    #[arg(long = "file")]
    file: String,

    /// Do not relay (dry-run mempool validation)
    #[arg(long = "dry", default_value_t = false)]
    dry: bool,

    /// Blink relay flag (for nets that support it)
    #[arg(long = "blink", default_value_t = false)]
    blink: bool,

    /// Retries with exponential backoff
    #[arg(long = "retries", default_value_t = 3)]
    retries: u32,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let auth = if args.auth.is_empty() {
        None
    } else {
        let (user, pass) = args.auth.split_once(':').unwrap_or((&args.auth, ""));
        Some((user.to_string(), pass.to_string()))
    };

    let rpc = MoneroRpc::new(&args.rpc, auth).context("init rpc")?;

    println!("[*] Probing node...");
    let height = rpc.get_height().context("get_height")?;
    let info = rpc.get_info().context("get_info")?;
    println!("    height={height} nettype={:?}", info.nettype);

    let blob = fs::read(&args.file).with_context(|| format!("read {}", args.file))?;
    println!("[*] Read {} bytes from {}", blob.len(), args.file);
    let computed_hash = match compute_tx_hash(&blob) {
        Ok(hash_hex) => {
            println!("[*] Computed tx hash (from blob): {}", hash_hex);
            Some(hash_hex)
        }
        Err(err) => {
            eprintln!("[WARN] Failed to compute tx hash locally: {err}");
            None
        }
    };

    let mut attempt = 0u32;
    let max_attempts = args.retries.saturating_add(1);
    loop {
        attempt += 1;
        println!(
            "[*] submit attempt {} (dry={}, blink={})",
            attempt, args.dry, args.blink
        );
        match rpc.submit_raw_tx(&blob, args.dry, args.blink) {
            Ok(res) => {
                println!(
                    "[OK] status={} tx_hash={} not_relayed={}",
                    res.status,
                    if res.tx_hash.is_empty() {
                        computed_hash.as_deref().unwrap_or("<not provided>")
                    } else {
                        res.tx_hash.as_str()
                    },
                    res.not_relayed
                );
                if res.tx_hash.is_empty() {
                    if let Some(hash_hex) = computed_hash.as_deref() {
                        println!("    computed_hash (from blob): {hash_hex}");
                    }
                }
                if let Some(reason) = res.reason.as_deref() {
                    if !reason.is_empty() {
                        println!("    rpc reason: {reason}");
                    }
                }
                if let Some(err) = res.error.as_ref() {
                    println!(
                        "    rpc error: code={:?} message={:?}",
                        err.code, err.message
                    );
                }
                if let Some(credits) = res.credits {
                    println!("    rpc credits: {}", credits);
                }
                // Lightweight polling to observe propagation when not dry-running.
                let poll_hash = if res.tx_hash.is_empty() {
                    computed_hash.clone().unwrap_or_default()
                } else {
                    res.tx_hash.clone()
                };
                if !args.dry && !poll_hash.is_empty() {
                    for i in 0..6 {
                        match rpc.get_tx(&poll_hash, true) {
                            Ok(txres) => {
                                let keys = txres
                                    .raw
                                    .as_object()
                                    .map(|m| m.keys().len())
                                    .unwrap_or_default();
                                println!("    poll {}: json_keys={}", i + 1, keys);
                                break;
                            }
                            Err(e) => {
                                println!("    poll {}: not found yet ({e}); waiting...", i + 1);
                                thread::sleep(Duration::from_millis(500 * (i + 1) as u64));
                            }
                        }
                    }
                }
                break;
            }
            Err(e) => {
                if attempt >= max_attempts {
                    eprintln!("[ERR] submit failed after {} attempts: {e}", attempt);
                    std::process::exit(2);
                }
                let backoff = 500u64 * (1u64 << ((attempt - 1).min(6)));
                eprintln!(
                    "[WARN] submit attempt {} failed: {} — retrying in {} ms",
                    attempt, e, backoff
                );
                thread::sleep(Duration::from_millis(backoff));
            }
        }
    }

    fn compute_tx_hash(blob: &[u8]) -> Result<String> {
        let mut slice = blob;
        let tx: OxTransaction<NotPruned> =
            OxTransaction::read(&mut slice).map_err(|e| anyhow::anyhow!("parse tx blob: {e:?}"))?;
        Ok(hex::encode(tx.hash()))
    }

    Ok(())
}
