mod commands;

use adaptor_clsag::{
    make_pre_sig, ClsagCtx, SettlementCtx, SignerWitness, SAMPLE_RING_COMMITMENTS, SAMPLE_RING_KEYS,
};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "eswp-cli", about = "EqualX developer CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// CLSAG pre-signature demo generator.
    Sample(SampleArgs),
    /// Atomic Desk utilities (context/presig envelopes, TxProof, watchers).
    AtomicDesk(commands::atomicdesk::AtomicDeskCli),
    /// Local settlement automation (Monero watcher + settle()).
    SettleLocal(commands::settle::SettleLocalArgs),
    /// Deadline-based refund helper.
    RefundLocal(commands::refund::RefundLocalArgs),
}

#[derive(Parser)]
struct SampleArgs {
    #[arg(long, default_value_t = 2)]
    i_star: usize,
    #[arg(long, default_value = "")]
    msg_hex: String,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Sample(args) => run_sample(args),
        Commands::AtomicDesk(args) => {
            if let Err(err) = commands::atomicdesk::run(args) {
                eprintln!("error: {err:?}");
                std::process::exit(1);
            }
        }
        Commands::SettleLocal(args) => {
            if let Err(err) = commands::settle::run(args) {
                eprintln!("error: {err:?}");
                std::process::exit(1);
            }
        }
        Commands::RefundLocal(args) => {
            if let Err(err) = commands::refund::run(args) {
                eprintln!("error: {err:?}");
                std::process::exit(1);
            }
        }
    }
}

fn run_sample(args: SampleArgs) {
    let msg = hex::decode(args.msg_hex).unwrap_or_default();
    assert!(
        args.i_star < SAMPLE_RING_KEYS.len(),
        "i_star must be within the sample ring"
    );
    let sctx = SettlementCtx {
        chain_tag: "evm:84532".into(),
        position_key: [0u8; 32],
        settle_digest: [0u8; 32],
    };
    let mut x = [0u8; 32];
    x[..8].copy_from_slice(&((args.i_star + 1) as u64).to_le_bytes());
    let mut mask = [0u8; 32];
    mask[..8].copy_from_slice(&((args.i_star + 1) as u64).to_le_bytes());
    let wit = SignerWitness {
        x,
        mask,
        amount: 0,
        i_star: args.i_star,
    };
    let ctx = ClsagCtx {
        ring_keys: SAMPLE_RING_KEYS.to_vec(),
        ring_commitments: SAMPLE_RING_COMMITMENTS.to_vec(),
        key_image: wit.key_image_bytes(),
        n: SAMPLE_RING_KEYS.len(),
    };
    let swap_id = [0u8; 32];
    let (pre, t) = make_pre_sig(&ctx, &wit, &msg, &swap_id, sctx).expect("make_pre_sig failed");
    println!("pre_hash={}", hex::encode(pre.pre_hash));
    println!("t={}", hex::encode(t));
}
