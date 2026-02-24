use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use mock_adapter::MockAdapter;
use orchestrator::{
    MoneroContext, OrchestratorConfig, ReservationId, ReservationParams, SwapOrchestrator,
};

#[derive(Parser, Debug)]
pub struct OrchestratorCli {
    #[command(subcommand)]
    pub command: OrchestratorSubcommand,

    /// Reservation id as 32-byte hex string.
    #[arg(
        long,
        default_value = "0x0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10"
    )]
    pub reservation_id: String,

    /// Mock adapter wall-clock timestamp.
    #[arg(long, default_value_t = 1_000)]
    pub now: u64,
}

#[derive(Subcommand, Debug)]
pub enum OrchestratorSubcommand {
    /// Run full maker lifecycle flow.
    MakerFlow {
        #[arg(long)]
        created_at: Option<u64>,
    },
    /// Run full taker lifecycle flow.
    TakerFlow,
}

pub fn run(args: OrchestratorCli) -> Result<()> {
    let rid = parse_reservation_id(&args.reservation_id)?;
    let adapter = MockAdapter::default();
    adapter.set_clock(args.now);
    let orchestrator = SwapOrchestrator::new(adapter.clone(), OrchestratorConfig::default());

    match args.command {
        OrchestratorSubcommand::MakerFlow { created_at } => {
            let created_at = created_at.or(Some(args.now));
            orchestrator
                .maker_create_reservation(ReservationParams {
                    reservation_id: rid,
                    created_at,
                })
                .context("maker_create_reservation failed")?;
            orchestrator
                .maker_set_hashlock(rid)
                .context("maker_set_hashlock failed")?;
            orchestrator
                .maker_handle_context(rid)
                .context("maker_handle_context failed")?;
            orchestrator
                .maker_publish_presig(rid)
                .context("maker_publish_presig failed")?;
            orchestrator
                .maker_handle_final_sig(rid)
                .context("maker_handle_final_sig failed")?;
            orchestrator
                .maker_settle(rid)
                .context("maker_settle failed")?;

            let state = orchestrator
                .state(rid)
                .ok_or_else(|| anyhow!("missing final maker state"))?;
            let side_effects = orchestrator.side_effects(rid).unwrap_or_default();

            println!("flow=maker");
            println!("reservation_id=0x{}", hex::encode(rid));
            println!("final_state={state:?}");
            println!("side_effects={}", side_effects.len());
            println!("events={}", adapter.events().len());
        }
        OrchestratorSubcommand::TakerFlow => {
            orchestrator
                .taker_accept_reservation(rid)
                .context("taker_accept_reservation failed")?;
            orchestrator
                .taker_publish_context(rid, sample_context(rid))
                .context("taker_publish_context failed")?;
            orchestrator
                .taker_handle_presig(rid)
                .context("taker_handle_presig failed")?;
            let monero_tx = orchestrator
                .taker_complete_and_broadcast(rid)
                .context("taker_complete_and_broadcast failed")?;
            orchestrator
                .taker_publish_final_sig(rid, monero_tx)
                .context("taker_publish_final_sig failed")?;

            let state = orchestrator
                .state(rid)
                .ok_or_else(|| anyhow!("missing final taker state"))?;
            let side_effects = orchestrator.side_effects(rid).unwrap_or_default();

            println!("flow=taker");
            println!("reservation_id=0x{}", hex::encode(rid));
            println!("monero_tx=0x{}", hex::encode(monero_tx));
            println!("final_state={state:?}");
            println!("side_effects={}", side_effects.len());
            println!("events={}", adapter.events().len());
        }
    }

    Ok(())
}

fn sample_context(reservation_id: ReservationId) -> MoneroContext {
    MoneroContext {
        context_hash: reservation_id,
        wire_version: 1,
        envelope: None,
    }
}

fn parse_reservation_id(value: &str) -> Result<ReservationId> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(raw).context("reservation_id must be hex")?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "reservation_id must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut rid = [0u8; 32];
    rid.copy_from_slice(&bytes);
    Ok(rid)
}
