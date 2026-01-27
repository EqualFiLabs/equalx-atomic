//! Reference implementation of the EqualX SDK surface area.

pub mod adaptor;
#[cfg(not(target_arch = "wasm32"))]
pub mod automation;
pub mod chain;
pub mod contracts;
pub mod error;
pub mod escrow;
pub mod key_management;
pub mod key_registry;
pub mod refund;
pub mod settlement;
pub mod transport;
pub mod tx_hash;

pub use adaptor::{
    complete, extract_t, make_pre_adaptor, verify, Backend, FinalAdaptorSignature,
    PreAdaptorParams, PreAdaptorResult,
};
#[cfg(not(target_arch = "wasm32"))]
pub use automation::{
    auto_refund, await_settle, trigger_settlement, AutoRefundConfig, SettlementOutcome,
    SettlementTarget,
};
pub use contracts::{
    AtomicDeskClient, AtomicReservation, AtomicTakerTranche, AtomicTranche, AuctionHouseClient,
    CurveDescriptor, CurveFill, CurveUpdateParams, CurveView, DeskBalances, DeskMakerFees,
    DeskVaultClient, MailboxClient, PublishEnvelopeArgs, SettlementEscrowClient,
    SettlementReservation, StoredCurve, TxHash,
};
pub use chain::{
    ChainEnvelopeArgs, KeyRegistryApi, MailboxApi, ReservationStatus as ChainReservationStatus,
    ReservationView, SettlementEscrowApi,
};
pub use error::{ErrorCode, Result};
pub use escrow::{
    decode_events, EscrowClient, EscrowEvent, EscrowEventKind, EscrowLog, EventResult,
    LockErc20Args, LockEthArgs, RefundArgs as EscrowRefundArgs, SettleArgs,
};
pub use key_management::{
    compute_key_image, derive_subaddress, generate_evm_keypair, generate_monero_keypair,
    sign_evm_message, Address, Scalar,
};
pub use key_registry::KeyRegistryClient;
pub use refund::{prepare_refund, RefundData, RefundParams};
pub use settlement::{
    compute_hashlock, compute_settlement_digest, SettlementCtx, SettlementDigestInputs,
};
#[cfg(not(target_arch = "wasm32"))]
pub use transport::AlloyHttpTransport;
pub use transport::{EvmCall, EvmMessageSigner, EvmTransport, EvmViewTransport};
pub use tx_hash::{
    PostTxHashArgs, QuoteBoardClient, QuoteCommitment, QuoteSnapshot, TakeQuoteArgs,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::{
        auction_house::AuctionHouse as AuctionHouseBindings,
        curves::CurveDescriptor as CurveDescriptorBindings,
        settlement_escrow::SettlementEscrow as SettlementEscrowBindings,
    };
    use crate::escrow::backend_to_byte;
    use adaptor_clsag::{ClsagCtx, SignerWitness, SAMPLE_RING_KEYS};
    use alloy_primitives::{keccak256, Address as AlloyAddress, Bytes, FixedBytes, B256, U256, Uint};
    use alloy_sol_types::{SolCall, SolValue};
    use hex::decode as hex_decode;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    fn sample_ctx() -> SettlementCtx {
        SettlementCtx::new("evm:8453", [0x22u8; 32], [0x11u8; 32]).expect("ctx")
    }

    fn sample_swap_id() -> [u8; 32] {
        [0xAAu8; 32]
    }

    fn sample_tau_pub() -> [u8; 33] {
        let mut bytes = [0u8; 33];
        bytes[0] = 0x02;
        bytes[32] = 0x01;
        bytes
    }

    const ROUNDTRIP_RING_KEYS: [&str; 5] = [
        "77b85d61f368e1334d7ce6d4f676e5c44130579a28c5de013d7a427ba1cfe342",
        "63cbf1c4fb820d0343e9da80fe69e0106d1bbf3e3b6f03ce90b5e8193047b4e9",
        "338f7671e2a13e5134a679f8f967571b41ad6daad5a821fe82b85c55bbaf601e",
        "be74226173e1fd1e22c35c543f29110c8ca03a4359934899fb168552de45313b",
        "09f380098e322b6a604a9952fb7f720cd3bc769391398b306a74a4bf40d9b8af",
    ];

    const ROUNDTRIP_RING_COMMITS: [&str; 5] = [
        "763be8a94eb0770ac1e9b5985494d40c93dd8caa441d43532705ad4218bb2935",
        "5de4ec601fd05140ada7ef63dfc4288bb4699fc0440f0258965e79280076cc73",
        "4b9545fc23fd63f68f42e39359c31cd683b10d41a4b9d76ec63c5ab6c4231a61",
        "b7ef69c43e8821ad9c8322ceff52c72c36dc95bf6bf3e57ccd0e0306225a2e10",
        "d352206cc5f3e87ef40b6365ff5314060886ea0f49e9f075403af080cbdcbe0a",
    ];

    const ROUNDTRIP_KEY_IMAGE: &str =
        "0e681f847db3d53a9edbe9431331175b74e820a5217f848aff931f09b9d338ea";
    const ROUNDTRIP_WITNESS_X: &str =
        "276b9fdd782ab886862256e98786326ad608f3b82f9817e8c96cd889963ce70b";
    const ROUNDTRIP_WITNESS_MASK: &str =
        "c33b89e852827c31dabe6b705a860e74c3350fee11c1faa3136df8fe2b5ba607";
    const ROUNDTRIP_MESSAGE: &str = "636c73616720726f756e647472697020766563746f72206d657373616765";
    const ROUNDTRIP_SWAP_ID: &str =
        "4242424242424242424242424242424242424242424242424242424242424242";
    const ROUNDTRIP_POSITION_KEY: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";
    const ROUNDTRIP_SETTLE_DIGEST: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    fn hex_to_array(hex: &str) -> [u8; 32] {
        let bytes = hex_decode(hex).expect("valid hex");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    }

    fn hex_to_vec(hex: &str) -> Vec<u8> {
        hex_decode(hex).expect("valid hex")
    }

    fn encode_bytes_return(data: &[u8]) -> Bytes {
        let mut out = Vec::with_capacity(64 + ((data.len() + 31) / 32) * 32);
        let mut offset = [0u8; 32];
        offset[31] = 0x20;
        out.extend_from_slice(&offset);

        let mut len_word = [0u8; 32];
        let len = data.len() as u64;
        len_word[24..].copy_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&len_word);

        let mut chunk = data.to_vec();
        while chunk.len() % 32 != 0 {
            chunk.push(0);
        }
        out.extend_from_slice(&chunk);
        Bytes::from(out)
    }

    fn sample_lock_eth_args() -> LockEthArgs {
        LockEthArgs {
            swap_id: sample_swap_id(),
            taker: AlloyAddress::repeat_byte(0xAA),
            maker: AlloyAddress::repeat_byte(0xBB),
            amount: U256::from(1_000u64),
            tip: U256::from(100u64),
            expiry: 500,
            backend: Backend::Clsag,
            settle_digest: sample_ctx().settle_digest(),
            quote_commitment: QuoteCommitment {
                adaptor_hash: [0x10; 32],
                m_digest: [0x20; 32],
                envelope: Bytes::new(),
            },
            gas_limit: Some(300_000),
        }
    }

    fn sample_clsag_setup() -> (PreAdaptorParams, ClsagCtx, Vec<u8>) {
        let mut clsag = ClsagCtx {
            ring_keys: ROUNDTRIP_RING_KEYS
                .iter()
                .map(|h| hex_to_array(h))
                .collect(),
            ring_commitments: ROUNDTRIP_RING_COMMITS
                .iter()
                .map(|h| hex_to_array(h))
                .collect(),
            key_image: hex_to_array(ROUNDTRIP_KEY_IMAGE),
            n: ROUNDTRIP_RING_KEYS.len(),
        };
        let witness = SignerWitness {
            x: hex_to_array(ROUNDTRIP_WITNESS_X),
            mask: hex_to_array(ROUNDTRIP_WITNESS_MASK),
            amount: 0,
            i_star: 2,
        };
        clsag.key_image = witness.key_image_bytes();
        let message = hex_to_vec(ROUNDTRIP_MESSAGE);
        let swap_id = hex_to_array(ROUNDTRIP_SWAP_ID);
        let settlement = SettlementCtx::new(
            "evm:84532",
            hex_to_array(ROUNDTRIP_POSITION_KEY),
            hex_to_array(ROUNDTRIP_SETTLE_DIGEST),
        )
        .expect("settlement ctx");
        let params = PreAdaptorParams {
            clsag: clsag.clone(),
            witness,
            message: message.clone(),
            swap_id,
            settlement,
        };
        (params, clsag, message)
    }

    fn sample_router_descriptor() -> CurveDescriptorBindings {
        CurveDescriptorBindings {
            deskId: FixedBytes::from([0x11; 32]),
            bucketId: U256::from(1u64),
            tokenA: AlloyAddress::repeat_byte(0xAA),
            tokenB: AlloyAddress::repeat_byte(0xBB),
            side: false,
            priceIsQuotePerBase: true,
            maxVolume: 1_000u128,
            startPrice: 2_000u128,
            endPrice: 1_500u128,
            startTime: 1_700_000_000u64,
            duration: 3_600u64,
            generation: 1,
            feeRateBps: 10,
            feeAsset: 0,
            supportBps: 0,
            supportAddress: AlloyAddress::repeat_byte(0xCC),
            salt: Uint::<96, 2>::from(42u64),
        }
    }

    fn hash_router_descriptor(desc: &CurveDescriptorBindings) -> B256 {
        use alloy_sol_types::SolValue;
        const TYPEHASH_STR: &str = "CurveDescriptor(bytes32 deskId,uint256 bucketId,address tokenA,address tokenB,bool side,bool priceIsQuotePerBase,uint128 maxVolume,uint128 startPrice,uint128 endPrice,uint64 startTime,uint64 duration,uint32 generation,uint16 feeRateBps,uint8 feeAsset,uint16 supportBps,address supportAddress,uint96 salt)";
        let typehash = keccak256(TYPEHASH_STR.as_bytes());
        let encoded = (
            typehash,
            desc.deskId,
            desc.bucketId,
            desc.tokenA,
            desc.tokenB,
            desc.side,
            desc.priceIsQuotePerBase,
            desc.maxVolume,
            desc.startPrice,
            desc.endPrice,
            desc.startTime,
            desc.duration,
            desc.generation,
            desc.feeRateBps,
            U256::from(desc.feeAsset),
            desc.supportBps,
            desc.supportAddress,
            desc.salt,
        )
            .abi_encode();
        keccak256(encoded)
    }

    #[test]
    fn curve_descriptor_hash_depends_on_generation() {
        let mut descriptor = sample_router_descriptor();
        let hash1 = hash_router_descriptor(&descriptor);
        descriptor.generation += 1;
        let hash2 = hash_router_descriptor(&descriptor);
        assert_ne!(hash1, hash2, "generation must alter descriptor hash");
    }

    #[derive(Clone, Default)]
    struct MockTransport {
        calls: Arc<Mutex<Vec<EvmCall>>>,
        view_calls: Arc<Mutex<Vec<EvmCall>>>,
        next_view: Arc<Mutex<Option<Bytes>>>,
        fail_send: Arc<Mutex<VecDeque<bool>>>,
        fail_view: Arc<Mutex<VecDeque<bool>>>,
    }

    impl MockTransport {
        fn with_view_response(bytes: Bytes) -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                view_calls: Arc::new(Mutex::new(Vec::new())),
                next_view: Arc::new(Mutex::new(Some(bytes))),
                fail_send: Arc::new(Mutex::new(VecDeque::new())),
                fail_view: Arc::new(Mutex::new(VecDeque::new())),
            }
        }

        fn set_view_response(&self, bytes: Bytes) {
            *self.next_view.lock().unwrap() = Some(bytes);
        }

        fn fail_next_send(&self) {
            self.fail_send.lock().unwrap().push_back(true);
        }
    }

    impl EvmTransport for MockTransport {
        fn send(&self, call: EvmCall) -> Result<B256> {
            self.calls.lock().unwrap().push(call);
            if self.fail_send.lock().unwrap().pop_front().unwrap_or(false) {
                return Err(ErrorCode::BridgeTransportEvm);
            }
            Ok(B256::from([0x42; 32]))
        }
    }

    impl EvmViewTransport for MockTransport {
        fn call_view(&self, call: EvmCall) -> Result<Bytes> {
            self.view_calls.lock().unwrap().push(call);
            if self.fail_view.lock().unwrap().pop_front().unwrap_or(false) {
                return Err(ErrorCode::BridgeTransportEvm);
            }
            self.next_view
                .lock()
                .unwrap()
                .clone()
                .ok_or(ErrorCode::BridgeTransportEvm)
        }
    }

    impl EvmMessageSigner for MockTransport {
        fn sign_hash(&self, digest: B256) -> Result<Bytes> {
            Ok(Bytes::from(digest.to_vec()))
        }

        fn signer_address(&self) -> AlloyAddress {
            AlloyAddress::ZERO
        }
    }

    #[test]
    fn settlement_binding_is_deterministic() {
        let ctx = sample_ctx();
        let binding1 = ctx.binding(sample_swap_id(), "test-domain");
        let binding2 = ctx.binding(sample_swap_id(), "test-domain");
        assert_eq!(binding1, binding2);
    }

    #[test]
    fn monero_key_management_rounds() {
        let (spend, view) = generate_monero_keypair().expect("monero keys");
        assert_ne!(spend, view);
        assert!(spend.iter().any(|b| *b != 0));

        let (address, derived_spend) =
            derive_subaddress(&view, &spend, 7).expect("subaddress derivation");
        assert!(address.starts_with('4') || address.starts_with('7') || address.starts_with('8'));
        let key_image =
            compute_key_image(&SAMPLE_RING_KEYS[0], &derived_spend).expect("key image computation");
        assert_ne!(key_image, [0u8; 32]);
    }

    #[test]
    fn evm_key_management_rounds() {
        let (priv_key, address) = generate_evm_keypair().expect("evm keypair");
        assert_ne!(address, AlloyAddress::ZERO);
        let signature = sign_evm_message(&priv_key, &[0x55; 32]).expect("evm signature generation");
        assert_eq!(signature.len(), 65);
        assert!(matches!(signature[64], 27 | 28));
    }

    #[test]
    fn adaptor_flow_completes_and_verifies() {
        let (params, clsag_ctx, message) = sample_clsag_setup();
        let pre = make_pre_adaptor(params).expect("pre adaptor");
        let final_sig =
            complete(&pre.pre_sig, pre.swap_id, pre.adaptor_secret).expect("completion");
        assert!(verify(&clsag_ctx, &message, &final_sig).expect("verify call"));
        assert_eq!(
            extract_t(&pre.pre_sig, &final_sig).expect("extract"),
            pre.adaptor_secret
        );
    }

    #[test]
    fn refund_preparation_enforces_timing() {
        let ctx = sample_ctx();
        let params = RefundParams {
            swap_id: sample_swap_id(),
            xmr_lock_height: 100,
            eth_expiry: 200,
            delta: 20,
            template: vec![0xAB; 8],
        };
        let refund = prepare_refund(&ctx, params).expect("refund data");
        assert_eq!(refund.lock_time, 120);
        assert!(refund.tx_bytes.len() > 8);
    }

    #[test]
    fn escrow_calls_and_events_are_deterministic() {
        let ctx = sample_ctx();
        let transport = MockTransport::default();
        let client = EscrowClient::new(AlloyAddress::ZERO, transport.clone());
        let commitment = QuoteCommitment {
            adaptor_hash: [0x10; 32],
            m_digest: [0x42; 32],
            envelope: Bytes::new(),
        };
        let le_args = LockEthArgs {
            swap_id: sample_swap_id(),
            taker: AlloyAddress::ZERO,
            maker: AlloyAddress::ZERO,
            amount: U256::from(1_000u64),
            tip: U256::from(100u64),
            expiry: 500,
            backend: Backend::Clsag,
            settle_digest: ctx.settle_digest(),
            quote_commitment: commitment.clone(),
            gas_limit: Some(300_000),
        };
        let le_hash = client.lock_eth(le_args).expect("lock eth");
        assert_ne!(le_hash.bytes(), [0u8; 32]);

        let le20_args = LockErc20Args {
            swap_id: sample_swap_id(),
            taker: AlloyAddress::ZERO,
            token: AlloyAddress::repeat_byte(0x44),
            amount: U256::from(2_000u64),
            tip: U256::from(50u64),
            maker: AlloyAddress::repeat_byte(0x22),
            expiry: 600,
            backend: Backend::Clsag,
            settle_digest: ctx.settle_digest(),
            quote_commitment: QuoteCommitment {
                adaptor_hash: [0x33; 32],
                m_digest: [0x24; 32],
                envelope: Bytes::new(),
            },
            permit: Bytes::new(),
            gas_limit: Some(400_000),
        };
        client.lock_erc20(le20_args).expect("lock erc20");

        client
            .settle(SettleArgs {
                swap_id: sample_swap_id(),
                adaptor_secret: [0x55; 32],
                gas_limit: Some(200_000),
            })
            .expect("settle");
        client
            .refund(EscrowRefundArgs {
                swap_id: sample_swap_id(),
                gas_limit: Some(200_000),
            })
            .expect("refund");

        let calls = transport.calls.lock().unwrap();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[0].value, U256::from(1_100u64));
        assert_eq!(calls[1].value, U256::from(50u64));
        assert_eq!(calls[2].value, U256::ZERO);
        assert_eq!(calls[3].value, U256::ZERO);

        let logs = vec![
            EscrowLog::locked(sample_swap_id(), U256::from(1_000u64), Backend::Clsag),
            EscrowLog::new(
                EscrowEventKind::SwapSettled,
                sample_swap_id(),
                U256::ZERO,
                Backend::Clsag,
            ),
            EscrowLog::new(
                EscrowEventKind::SwapRefunded,
                sample_swap_id(),
                U256::ZERO,
                Backend::Clsag,
            ),
        ];
        let events = decode_events(&ctx, &logs).expect("decode events");
        assert_eq!(events.len(), 3);
        assert!(matches!(events[0].event, EscrowEvent::SwapLocked { .. }));
    }

    #[test]
    fn decode_events_rejects_unknown_kind() {
        let ctx = sample_ctx();
        let log = EscrowLog {
            kind: 9,
            swap_id: sample_swap_id(),
            amount: U256::ZERO,
            backend: backend_to_byte(Backend::Clsag),
        };
        let err = decode_events(&ctx, &[log]).expect_err("invalid kind");
        assert_eq!(err, ErrorCode::BridgeInvalidLog);
    }

    #[test]
    fn decode_events_rejects_unknown_backend() {
        let ctx = sample_ctx();
        let log = EscrowLog {
            kind: EscrowEventKind::SwapSettled.into(),
            swap_id: sample_swap_id(),
            amount: U256::ZERO,
            backend: 0xFF,
        };
        let err = decode_events(&ctx, &[log]).expect_err("invalid backend");
        assert_eq!(err, ErrorCode::BridgeBackendUnsupported);
    }

    #[test]
    fn quoteboard_view_returns_commitment() {
        use alloy_primitives::U256 as AlloyU256;
        let quote = crate::tx_hash::QuoteBoard::Quote {
            maker: AlloyAddress::repeat_byte(0x11),
            asset: AlloyAddress::repeat_byte(0x22),
            backend: 0x01,
            rateNum: AlloyU256::from(5u64),
            rateDen: AlloyU256::from(1u64),
            minAmt: AlloyU256::from(10u64),
            maxAmt: AlloyU256::from(20u64),
            bond: AlloyU256::ZERO,
            ttl: 1234,
            adaptorHash: FixedBytes::<32>::from([0xAB; 32]),
            mDigest: FixedBytes::<32>::from([0xBC; 32]),
            envelope: Bytes::from(vec![0x01, 0x02]),
            live: true,
        };
        let encoded = quote.abi_encode();
        let transport = MockTransport::with_view_response(Bytes::from(encoded));
        let client = QuoteBoardClient::new(AlloyAddress::repeat_byte(0x44), transport);
        let snapshot = client.quote(AlloyU256::from(7u64)).expect("quote fetch");
        assert_eq!(snapshot.commitment.adaptor_hash, [0xAB; 32]);
        assert_eq!(snapshot.commitment.m_digest, [0xBC; 32]);
        assert_eq!(snapshot.commitment.envelope, Bytes::from(vec![0x01, 0x02]));
        assert_eq!(snapshot.backend, Backend::Clsag);
        assert!(snapshot.live);
    }

    #[test]
    fn quoteboard_take_quote_sends_call() {
        use alloy_primitives::U256 as AlloyU256;
        let transport = MockTransport::default();
        let client = QuoteBoardClient::new(AlloyAddress::repeat_byte(0x55), transport.clone());
        let args = TakeQuoteArgs {
            quote_id: AlloyU256::from(9u64),
            amount: AlloyU256::from(100u64),
            tip: AlloyU256::from(5u64),
            expiry: 1_700_000_000u64,
            destination: &[0xAA, 0xBB],
            value: AlloyU256::from(105u64),
            gas_limit: Some(555_000),
        };
        client.take_quote(args).expect("take quote call");
        let calls = transport.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].value, AlloyU256::from(105u64));
        assert_eq!(calls[0].gas_limit, Some(555_000));
    }

    #[test]
    fn key_registry_registers_pubkey() {
        let transport = MockTransport::default();
        let client = KeyRegistryClient::new(AlloyAddress::repeat_byte(0x90), transport.clone());
        let mut pubkey = [0u8; 33];
        pubkey[0] = 0x02;
        pubkey[32] = 0x55;
        client
            .register_enc_pub(&pubkey, Some(210_000))
            .expect("register");
        let calls = transport.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].gas_limit, Some(210_000));
        assert_eq!(calls[0].value, U256::ZERO);
    }

    #[test]
    fn key_registry_view_returns_pubkey() {
        let pubkey = vec![0xAB; 33];
        let encoded = encode_bytes_return(&pubkey);
        let transport = MockTransport::with_view_response(encoded);
        let client = KeyRegistryClient::new(AlloyAddress::repeat_byte(0x44), transport.clone());
        let fetched = client
            .get_enc_pub(AlloyAddress::repeat_byte(0x12))
            .expect("view call");
        assert_eq!(fetched, pubkey);
    }

    #[test]
    fn post_tx_hash_is_bound_to_context() {
        let transport = MockTransport::default();
        let client = QuoteBoardClient::new(AlloyAddress::repeat_byte(0x12), transport);
        let args = PostTxHashArgs {
            swap_id: sample_swap_id(),
            monero_tx_hash: [0x45; 32],
            tau_pub: &sample_tau_pub(),
        };
        let result = client.post_tx_hash(args).expect("post tx hash");
        assert_ne!(result.bytes(), [0u8; 32]);
    }

    #[test]
    fn post_tx_hash_rejects_short_tau_pub() {
        let transport = MockTransport::default();
        let client = QuoteBoardClient::new(AlloyAddress::repeat_byte(0x99), transport);
        let args = PostTxHashArgs {
            swap_id: sample_swap_id(),
            monero_tx_hash: [0x11; 32],
            tau_pub: &[0x02, 0x01],
        };
        let err = client.post_tx_hash(args).expect_err("should fail");
        assert_eq!(err, ErrorCode::TauPubInvalid);
    }

    #[test]
    fn escrow_client_transport_errors_and_retries() {
        let transport = MockTransport::default();
        let client = EscrowClient::new(AlloyAddress::repeat_byte(0xCD), transport.clone());
        transport.fail_next_send();
        let args = sample_lock_eth_args();
        assert_eq!(
            client.lock_eth(args.clone()).expect_err("first send"),
            ErrorCode::BridgeTransportEvm
        );
        let hash = client.lock_eth(args).expect("retry succeeds");
        assert_ne!(hash.bytes(), [0u8; 32]);
        assert_eq!(transport.calls.lock().unwrap().len(), 2);
    }

    #[test]
    fn auction_house_client_handles_view_helpers() {
        let house = AlloyAddress::repeat_byte(0x42);
        let transport = MockTransport::default();
        let client = AuctionHouseClient::new(house, transport.clone());

        let fill_wire = AuctionHouseBindings::CurveFillView {
            deskId: FixedBytes::<32>::from([0xAA; 32]),
            maker: AlloyAddress::repeat_byte(0x10),
            tokenA: AlloyAddress::repeat_byte(0x11),
            tokenB: AlloyAddress::repeat_byte(0x12),
            baseIsA: true,
            startPrice: 1_000u128,
            endPrice: 500u128,
            startTime: 100u64,
            duration: 50u64,
            feeRateBps: 25,
            remainingVolume: 750u128,
        };
        let encoded = AuctionHouseBindings::loadCurveForFillCall::abi_encode_returns(&(fill_wire,));
        transport.set_view_response(Bytes::from(encoded));

        let view = client
            .load_curve_for_fill(U256::from(77u64))
            .expect("curve fetch");
        assert_eq!(view.remaining_volume, U256::from(750u64));
        assert_eq!(view.fee_rate_bps, 25);
        assert_eq!(view.token_a, AlloyAddress::repeat_byte(0x11));

        let auction_call = AuctionHouseBindings::loadCurveForFillCall {
            curveId: U256::from(77u64),
        }
        .abi_encode();
        {
            let calls = transport.view_calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].to, house);
            assert_eq!(calls[0].data, Bytes::from(auction_call));
        }

        let counter_bytes =
            AuctionHouseBindings::auctionCounterCall::abi_encode_returns(&(U256::from(9u64),));
        transport.set_view_response(Bytes::from(counter_bytes));
        assert_eq!(client.auction_counter().expect("counter"), U256::from(9u64));

        let vault_addr = AlloyAddress::repeat_byte(0x55);
        let vault_bytes = AuctionHouseBindings::vaultCall::abi_encode_returns(&(vault_addr,));
        transport.set_view_response(Bytes::from(vault_bytes));
        assert_eq!(client.vault().expect("vault"), vault_addr);

        let calls = transport.view_calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(
            calls[1].data,
            Bytes::from(AuctionHouseBindings::auctionCounterCall {}.abi_encode())
        );
        assert_eq!(
            calls[2].data,
            Bytes::from(AuctionHouseBindings::vaultCall {}.abi_encode())
        );
    }

    #[test]
    fn settlement_escrow_client_handles_calls_and_gas_limits() {
        let transport = MockTransport::default();
        let escrow_addr = AlloyAddress::repeat_byte(0x80);
        let client = SettlementEscrowClient::new(escrow_addr, transport.clone());

        let reservation_id = FixedBytes::<32>::from([0x05u8; 32]);
        let tau = [0x44u8; 32];
        client
            .settle(reservation_id, tau, None)
            .expect("default gas settle");
        client
            .settle(FixedBytes::<32>::from([0x06u8; 32]), tau, Some(450_000))
            .expect("custom gas settle");
        client
            .refund(FixedBytes::<32>::from([0x07u8; 32]), [0x11; 32], Some(350_000))
            .expect("refund call");

        let calls = transport.calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].gas_limit, Some(200_000));
        assert_eq!(calls[1].gas_limit, Some(450_000));
        assert_eq!(calls[2].gas_limit, Some(350_000));
        assert_eq!(calls[0].value, U256::ZERO);
        assert_eq!(calls[2].to, escrow_addr);

        let reservation_wire = SettlementEscrowBindings::Reservation {
            reservationId: FixedBytes::<32>::from([0x7Bu8; 32]),
            deskId: FixedBytes::<32>::from([0xDD; 32]),
            positionKey: FixedBytes::<32>::from([0x11; 32]),
            positionId: U256::from(55u64),
            desk: AlloyAddress::repeat_byte(0x01),
            taker: AlloyAddress::repeat_byte(0x02),
            poolIdA: U256::from(1u64),
            poolIdB: U256::from(2u64),
            tokenA: AlloyAddress::repeat_byte(0x03),
            tokenB: AlloyAddress::repeat_byte(0x04),
            baseIsA: true,
            asset: AlloyAddress::ZERO,
            amount: U256::from(999u64),
            settlementDigest: FixedBytes::<32>::from([0xAA; 32]),
            hashlock: FixedBytes::<32>::from([0xBB; 32]),
            counter: U256::from(7u64),
            expiry: 1_700_000_123,
            createdAt: 1_700_000_000,
            feeBps: 150,
            feePayer: 0,
            status: SettlementEscrowBindings::ReservationStatus::Active,
        };
        let reservation_bytes =
            SettlementEscrowBindings::getReservationCall::abi_encode_returns(&(reservation_wire,));
        transport.set_view_response(Bytes::from(reservation_bytes));

        let view = client
            .get_reservation(reservation_id)
            .expect("reservation view");
        assert_eq!(view.amount, U256::from(999u64));
        assert_eq!(view.desk, AlloyAddress::repeat_byte(0x01));
        assert_eq!(view.settlement_digest, FixedBytes::<32>::from([0xAA; 32]));

        let view_calls = transport.view_calls.lock().unwrap();
        assert_eq!(view_calls.len(), 1);
        let expected = SettlementEscrowBindings::getReservationCall {
            reservationId: reservation_id,
        }
        .abi_encode();
        assert_eq!(view_calls[0].data, Bytes::from(expected));
    }

    #[test]
    fn settlement_escrow_client_rejects_zero_tau() {
        let transport = MockTransport::default();
        let client = SettlementEscrowClient::new(AlloyAddress::repeat_byte(0x70), transport);
        let err = client
            .settle(FixedBytes::<32>::from([0x01u8; 32]), [0u8; 32], None)
            .expect_err("zero tau should fail");
        assert_eq!(err, ErrorCode::SettlementDigestMismatch);
    }
}
