use adaptor_clsag::wire::{ClsagPreSig, MAGIC_CLSAG_PRESIG};
use adaptor_clsag::{EswpError, SettlementCtx, BACKEND_ID_CLSAG, SAMPLE_RING_KEYS, WIRE_VERSION};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};
use presig_envelope::{
    decrypt_presig, encrypt_presig, DecryptRequest, EncryptRequest, EncryptionOutput, Envelope,
    EnvelopeContext, EnvelopeError,
};
use proptest::prelude::*;

#[derive(Clone, Debug)]
struct EncryptRequestInput {
    taker_secret: [u8; 32],
    taker_pubkey: [u8; 33],
    maker_eph_secret: Option<[u8; 32]>,
    presig: Vec<u8>,
    context: EnvelopeContext,
}

fn taker_pubkey_from_secret(secret_bytes: &[u8; 32]) -> [u8; 33] {
    let taker_sk = SecretKey::from_slice(secret_bytes).expect("valid secret key");
    let taker_pub = PublicKey::from_secret_scalar(&taker_sk.to_nonzero_scalar());
    let mut out = [0u8; 33];
    out.copy_from_slice(taker_pub.to_encoded_point(true).as_bytes());
    out
}

/// Arbitrary generator: valid secp256k1 secret key bytes.
fn arb_secret_key_bytes() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>().prop_filter("valid secp256k1 secret key", |bytes| {
        SecretKey::from_slice(bytes).is_ok()
    })
}

/// Arbitrary generator: EnvelopeContext.
fn arb_envelope_context() -> impl Strategy<Value = EnvelopeContext> {
    (
        any::<u64>(),
        any::<[u8; 20]>(),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        any::<[u8; 20]>(),
        any::<[u8; 20]>(),
        any::<u8>(),
    )
        .prop_map(
            |(
                chain_id,
                escrow_address,
                swap_id,
                settle_digest,
                m_digest,
                maker_address,
                taker_address,
                version,
            )| EnvelopeContext {
                chain_id,
                escrow_address,
                swap_id,
                settle_digest,
                m_digest,
                maker_address,
                taker_address,
                version,
            },
        )
}

/// Arbitrary generator: EncryptRequest inputs (owned form for proptest).
fn arb_encrypt_request_input() -> impl Strategy<Value = EncryptRequestInput> {
    (
        arb_secret_key_bytes(),
        prop_oneof![Just(None), arb_secret_key_bytes().prop_map(Some)],
        prop::collection::vec(any::<u8>(), 0..512),
        arb_envelope_context(),
    )
        .prop_map(
            |(taker_secret, maker_eph_secret, presig, context)| EncryptRequestInput {
                taker_pubkey: taker_pubkey_from_secret(&taker_secret),
                taker_secret,
                maker_eph_secret,
                presig,
                context,
            },
        )
}

/// Arbitrary generator: valid Envelope values (built via encrypt function).
fn arb_envelope() -> impl Strategy<Value = Envelope> {
    arb_encrypt_request_input().prop_filter_map("encryptable envelope", |input| {
        let request = EncryptRequest {
            taker_pubkey: &input.taker_pubkey,
            maker_eph_secret: input.maker_eph_secret,
            presig: &input.presig,
            context: input.context,
        };
        encrypt_presig(&request)
            .ok()
            .map(|out| out.envelope)
            .filter(|env| !env.ciphertext.is_empty())
    })
}

/// Arbitrary generator: valid PreSig wire-format container inputs.
fn arb_presig_wire_input() -> impl Strategy<Value = ClsagPreSig> {
    (
        proptest::string::string_regex("[a-z0-9:_-]{1,32}")
            .expect("regex")
            .boxed(),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        any::<u8>(),
        prop::collection::vec(any::<u8>(), 0..256),
        prop::collection::vec(any::<u8>(), 0..256),
    )
        .prop_map(
            |(
                chain_tag,
                position_key,
                settle_digest,
                pre_hash,
                resp_seed,
                message,
                proof_bytes_sans_resp,
            )| {
                let ring_size = SAMPLE_RING_KEYS.len() as u8;
                let resp_index = resp_seed % ring_size;
                let mut ring_bytes = Vec::with_capacity(SAMPLE_RING_KEYS.len() * 32);
                for point in SAMPLE_RING_KEYS {
                    ring_bytes.extend_from_slice(&point);
                }

                ClsagPreSig {
                    magic: MAGIC_CLSAG_PRESIG,
                    wire_version: WIRE_VERSION,
                    backend: BACKEND_ID_CLSAG,
                    ring_size,
                    resp_index,
                    reserved0: 0,
                    m: message,
                    ring_bytes,
                    pre_hash,
                    ctx: SettlementCtx {
                        chain_tag,
                        position_key,
                        settle_digest,
                    },
                    proof_bytes_sans_resp,
                }
            },
        )
}

fn encode_encryption(input: &EncryptRequestInput) -> EncryptionOutput {
    let request = EncryptRequest {
        taker_pubkey: &input.taker_pubkey,
        maker_eph_secret: input.maker_eph_secret,
        presig: &input.presig,
        context: input.context,
    };
    encrypt_presig(&request).expect("valid encryption input")
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        .. ProptestConfig::default()
    })]

    /// Property 9: Presig container serialization round-trip.
    #[test]
    fn property9_presig_container_roundtrip(container in arb_presig_wire_input()) {
        let encoded = container.encode().expect("encode");
        let decoded = ClsagPreSig::decode(&encoded).expect("decode");
        prop_assert_eq!(decoded, container);
    }

    /// Property 11: Presig serialization determinism.
    #[test]
    fn property11_presig_serialization_determinism(container in arb_presig_wire_input()) {
        let encoded_a = container.encode().expect("encode a");
        let encoded_b = container.encode().expect("encode b");
        prop_assert_eq!(encoded_a, encoded_b);
    }

    /// Property 10: Presig deserializer rejects invalid magic.
    #[test]
    fn property10_presig_invalid_magic(container in arb_presig_wire_input()) {
        let mut encoded = container.encode().expect("encode");
        encoded[0] ^= 0x01;
        let err = ClsagPreSig::decode(&encoded).expect_err("must fail");
        prop_assert!(matches!(err, EswpError::MagicMismatch));
    }

    /// Property 10: Presig deserializer rejects unsupported version.
    #[test]
    fn property10_presig_unsupported_version(container in arb_presig_wire_input()) {
        let mut encoded = container.encode().expect("encode");
        encoded[4] = 0xFF;
        encoded[5] = 0xFF;
        let err = ClsagPreSig::decode(&encoded).expect_err("must fail");
        prop_assert!(matches!(err, EswpError::VersionUnsupported));
    }

    /// Property 10: Presig deserializer rejects truncated fields.
    #[test]
    fn property10_presig_truncated_fields(container in arb_presig_wire_input(), cut_seed in 0usize..2048) {
        let encoded = container.encode().expect("encode");
        let structured_prefix_len = encoded.len().saturating_sub(container.proof_bytes_sans_resp.len());
        prop_assume!(structured_prefix_len > 0);
        let cut = cut_seed % structured_prefix_len;
        let truncated = &encoded[..cut];
        let err = ClsagPreSig::decode(truncated).expect_err("must fail");
        prop_assert!(matches!(
            err,
            EswpError::EncodingNoncanonical
                | EswpError::RingInvalid
                | EswpError::RespIndexUnadmitted
                | EswpError::PreHashMismatch
                | EswpError::CtxUnsupported
        ));
    }

    /// Property 12: Envelope encryption round-trip.
    #[test]
    fn property12_envelope_roundtrip(input in arb_encrypt_request_input()) {
        let encrypted = encode_encryption(&input);
        let decrypted = decrypt_presig(&DecryptRequest {
            taker_secret: &input.taker_secret,
            envelope: &encrypted.envelope,
            context: input.context,
        }).expect("decrypt");
        prop_assert_eq!(decrypted.plaintext, input.presig);
    }

    /// Property 13: Envelope wrong-key rejection.
    #[test]
    fn property13_envelope_wrong_key_rejection(
        input in arb_encrypt_request_input(),
        wrong_secret in arb_secret_key_bytes(),
    ) {
        prop_assume!(wrong_secret != input.taker_secret);
        let encrypted = encode_encryption(&input);
        let result = decrypt_presig(&DecryptRequest {
            taker_secret: &wrong_secret,
            envelope: &encrypted.envelope,
            context: input.context,
        });
        prop_assert!(matches!(result, Err(EnvelopeError::Aead)));
    }

    /// Property 14: Envelope tamper detection (ciphertext/tag tampering).
    #[test]
    fn property14_envelope_tamper_detection_ciphertext(input in arb_encrypt_request_input()) {
        let encrypted = encode_encryption(&input);
        let mut tampered = encrypted.envelope.clone();
        if tampered.ciphertext.is_empty() {
            tampered.tag[0] ^= 0x01;
        } else {
            tampered.ciphertext[0] ^= 0x01;
        }
        let result = decrypt_presig(&DecryptRequest {
            taker_secret: &input.taker_secret,
            envelope: &tampered,
            context: input.context,
        });
        prop_assert!(matches!(result, Err(EnvelopeError::Aead)));
    }

    /// Property 14: Envelope tamper detection (AAD/context tampering).
    #[test]
    fn property14_envelope_tamper_detection_aad(input in arb_encrypt_request_input()) {
        let encrypted = encode_encryption(&input);
        let mut wrong_context = input.context;
        wrong_context.version = wrong_context.version.wrapping_add(1);
        let result = decrypt_presig(&DecryptRequest {
            taker_secret: &input.taker_secret,
            envelope: &encrypted.envelope,
            context: wrong_context,
        });
        prop_assert!(matches!(result, Err(EnvelopeError::Aead)));
    }

    #[test]
    fn envelope_wire_roundtrip_with_generated_envelope(envelope in arb_envelope()) {
        let bytes = envelope.to_bytes();
        let decoded = Envelope::from_bytes(&bytes).expect("decode");
        prop_assert_eq!(decoded, envelope);
    }
}
