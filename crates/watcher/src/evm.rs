// SPDX-License-Identifier: Apache-2.0

//! Helpers for decoding AtomicDesk / SettlementEscrow events so dashboards and
//! automation layers can surface reservation metadata and state transitions.
//!
//! The module does **not** perform any RPCs; call sites are expected to feed
//! raw log topics + data gathered from an Ethereum node.

use alloy_primitives::{b256, Address, FixedBytes, B256, U256};
use alloy_sol_types::{sol, SolType};
use anyhow::{anyhow, ensure, Result};
const RESERVATION_CREATED_TOPIC: B256 =
    b256!("bb284251eb13344d6670b853b97e3a219b42869b9c0aca301d23c80f805ec1d1");
const HASHLOCK_SET_TOPIC: B256 =
    b256!("b02f4cb7dd5a3cf6dddc6715fb1f561181a29e6f835adfed54e7370965a01972");
const ATOMIC_RESERVATION_TOPIC: B256 =
    b256!("1ddda36df969a97d0bc292e012733b07078d790ed011aef7fc50118ed19cb1f0");
const RESERVATION_SETTLED_TOPIC: B256 =
    b256!("6be47e61e7f7fd77b4e8201b3ace162fa32be35d1741c6e8d5a37b9463ff6ec8");
const RESERVATION_REFUNDED_TOPIC: B256 =
    b256!("ab528a5b2d7a20115e2f343695e1f2426261c227e7df5fc3ced5365e86a5e3a7");
const TRANCHE_OPENED_TOPIC: B256 =
    b256!("9868774a230125c8dec0be0294563355a987a3c915027e72aceeb2eacc71e556");
const TAKER_TRANCHE_OPENED_TOPIC: B256 =
    b256!("5ef608c488294ad87817c00aaa3f80f4f50416b62b8a5f603b1e3db3404f793f");
const TRANCHE_RESERVED_TOPIC: B256 =
    b256!("f1d082a8c1d907940678bec35245f9c9be7379f8b7306cbbb22671c0bca446fa");
const TAKER_TRANCHE_RESERVED_TOPIC: B256 =
    b256!("b6e30a044e2238b5f350746e7b8a93a129a815a16d2b0edffa4e4acd3e88bc58");

sol! {
    struct ReservationCreatedData {
        uint256 amount;
        uint256 counter;
    }

    struct HashlockSetData {
        bytes32 hashlock;
    }

    struct AtomicReservationData {
        address asset;
        uint256 amount;
        bytes32 settlementDigest;
        uint64 expiry;
        uint64 createdAt;
    }

    struct ReservationSettledData {
        bytes32 tau;
    }

    struct ReservationRefundedData {
        bytes32 evidence;
    }

    struct TrancheOpenedData {
        address asset;
        uint256 priceNumerator;
        uint256 priceDenominator;
        uint256 totalLiquidity;
        uint256 minFill;
        uint16 feeBps;
        uint8 feePayer;
        uint64 expiry;
    }

    struct TakerTrancheOpenedData {
        address asset;
        uint256 priceNumerator;
        uint256 priceDenominator;
        uint256 totalLiquidity;
        uint256 minFill;
        uint16 feeBps;
        uint8 feePayer;
        uint64 expiry;
        uint256 postingFee;
    }

    struct TrancheReservedData {
        uint256 amount;
        uint256 remainingLiquidity;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservationCreatedRecord {
    pub reservation_id: FixedBytes<32>,
    pub taker: Address,
    pub desk: Address,
    pub amount: U256,
    pub counter: U256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashlockSetRecord {
    pub reservation_id: FixedBytes<32>,
    pub hashlock: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AtomicReservationRecord {
    pub reservation_id: FixedBytes<32>,
    pub desk_id: FixedBytes<32>,
    pub taker: Address,
    pub asset: Address,
    pub amount: U256,
    pub settlement_digest: [u8; 32],
    pub expiry: u64,
    pub created_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrancheOpenedRecord {
    pub tranche_id: FixedBytes<32>,
    pub desk_id: FixedBytes<32>,
    pub maker: Address,
    pub asset: Address,
    pub price_numerator: U256,
    pub price_denominator: U256,
    pub total_liquidity: U256,
    pub min_fill: U256,
    pub fee_bps: u16,
    pub fee_payer: u8,
    pub expiry: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TakerTrancheOpenedRecord {
    pub tranche_id: FixedBytes<32>,
    pub desk_id: FixedBytes<32>,
    pub taker: Address,
    pub asset: Address,
    pub price_numerator: U256,
    pub price_denominator: U256,
    pub total_liquidity: U256,
    pub min_fill: U256,
    pub fee_bps: u16,
    pub fee_payer: u8,
    pub expiry: u64,
    pub posting_fee: U256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrancheReservedRecord {
    pub tranche_id: FixedBytes<32>,
    pub reservation_id: FixedBytes<32>,
    pub taker: Address,
    pub amount: U256,
    pub remaining_liquidity: U256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TakerTrancheReservedRecord {
    pub tranche_id: FixedBytes<32>,
    pub reservation_id: FixedBytes<32>,
    pub maker: Address,
    pub amount: U256,
    pub remaining_liquidity: U256,
}

// Legacy QuoteBoard decoding has been removed; watcher focuses on Router / SettlementEscrow events.

/// Decode a `ReservationCreated` event emitted by SettlementEscrow.
pub fn decode_reservation_created(
    topics: &[B256],
    data: &[u8],
) -> Result<ReservationCreatedRecord> {
    ensure!(
        topics.len() >= 4 && topics[0] == RESERVATION_CREATED_TOPIC,
        "not a ReservationCreated log"
    );
    let reservation_id = topic_to_bytes32(topics[1]);
    let taker = topic_to_address(topics[2]);
    let desk = topic_to_address(topics[3]);
    let parsed = ReservationCreatedData::abi_decode(data, true)
        .map_err(|err| anyhow!("decode ReservationCreated: {err}"))?;
    Ok(ReservationCreatedRecord {
        reservation_id,
        taker,
        desk,
        amount: parsed.amount,
        counter: parsed.counter,
    })
}

/// Decode a `HashlockSet` event emitted by SettlementEscrow.
pub fn decode_hashlock_set(topics: &[B256], data: &[u8]) -> Result<HashlockSetRecord> {
    ensure!(
        topics.len() >= 2 && topics[0] == HASHLOCK_SET_TOPIC,
        "not a HashlockSet log"
    );
    let reservation_id = topic_to_bytes32(topics[1]);
    let parsed = HashlockSetData::abi_decode(data, true)
        .map_err(|err| anyhow!("decode HashlockSet: {err}"))?;
    Ok(HashlockSetRecord {
        reservation_id,
        hashlock: parsed.hashlock.into(),
    })
}

/// Decode the AtomicDesk `ReservationCreated` event.
pub fn decode_atomic_reservation_created(
    topics: &[B256],
    data: &[u8],
) -> Result<AtomicReservationRecord> {
    ensure!(
        topics.len() >= 4 && topics[0] == ATOMIC_RESERVATION_TOPIC,
        "not an AtomicDesk ReservationCreated log"
    );
    let reservation_id = topic_to_bytes32(topics[1]);
    let desk_bytes: [u8; 32] = topics[2].into();
    let desk_id = FixedBytes::<32>::from(desk_bytes);
    let taker = topic_to_address(topics[3]);
    let parsed = AtomicReservationData::abi_decode(data, true)
        .map_err(|err| anyhow!("decode AtomicDesk ReservationCreated: {err}"))?;
    Ok(AtomicReservationRecord {
        reservation_id,
        desk_id,
        taker,
        asset: parsed.asset,
        amount: parsed.amount,
        settlement_digest: parsed.settlementDigest.into(),
        expiry: parsed.expiry,
        created_at: parsed.createdAt,
    })
}

/// Decode the AtomicDesk `TrancheOpened` event.
pub fn decode_tranche_opened(topics: &[B256], data: &[u8]) -> Result<TrancheOpenedRecord> {
    ensure!(
        topics.len() >= 4 && topics[0] == TRANCHE_OPENED_TOPIC,
        "not an AtomicDesk TrancheOpened log"
    );
    let tranche_id = topic_to_bytes32(topics[1]);
    let desk_bytes: [u8; 32] = topics[2].into();
    let desk_id = FixedBytes::<32>::from(desk_bytes);
    let maker = topic_to_address(topics[3]);
    let parsed = TrancheOpenedData::abi_decode(data, true)
        .map_err(|err| anyhow!("decode TrancheOpened: {err}"))?;
    Ok(TrancheOpenedRecord {
        tranche_id,
        desk_id,
        maker,
        asset: parsed.asset,
        price_numerator: parsed.priceNumerator,
        price_denominator: parsed.priceDenominator,
        total_liquidity: parsed.totalLiquidity,
        min_fill: parsed.minFill,
        fee_bps: parsed.feeBps,
        fee_payer: parsed.feePayer,
        expiry: parsed.expiry,
    })
}

/// Decode the AtomicDesk `TakerTrancheOpened` event.
pub fn decode_taker_tranche_opened(
    topics: &[B256],
    data: &[u8],
) -> Result<TakerTrancheOpenedRecord> {
    ensure!(
        topics.len() >= 4 && topics[0] == TAKER_TRANCHE_OPENED_TOPIC,
        "not an AtomicDesk TakerTrancheOpened log"
    );
    let tranche_id = topic_to_bytes32(topics[1]);
    let desk_bytes: [u8; 32] = topics[2].into();
    let desk_id = FixedBytes::<32>::from(desk_bytes);
    let taker = topic_to_address(topics[3]);
    let parsed = TakerTrancheOpenedData::abi_decode(data, true)
        .map_err(|err| anyhow!("decode TakerTrancheOpened: {err}"))?;
    Ok(TakerTrancheOpenedRecord {
        tranche_id,
        desk_id,
        taker,
        asset: parsed.asset,
        price_numerator: parsed.priceNumerator,
        price_denominator: parsed.priceDenominator,
        total_liquidity: parsed.totalLiquidity,
        min_fill: parsed.minFill,
        fee_bps: parsed.feeBps,
        fee_payer: parsed.feePayer,
        expiry: parsed.expiry,
        posting_fee: parsed.postingFee,
    })
}

/// Decode the AtomicDesk `TrancheReserved` event.
pub fn decode_tranche_reserved(topics: &[B256], data: &[u8]) -> Result<TrancheReservedRecord> {
    ensure!(
        topics.len() >= 4 && topics[0] == TRANCHE_RESERVED_TOPIC,
        "not an AtomicDesk TrancheReserved log"
    );
    let tranche_id = topic_to_bytes32(topics[1]);
    let reservation_id = topic_to_bytes32(topics[2]);
    let taker = topic_to_address(topics[3]);
    let parsed = TrancheReservedData::abi_decode(data, true)
        .map_err(|err| anyhow!("decode TrancheReserved: {err}"))?;
    Ok(TrancheReservedRecord {
        tranche_id,
        reservation_id,
        taker,
        amount: parsed.amount,
        remaining_liquidity: parsed.remainingLiquidity,
    })
}

/// Decode the AtomicDesk `TakerTrancheReserved` event.
pub fn decode_taker_tranche_reserved(
    topics: &[B256],
    data: &[u8],
) -> Result<TakerTrancheReservedRecord> {
    ensure!(
        topics.len() >= 4 && topics[0] == TAKER_TRANCHE_RESERVED_TOPIC,
        "not an AtomicDesk TakerTrancheReserved log"
    );
    let tranche_id = topic_to_bytes32(topics[1]);
    let reservation_id = topic_to_bytes32(topics[2]);
    let maker = topic_to_address(topics[3]);
    let parsed = TrancheReservedData::abi_decode(data, true)
        .map_err(|err| anyhow!("decode TakerTrancheReserved: {err}"))?;
    Ok(TakerTrancheReservedRecord {
        tranche_id,
        reservation_id,
        maker,
        amount: parsed.amount,
        remaining_liquidity: parsed.remainingLiquidity,
    })
}

fn topic_to_bytes32(topic: B256) -> FixedBytes<32> {
    let bytes: [u8; 32] = topic.into();
    FixedBytes::<32>::from(bytes)
}

fn topic_to_address(topic: B256) -> Address {
    let bytes: [u8; 32] = topic.into();
    Address::from_slice(&bytes[12..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, B256};
    use alloy_sol_types::SolValue;

    fn encode_address_topic(addr: Address) -> B256 {
        let mut buf = [0u8; 32];
        buf[12..].copy_from_slice(addr.as_slice());
        B256::from(buf)
    }

    #[test]
    fn decode_reservation_created_event() {
        let reservation_bytes = [0x07u8; 32];
        let reservation_id = FixedBytes::<32>::from(reservation_bytes);
        let taker = address!("0x7777777777777777777777777777777777777777");
        let desk = address!("0x8888888888888888888888888888888888888888");
        let amount = U256::from(5_000u64);
        let counter = U256::from(321u64);
        let topics = vec![
            RESERVATION_CREATED_TOPIC,
            B256::from(reservation_bytes),
            encode_address_topic(taker),
            encode_address_topic(desk),
        ];
        let data = SolValue::abi_encode(&ReservationCreatedData {
            amount,
            counter,
        });

        let record = decode_reservation_created(&topics, &data).expect("decode reservation");
        assert_eq!(record.reservation_id, reservation_id);
        assert_eq!(record.taker, taker);
        assert_eq!(record.desk, desk);
        assert_eq!(record.amount, amount);
        assert_eq!(record.counter, counter);
    }

    #[test]
    fn decode_hashlock_set_event() {
        let reservation_bytes = [0x09u8; 32];
        let reservation_id = FixedBytes::<32>::from(reservation_bytes);
        let hashlock = [0xABu8; 32];
        let topics = vec![HASHLOCK_SET_TOPIC, B256::from(reservation_bytes)];
        let data = SolValue::abi_encode(&HashlockSetData {
            hashlock: FixedBytes::<32>::from(hashlock),
        });

        let record = decode_hashlock_set(&topics, &data).expect("decode hashlock");
        assert_eq!(record.reservation_id, reservation_id);
        assert_eq!(record.hashlock, hashlock);
    }

    #[test]
    fn decode_atomic_reservation_created_event() {
        let reservation_bytes = [0x23u8; 32];
        let reservation_id = FixedBytes::<32>::from(reservation_bytes);
        let desk_bytes = [0x11u8; 32];
        let desk_id = FixedBytes::<32>::from(desk_bytes);
        let taker = address!("0x9999999999999999999999999999999999999999");
        let asset = address!("0x1111111111111111111111111111111111111111");
        let amount = U256::from(456u64);
        let digest = [0x22u8; 32];
        let expiry = 1_650_000_000u64;
        let created_at = 1_650_000_500u64;
        let topics = vec![
            ATOMIC_RESERVATION_TOPIC,
            B256::from(reservation_bytes),
            B256::from(desk_bytes),
            encode_address_topic(taker),
        ];
        let data = SolValue::abi_encode(&AtomicReservationData {
            asset,
            amount,
            settlementDigest: FixedBytes::<32>::from(digest),
            expiry,
            createdAt: created_at,
        });

        let record =
            decode_atomic_reservation_created(&topics, &data).expect("decode atomic reservation");
        assert_eq!(record.reservation_id, reservation_id);
        assert_eq!(record.desk_id, desk_id);
        assert_eq!(record.taker, taker);
        assert_eq!(record.asset, asset);
        assert_eq!(record.amount, amount);
        assert_eq!(record.settlement_digest, digest);
        assert_eq!(record.expiry, expiry);
        assert_eq!(record.created_at, created_at);
    }

    #[test]
    fn decode_tranche_opened_event() {
        let tranche_bytes = [0x44u8; 32];
        let tranche_id = FixedBytes::<32>::from(tranche_bytes);
        let desk_bytes = [0x55u8; 32];
        let desk_id = FixedBytes::<32>::from(desk_bytes);
        let maker = address!("0x1111111111111111111111111111111111111111");
        let asset = address!("0x2222222222222222222222222222222222222222");
        let topics = vec![
            TRANCHE_OPENED_TOPIC,
            B256::from(tranche_bytes),
            B256::from(desk_bytes),
            encode_address_topic(maker),
        ];
        let data = SolValue::abi_encode(&TrancheOpenedData {
            asset,
            priceNumerator: U256::from(5_000u64),
            priceDenominator: U256::from(10_000u64),
            totalLiquidity: U256::from(8_000u64),
            minFill: U256::from(1_000u64),
            feeBps: 125,
            feePayer: 1,
            expiry: 1_700_000_000u64,
        });

        let record = decode_tranche_opened(&topics, &data).expect("decode tranche opened");
        assert_eq!(record.tranche_id, tranche_id);
        assert_eq!(record.desk_id, desk_id);
        assert_eq!(record.maker, maker);
        assert_eq!(record.asset, asset);
        assert_eq!(record.price_numerator, U256::from(5_000u64));
        assert_eq!(record.price_denominator, U256::from(10_000u64));
        assert_eq!(record.total_liquidity, U256::from(8_000u64));
        assert_eq!(record.min_fill, U256::from(1_000u64));
        assert_eq!(record.fee_bps, 125);
        assert_eq!(record.fee_payer, 1);
        assert_eq!(record.expiry, 1_700_000_000u64);
    }

    #[test]
    fn decode_taker_tranche_opened_event() {
        let tranche_bytes = [0x66u8; 32];
        let tranche_id = FixedBytes::<32>::from(tranche_bytes);
        let desk_bytes = [0x77u8; 32];
        let desk_id = FixedBytes::<32>::from(desk_bytes);
        let taker = address!("0x3333333333333333333333333333333333333333");
        let asset = address!("0x4444444444444444444444444444444444444444");
        let topics = vec![
            TAKER_TRANCHE_OPENED_TOPIC,
            B256::from(tranche_bytes),
            B256::from(desk_bytes),
            encode_address_topic(taker),
        ];
        let data = SolValue::abi_encode(&TakerTrancheOpenedData {
            asset,
            priceNumerator: U256::from(2_000u64),
            priceDenominator: U256::from(3_000u64),
            totalLiquidity: U256::from(9_000u64),
            minFill: U256::from(500u64),
            feeBps: 250,
            feePayer: 0,
            expiry: 1_800_000_000u64,
            postingFee: U256::from(12_345u64),
        });

        let record =
            decode_taker_tranche_opened(&topics, &data).expect("decode taker tranche opened");
        assert_eq!(record.tranche_id, tranche_id);
        assert_eq!(record.desk_id, desk_id);
        assert_eq!(record.taker, taker);
        assert_eq!(record.asset, asset);
        assert_eq!(record.price_numerator, U256::from(2_000u64));
        assert_eq!(record.price_denominator, U256::from(3_000u64));
        assert_eq!(record.total_liquidity, U256::from(9_000u64));
        assert_eq!(record.min_fill, U256::from(500u64));
        assert_eq!(record.fee_bps, 250);
        assert_eq!(record.fee_payer, 0);
        assert_eq!(record.expiry, 1_800_000_000u64);
        assert_eq!(record.posting_fee, U256::from(12_345u64));
    }

    #[test]
    fn decode_tranche_reserved_event() {
        let tranche_bytes = [0x88u8; 32];
        let reservation_bytes = [0x99u8; 32];
        let tranche_id = FixedBytes::<32>::from(tranche_bytes);
        let reservation_id = FixedBytes::<32>::from(reservation_bytes);
        let taker = address!("0x5555555555555555555555555555555555555555");
        let topics = vec![
            TRANCHE_RESERVED_TOPIC,
            B256::from(tranche_bytes),
            B256::from(reservation_bytes),
            encode_address_topic(taker),
        ];
        let data = SolValue::abi_encode(&TrancheReservedData {
            amount: U256::from(777u64),
            remainingLiquidity: U256::from(888u64),
        });

        let record = decode_tranche_reserved(&topics, &data).expect("decode tranche reserved");
        assert_eq!(record.tranche_id, tranche_id);
        assert_eq!(record.reservation_id, reservation_id);
        assert_eq!(record.taker, taker);
        assert_eq!(record.amount, U256::from(777u64));
        assert_eq!(record.remaining_liquidity, U256::from(888u64));
    }

    #[test]
    fn decode_reservation_settled_and_refunded_events() {
        let reservation_bytes = [0xAAu8; 32];
        let reservation_id = FixedBytes::<32>::from(reservation_bytes);
        let tau = [0x55u8; 32];
        let settled_topics = vec![RESERVATION_SETTLED_TOPIC, B256::from(reservation_bytes)];
        let settled_data = SolValue::abi_encode(&ReservationSettledData {
            tau: FixedBytes::<32>::from(tau),
        });
        let (decoded_id, decoded_tau) =
            decode_reservation_settled(&settled_topics, &settled_data).expect("decode settled");
        assert_eq!(decoded_id, reservation_id);
        assert_eq!(decoded_tau, tau);
        assert!(decode_reservation_settled(&settled_topics[..1], &settled_data).is_err());

        let refunded_topics = vec![RESERVATION_REFUNDED_TOPIC, B256::from(reservation_bytes)];
        let evidence = [0x99u8; 32];
        let refunded_data = SolValue::abi_encode(&ReservationRefundedData {
            evidence: FixedBytes::<32>::from(evidence),
        });
        let (decoded_id, decoded_evidence) =
            decode_reservation_refunded(&refunded_topics, &refunded_data).expect("decode refunded");
        assert_eq!(decoded_id, reservation_id);
        assert_eq!(decoded_evidence, evidence);
        assert!(decode_reservation_refunded(&refunded_topics[..1], &refunded_data).is_err());
    }
}

/// Decode a `ReservationSettled` event emitted by SettlementEscrow.
pub fn decode_reservation_settled(
    topics: &[B256],
    data: &[u8],
) -> Result<(FixedBytes<32>, [u8; 32])> {
    ensure!(
        topics.len() >= 2 && topics[0] == RESERVATION_SETTLED_TOPIC,
        "not a ReservationSettled log"
    );
    let reservation_id = topic_to_bytes32(topics[1]);
    let parsed = ReservationSettledData::abi_decode(data, true)
        .map_err(|err| anyhow!("decode ReservationSettled: {err}"))?;
    Ok((reservation_id, parsed.tau.into()))
}

/// Decode a `ReservationRefunded` event emitted by SettlementEscrow.
pub fn decode_reservation_refunded(
    topics: &[B256],
    data: &[u8],
) -> Result<(FixedBytes<32>, [u8; 32])> {
    ensure!(
        topics.len() >= 2 && topics[0] == RESERVATION_REFUNDED_TOPIC,
        "not a ReservationRefunded log"
    );
    let reservation_id = topic_to_bytes32(topics[1]);
    let parsed = ReservationRefundedData::abi_decode(data, true)
        .map_err(|err| anyhow!("decode ReservationRefunded: {err}"))?;
    Ok((reservation_id, parsed.evidence.into()))
}
