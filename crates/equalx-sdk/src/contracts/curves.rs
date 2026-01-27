use alloy_sol_types::sol;

sol! {
    /// Full descriptor supplied when creating or filling a commitment curve.
    struct CurveDescriptor {
        bytes32 deskId;
        uint256 bucketId;
        address tokenA;
        address tokenB;
        bool side;
        bool priceIsQuotePerBase;
        uint128 maxVolume;
        uint128 startPrice;
        uint128 endPrice;
        uint64 startTime;
        uint64 duration;
        uint32 generation;
        uint16 feeRateBps;
        uint8 feeAsset;
        uint16 supportBps;
        address supportAddress;
        uint96 salt;
    }

    struct CurveUpdateParams {
        uint128 startPrice;
        uint128 endPrice;
        uint64 startTime;
        uint64 duration;
    }

    /// Minimal onchain storage payload for a curve commitment.
    struct StoredCurve {
        bytes32 commitment;
        uint128 remainingVolume;
        uint64 endTime;
        uint32 generation;
        bool active;
    }
}
