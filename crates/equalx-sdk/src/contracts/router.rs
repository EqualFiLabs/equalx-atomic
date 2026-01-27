use alloy_sol_types::sol;

sol! {
    #[allow(non_camel_case_types)]
    contract Router {
        struct DirectIntent {
            uint256 curveId;
            uint128 amountIn;
            uint128 minAmountOut;
            uint64 userDeadline;
        }
    }
}
