use monero_wallet_core::model::OwnedOutput;
use monero_wallet_core::{SpendFilter, SpendableSet};

#[test]
fn spendable_filter_sorts_and_filters() {
    let v = vec![
        OwnedOutput {
            block_height: 100,
            global_index: 5,
            amount: 7,
            ..fake()
        },
        OwnedOutput {
            block_height: 50,
            global_index: 1,
            amount: 2,
            ..fake()
        },
        OwnedOutput {
            block_height: 60,
            global_index: 2,
            amount: 9,
            ..fake()
        },
    ];
    let as_of = 120;
    let f = SpendFilter {
        min_confirmations: 10,
        min_amount: 5,
        as_of_height: as_of,
    };
    let got = SpendableSet::filter(&v, f);
    assert_eq!(got.len(), 2);
    assert!(got[0].block_height <= got[1].block_height);
}

fn fake() -> OwnedOutput {
    OwnedOutput {
        txid: [0u8; 32],
        out_index_in_tx: 0,
        amount: 0,
        global_index: 0,
        mask: [0u8; 32],
        one_time_pubkey: [0u8; 32],
        subaddr_account: 0,
        subaddr_index: 0,
        unlock_time: 0,
        block_height: 0,
        key_image: Some([1u8; 32]),
    }
}
