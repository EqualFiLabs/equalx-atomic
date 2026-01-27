use monero_rpc::MoneroRpc;
use monero_wallet_core::{InMemoryStore, ScanParams, Scanner, SubAddr, WalletConfig};

fn main() -> anyhow::Result<()> {
    let mut spend_pub = [0u8; 32];
    spend_pub[0] = 9; // replace in real usage
    let cfg = WalletConfig {
        view_key: [0u8; 32], // replace in real usage
        spend_pub,
        spend_key: None,
        subaddrs: vec![SubAddr {
            account: 0,
            index: 0,
            label: None,
        }],
        network: "stagenet".into(),
    };
    let store = InMemoryStore::new();
    let rpc = MoneroRpc::new("http://127.0.0.1:38081", None)?;
    let scanner = Scanner::new(cfg, store, rpc);
    scanner.scan(&ScanParams {
        start_height: Some(1_000_000),
        end_height_inclusive: Some(1_000_100),
    })?;
    for o in scanner.list_owned()? {
        println!(
            "owned: txid={}, gidx={}, amt={}",
            hex::encode(o.txid),
            o.global_index,
            o.amount
        );
    }
    Ok(())
}
