use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct ScanCursor {
    pub next_height: u64,
}

pub trait WalletStore: Send + Sync + 'static {
    fn put<T: Serialize>(&self, key: &str, value: &T) -> anyhow::Result<()>;
    fn get<T: DeserializeOwned>(&self, key: &str) -> anyhow::Result<Option<T>>;
    fn del(&self, key: &str) -> anyhow::Result<()>;
    // Convenience: namespaced collections
    fn put_owned_output(&self, out: &crate::model::OwnedOutput) -> anyhow::Result<()>;
    fn list_owned_outputs(&self) -> anyhow::Result<Vec<crate::model::OwnedOutput>>;
    fn put_cursor(&self, c: ScanCursor) -> anyhow::Result<()>;
    fn get_cursor(&self) -> anyhow::Result<ScanCursor>;
}

#[derive(Default)]
pub struct InMemoryStore {
    kv: parking_lot::RwLock<BTreeMap<String, Vec<u8>>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl WalletStore for InMemoryStore {
    fn put<T: Serialize>(&self, key: &str, value: &T) -> anyhow::Result<()> {
        let bytes = bincode::serialize(value)?;
        self.kv.write().insert(key.to_string(), bytes);
        Ok(())
    }

    fn get<T: DeserializeOwned>(&self, key: &str) -> anyhow::Result<Option<T>> {
        self.kv
            .read()
            .get(key)
            .map(|v| bincode::deserialize(v))
            .transpose()
            .map_err(Into::into)
    }

    fn del(&self, key: &str) -> anyhow::Result<()> {
        self.kv.write().remove(key);
        Ok(())
    }

    fn put_owned_output(&self, out: &crate::model::OwnedOutput) -> anyhow::Result<()> {
        let k = format!("owned/{}:{}", hex::encode(out.txid), out.global_index);
        self.put(&k, out)
    }

    fn list_owned_outputs(&self) -> anyhow::Result<Vec<crate::model::OwnedOutput>> {
        let m = self.kv.read();
        let mut v = Vec::new();
        for (k, val) in m.iter() {
            if k.starts_with("owned/") {
                v.push(bincode::deserialize(val)?);
            }
        }
        Ok(v)
    }

    fn put_cursor(&self, c: ScanCursor) -> anyhow::Result<()> {
        self.put("scan/cursor", &c)
    }

    fn get_cursor(&self) -> anyhow::Result<ScanCursor> {
        Ok(self.get("scan/cursor")?.unwrap_or_default())
    }
}
