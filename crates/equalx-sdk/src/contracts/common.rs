use alloy_primitives::B256;

/// Hash returned by the transport after executing an EVM transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxHash(pub B256);

impl TxHash {
    pub fn bytes(self) -> [u8; 32] {
        self.0.into()
    }
}

impl From<B256> for TxHash {
    fn from(value: B256) -> Self {
        Self(value)
    }
}
