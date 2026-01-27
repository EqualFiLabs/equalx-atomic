use crate::model::OwnedOutput;
#[derive(Clone, Copy, Debug, Default)]
pub struct SpendFilter {
    pub min_confirmations: u64,
    pub min_amount: u64,
    pub as_of_height: u64,
}
pub struct SpendableSet;
impl SpendableSet {
    pub fn filter(outputs: &[OwnedOutput], f: SpendFilter) -> Vec<&OwnedOutput> {
        let mut filtered: Vec<&OwnedOutput> = outputs
            .iter()
            .filter(|o| {
                let confs = f.as_of_height.saturating_sub(o.block_height) + 1;
                confs >= f.min_confirmations
                    && o.amount >= f.min_amount
                    && (o.unlock_time <= o.block_height || o.unlock_time <= f.as_of_height)
            })
            .collect();
        filtered.sort_by_key(|o| (o.block_height, o.global_index));
        filtered
    }
}
