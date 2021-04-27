use std::time::{SystemTime, UNIX_EPOCH};

pub fn generate() {}
pub fn verify() {}
pub fn verify_delta() {}
fn get_counter() -> u64 {
  let start = SystemTime::now();
  let since_the_epoch = start
      .duration_since(UNIX_EPOCH)
      .unwrap(); // TODO for simplicity, im gong to unwrap here instead of catch errors. If this throws an error, it might indicate worse issues
  since_the_epoch.as_secs() / 30
}
