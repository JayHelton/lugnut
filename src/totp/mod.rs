use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{generate, verify_delta, GenerationError};

pub struct Totp {
    key: String,
    epoch_time_offset: Option<u64>,
    time: Option<u64>,
    step: u64,
    window: Option<u32>,
    digest: Option<Vec<u8>>,
}

impl Totp {
    pub fn new(key: String) -> Totp {
        Totp {
            key,
            window: Some(60),
            epoch_time_offset: None,
            time: None,
            step: 30,
            digest: None,
        }
    }

    pub fn with_epoch__time_offset<'a>(&'a mut self, offset: u64) -> &'a mut Totp {
        self.epoch_time_offset = Some(offset);
        self
    }

    pub fn with_window<'a>(&'a mut self, window: u32) -> &'a mut Totp {
        self.window = Some(window);
        self
    }

    pub fn with_digest<'a>(&'a mut self, digest: Vec<u8>) -> &'a mut Totp {
        self.digest = Some(digest);
        self
    }

    pub fn generate<'a>(&'a self) -> std::result::Result<String, GenerationError> {
        generate(
            self.key.clone(),
            self.get_counter() as u128,
            None,
            self.digest.clone(),
        )
    }

    pub fn verify<'a>(&'a mut self, token: String) -> std::result::Result<bool, GenerationError> {
        let counter = self.get_counter();
        verify_delta(
            token,
            self.key.clone(),
            counter as u128,
            None,
            self.window,
            self.digest.clone(),
        )
    }

    fn get_counter<'a>(&'a self) -> u64 {
        let end = if let Some(t) = self.time {
            UNIX_EPOCH + Duration::from_secs(t)
        } else {
            SystemTime::now()
        };
        let start = if let Some(e) = self.epoch_time_offset {
            UNIX_EPOCH + Duration::from_secs(e)
        } else {
            UNIX_EPOCH
        };

        let epoch = end.duration_since(start).unwrap();
        epoch.as_secs() / self.step 
    }
}

#[cfg(test)]
mod totp_tests {
    use std::{thread, time::Duration};

    use super::Totp;

    #[test]
    fn it_works() {
        let mut totp = Totp::new("my secret key".to_string());
        let code = totp.generate().expect("borked");
        println!(" {:?}", code);
        thread::sleep(Duration::from_secs(22));
        let verified = totp.verify(code).expect("borked here too");
        println!(" {:?}", verified);
    }
}
