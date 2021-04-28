use std::time::{SystemTime, UNIX_EPOCH};

use crate::{generate, verify_delta, GenerationError};

pub struct Totp {
    key: String,
    counter: u64,
    time_offset: Option<u64>,
    digest: Option<Vec<u8>>,
}

impl Totp {
    pub fn new(key: String) -> Totp {
        let start = SystemTime::now();
        let since_the_epoch = start.duration_since(UNIX_EPOCH).unwrap();
        let counter = since_the_epoch.as_secs() / 30;
        Totp {
            key,
            counter,
            time_offset: None,
            digest: None,
        }
    }

    pub fn with_time_offset<'a>(&'a mut self, offset: u64) -> &'a mut Totp {
        self.time_offset = Some(offset);
        self
    }

    pub fn with_digest<'a>(&'a mut self, digest: Vec<u8>) -> &'a mut Totp {
        self.digest = Some(digest);
        self
    }

    pub fn generate<'a>(&'a self) -> std::result::Result<String, GenerationError> {
        generate(
            self.key.clone(),
            self.counter as u128,
            None,
            self.digest.clone(),
        )
    }

    // pub fn verify<'a>(&'a mut self, token: String) -> std::result::Result<bool, GenerationError> {
    //     // verify_delta(
    //     //     token,
    //     //     self.key.clone(),
    //     //     self.counter,
    //     //     None,
    //     //     None,
    //     //     self.digest.clone(),
    //     // )
    // }
}
