use std::time::{SystemTime, UNIX_EPOCH};

use crate::{generate, verify_delta, GenerationError};

pub struct Totp {
    key: String,
    time_offset: Option<u64>,
    digest: Option<Vec<u8>>,
}

impl Totp {
    pub fn new(key: String) -> Totp {
        Totp {
            key,
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
            Some(0), // TODO make window a parameter
            self.digest.clone(),
        )
    }

    fn get_counter<'a>(&'a self)  -> u64 {
        let start = SystemTime::now();
        let epoch = start.duration_since(UNIX_EPOCH).unwrap();
        epoch.as_secs() / 30
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
