use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{digest, generate, verify_delta, Algorithm, GenerationError};

pub struct Totp {
    epoch_time_offset: u64,
    time: u64,
    step: u64,
    window: u64,
    digest: Vec<u8>,
}

impl Totp {
    /// Returns a new instance of a TOTP Builder.
    ///
    /// # Arguments
    ///
    /// * `secret` - A string of the secret
    ///
    /// # Examples
    ///
    /// ```
    /// use lugnut::totp::Totp;
    /// let mut totp_builder = Totp::new();
    /// ```
    pub fn new() -> Totp {
        Totp {
            window: 0,
            epoch_time_offset: 0,
            time: 0,
            step: 30,
            digest: Vec::new(),
        }
    }

    /// Set an epoch time offset to be used when calculating the time-based counter.
    /// Defaults to 0/
    ///
    /// # Arguments
    ///
    /// * `offset` - Epoch time offset in seconds
    ///
    /// # Examples
    ///
    /// ```
    /// use lugnut::totp::Totp;
    /// let mut totp_builder = Totp::new();
    /// totp_builder.with_epoch_time_offset(500);
    /// ```
    pub fn with_epoch_time_offset<'a>(&'a mut self, offset: u64) -> &'a mut Totp {
        self.epoch_time_offset = offset;
        self
    }

    /// Set the window that will be checked when verifying the OTP.
    /// The window is two-sided, so if the window is set to 5, and the OTP is
    /// counter is 15, 10-20 will be asserted against while verifying.
    ///
    /// Defaults to 0.
    /// # Arguments
    ///
    /// * `window` - The window margin for the OTP verification.
    ///
    /// # Examples
    ///
    /// ```
    /// use lugnut::totp::Totp;
    /// let mut totp_builder = Totp::new();
    /// totp_builder.with_window(5);
    /// ```
    pub fn with_window<'a>(&'a mut self, window: u64) -> &'a mut Totp {
        self.window = window;
        self
    }

    /// Use a self-generated digest.
    ///
    /// # Arguments
    ///
    /// * `digest` - The digest to be used when creating the OTP
    ///
    /// # Examples
    ///
    /// ```
    /// use lugnut::totp::Totp;
    /// let mut totp_builder = Totp::new();
    /// totp_builder.with_digest(vec![1, 2, 3, 4]);
    /// ```
    pub fn with_digest<'a>(&'a mut self, digest: Vec<u8>) -> &'a mut Totp {
        self.digest = digest;
        self
    }

    /// Generate a new Time-based OTP.
    ///
    /// # Examples
    ///
    /// ```
    /// use lugnut::totp::Totp;
    /// let key = "my secret key".to_string();
    /// let mut totp_builder = Totp::new();
    /// let code = totp_builder.generate(key);
    /// ```
    pub fn generate<'a>(&'a self, key: String) -> std::result::Result<String, GenerationError> {
        let counter = self.get_counter() as u128;
        let hash = if self.digest.is_empty() {
            digest(key.clone(), counter, Algorithm::Sha1)?
        } else {
            self.digest.clone()
        };
        generate(key, counter, 6, hash)
    }

    /// Verify a Time-based OTP.
    ///
    /// # Examples
    ///
    /// ```
    /// use lugnut::totp::Totp;
    /// let key = "my secret key".to_string();
    /// let mut totp_builder = Totp::new();
    /// let verified = totp_builder.verify("1234".to_string(), key);
    /// ```
    pub fn verify<'a>(
        &'a self,
        token: String,
        key: String,
    ) -> std::result::Result<bool, GenerationError> {
        let counter = self.get_counter();
        let windowed_counter = (counter - self.window) as u128;
        let hash = if self.digest.is_empty() {
            digest(key.clone(), windowed_counter, Algorithm::Sha1)?
        } else {
            self.digest.clone()
        };
        verify_delta(
            token,
            key,
            windowed_counter,
            6,
            self.window + self.window,
            hash,
        )
    }

    #[doc(hidden)]
    fn get_counter<'a>(&'a self) -> u64 {
        let end = if self.time == 0 {
            SystemTime::now()
        } else {
            UNIX_EPOCH + Duration::from_secs(self.time)
        };

        let start = UNIX_EPOCH + Duration::from_secs(self.epoch_time_offset);

        let epoch = end.duration_since(start).unwrap();
        epoch.as_secs() / self.step
    }
}

#[cfg(test)]
mod totp_tests {
    use super::Totp;
    use std::assert;

    #[test]
    fn assert_correct_otp() {
        let key = "my secret key".to_string();
        let totp = Totp::new();
        let code = totp.generate(key.clone()).expect("borked");
        let verified = totp.verify(code, key).expect("borked here too");
        assert!(verified);
    }

    #[test]
    fn assert_incorrect_otp() {
        let key = "my secret key".to_string();
        let totp = Totp::new();
        let _code = totp.generate(key.clone()).expect("borked");
        let verified = totp
            .verify("wrong".to_string(), key)
            .expect("borked here too");
        assert!(!verified);
    }
}
