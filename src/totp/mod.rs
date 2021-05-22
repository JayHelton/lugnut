use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{digest, generate, verify_delta, Algorithm, GenerationError};

pub struct Totp {
    key: String,
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
    /// let mut totp_builder = Totp::new("my secret".to_string());
    /// ```
    pub fn new(key: String) -> Totp {
        Totp {
            key,
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
    /// let mut totp_builder = Totp::new("my secret".to_string());
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
    /// let mut totp_builder = Totp::new("my secret".to_string());
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
    /// let mut totp_builder = Totp::new("my secret".to_string());
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
    /// let mut totp_builder = Totp::new("my secret".to_string());
    /// let code = totp_builder.generate();
    /// ```
    pub fn generate<'a>(&'a mut self) -> std::result::Result<String, GenerationError> {
        let counter = self.get_counter() as u128;
        if self.digest.is_empty() {
            self.digest = digest(self.key.clone(), counter, Algorithm::Sha1)?;
        }
        generate(self.key.clone(), counter, 6, self.digest.clone())
    }

    /// Verify a Time-based OTP.
    ///
    /// # Examples
    ///
    /// ```
    /// use lugnut::totp::Totp;
    /// let mut totp_builder = Totp::new("my secret".to_string());
    /// let verified = totp_builder.verify("1234".to_string());
    /// ```
    pub fn verify<'a>(&'a mut self, token: String) -> std::result::Result<bool, GenerationError> {
        let counter = self.get_counter();
        let windowed_counter = (counter - self.window) as u128;
        if self.digest.is_empty() {
            self.digest = digest(self.key.clone(), windowed_counter, Algorithm::Sha1)?;
        }
        verify_delta(
            token,
            self.key.clone(),
            windowed_counter,
            6,
            self.window + self.window,
            self.digest.clone(),
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
        let mut totp = Totp::new("my secret key".to_string());
        let code = totp.generate().expect("borked");
        let verified = totp.verify(code).expect("borked here too");
        assert!(verified);
    }

    #[test]
    fn assert_incorrect_otp() {
        let mut totp = Totp::new("my secret key".to_string());
        let _code = totp.generate().expect("borked");
        let verified = totp.verify("wrong".to_string()).expect("borked here too");
        assert!(!verified);
    }
}
