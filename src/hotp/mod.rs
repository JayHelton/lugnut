use crate::{digest, generate, verify_delta, Algorithm, GenerationError};

pub struct Hotp {
    window: u64,
    digits: u32,
    digest: Vec<u8>,
}
impl Hotp {
    pub fn new() -> Hotp {
        Hotp {
            window: 0,
            digits: 6,
            digest: Vec::new(),
        }
    }
    pub fn with_length<'a>(&'a mut self, n: u32) -> &'a mut Hotp {
        self.digits = n;
        self
    }
    pub fn with_digest<'a>(&'a mut self, digest: Vec<u8>) -> &'a mut Hotp {
        self.digest = digest;
        self
    }
    pub fn with_window<'a>(&'a mut self, window: u64) -> &'a mut Hotp {
        self.window = window;
        self
    }
    pub fn generate<'a>(
        &'a self,
        key: String,
        counter: u128,
    ) -> std::result::Result<String, GenerationError> {
        let hash = if self.digest.is_empty() {
            digest(key.clone(), counter, Algorithm::Sha1)?
        } else {
            self.digest.clone()
        };
        generate(key, counter, self.digits, hash)
    }
    pub fn verify<'a>(
        &'a self,
        token: String,
        key: String,
        counter: u128,
    ) -> std::result::Result<bool, GenerationError> {
        let hash = if self.digest.is_empty() {
            digest(key.clone(), counter, Algorithm::Sha1)?
        } else {
            self.digest.clone()
        };
        verify_delta(token, key, counter, self.digits, self.window, hash)
    }
}

#[cfg(test)]
mod tests_generate {
    use crate::generate_secret;
    use crate::hotp::Hotp;

    #[test]
    fn test_generate_hotp_default() {
        let key = generate_secret();
        let mut hotp = Hotp::new();
        let pad = match hotp.generate(key, 100) {
            Ok(h) => h,
            _ => String::from(""),
        };
        assert_eq!(pad.len(), 6);
    }

    #[test]
    fn test_generate_hotp_custom_length() {
        let key = generate_secret();
        let mut hotp = Hotp::new();
        hotp.with_length(50);
        let pad = match hotp.generate(key, 100) {
            Ok(h) => h,
            _ => String::from(""),
        };
        assert_eq!(pad.len(), 50);
    }
}

#[cfg(test)]
mod tests_verify {
    use crate::hotp::Hotp;
    use crate::{digest, Algorithm};

    #[test]
    fn test_verify() {
        let key = String::from("SuperSecretKey"); // Generates a otp of 0897822634
        let counter = 100;
        let digits = 10;
        let defined_digest = if let Ok(d) = digest(key.clone(), counter, Algorithm::Sha1) {
            d
        } else {
            vec![]
        };
        let mut hotp = Hotp::new();
        hotp.with_length(digits);
        hotp.with_digest(defined_digest.clone());
        let pad = match hotp.generate(key.clone(), 100) {
            Ok(h) => h,
            _ => String::from(""),
        };
        let verified = if let Ok(v) = hotp.verify(pad, key, 100) {
            v
        } else {
            false
        };
        assert_eq!(true, verified);
    }
}

#[cfg(test)]
mod test_builder_pattern {
    use crate::hotp::Hotp;

    #[test]
    fn test_builder_pattern_default() {
        let key = String::from("SuperSecretKey");
        let counter = 100;
        let hotp = Hotp::new();
        let pad = match hotp.generate(key, counter) {
            Ok(h) => h,
            _ => String::from(""),
        };
        assert_eq!(pad.len(), 6);
    }

    #[test]
    fn test_builder_pattern_n_length() {
        let key = String::from("SuperSecretKey");
        let counter = 100;
        let mut hotp = Hotp::new();
        hotp.with_length(10);
        let pad = match hotp.generate(key, counter) {
            Ok(h) => h,
            _ => String::from(""),
        };
        assert_eq!(pad.len(), 10);
    }

    #[test]
    fn test_builder_pattern_verify() {
        let key = String::from("SuperSecretKey"); // Generates a otp of 0897822634
        let counter = 100;
        let mut hotp = Hotp::new();
        hotp.with_length(10);
        let pad = match hotp.generate(key.clone(), counter) {
            Ok(h) => h,
            _ => String::from(""),
        };
        let result_correct = if let Ok(v) = hotp.verify(pad, key.clone(), counter) {
            v
        } else {
            false
        };
        let result_fail =
            if let Ok(v) = hotp.verify(String::from("This should not verify"), key, counter) {
                v
            } else {
                false
            };
        assert_eq!(true, result_correct);
        assert_eq!(false, result_fail);
    }
}
