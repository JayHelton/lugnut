use crate::{digest, generate, verify_delta, Algorithm, GenerationError};

pub struct Hotp {
    key: String,
    counter: u128,
    digits: u32,
    window: u32,
    digest: Option<Vec<u8>>,
}

impl Hotp {
    pub fn new(key: String, counter: u128) -> Hotp {
        Hotp {
            key,
            counter,
            digits: 6,
            window: 10,
            digest: None,
        }
    }

    pub fn of_n_length<'a>(&'a mut self, n: u32) -> &'a mut Hotp {
        self.digits = n;
        self
    }

    pub fn with_digest<'a>(&'a mut self, digest: Vec<u8>) -> &'a mut Hotp {
        self.digest = Some(digest);
        self
    }

    pub fn with_window<'a>(&'a mut self, window: u32) -> &'a mut Hotp {
        self.window = window;
        self
    }

    pub fn generate<'a>(&'a self) -> std::result::Result<String, GenerationError> {
        let digest_hash = if let Some(d) = self.digest {
            d
        } else {
            digest(self.key, self.counter, Algorithm::Sha1)?
        };
        generate(
            self.key.clone(),
            self.counter,
            self.digits,
            digest_hash.clone(),
        )
    }

    pub fn verify<'a>(&'a mut self, token: String) -> std::result::Result<bool, GenerationError> {
        let digest_hash = if let Some(d) = self.digest {
            d
        } else {
            digest(self.key, self.counter, Algorithm::Sha1)?
        };
        verify_delta(
            token,
            self.key.clone(),
            self.counter,
            self.digits,
            self.window,
            digest_hash,
        )
    }
}

#[cfg(test)]
mod tests_generate {
    use crate::generate_secret;
    use crate::hotp::Hotp;

    #[test]
    fn test_generate_hotp_default() {
        let key = generate_secret();
        let hotp = Hotp::new(key, 100);
        let pad = match hotp.generate() {
            Ok(h) => h,
            _ => String::from(""),
        };
        assert_eq!(pad.len(), 6);
    }

    #[test]
    fn test_generate_hotp_custom_length() {
        let key = generate_secret();
        let mut hotp = Hotp::new(key, 100);
        hotp.of_n_length(50);
        let pad = match hotp.generate() {
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
        let mut hotp = Hotp::new(key, 100);
        hotp.of_n_length(digits);
        hotp.with_digest(defined_digest.clone());
        let pad = match hotp.generate() {
            Ok(h) => h,
            _ => String::from(""),
        };
        let verified = if let Ok(v) = hotp.verify(pad) {
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
        let hotp = Hotp::new(key, counter);
        let pad = match hotp.generate() {
            Ok(h) => h,
            _ => String::from(""),
        };
        assert_eq!(pad.len(), 6);
    }

    #[test]
    fn test_builder_pattern_n_length() {
        let key = String::from("SuperSecretKey");
        let counter = 100;
        let mut hotp = Hotp::new(key, counter);
        hotp.of_n_length(10);
        let pad = match hotp.generate() {
            Ok(h) => h,
            _ => String::from(""),
        };
        assert_eq!(pad.len(), 10);
    }

    #[test]
    fn test_builder_pattern_verify() {
        let key = String::from("SuperSecretKey"); // Generates a otp of 0897822634
        let counter = 100;
        let mut hotp = Hotp::new(key, counter);
        hotp.of_n_length(10);
        let pad = match hotp.generate() {
            Ok(h) => h,
            _ => String::from(""),
        };
        let result_correct = if let Ok(v) = hotp.verify(pad) {
            v
        } else {
            false
        };
        let result_fail = if let Ok(v) = hotp.verify(String::from("This should not verify")) {
            v
        } else {
            false
        };
        assert_eq!(true, result_correct);
        assert_eq!(false, result_fail);
    }
}
