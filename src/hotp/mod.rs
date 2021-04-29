use crate::{digest, Algorithm, GenerationError};

pub struct Hotp {
    key: String,
    counter: u128,
    window: Option<u32>,
    digits: Option<u32>,
    digest: Option<Vec<u8>>,
}
impl Hotp {
    pub fn new(key: String, counter: u128) -> Hotp {
        Hotp {
            key,
            counter,
            window: None,
            digits: None,
            digest: None
        }
    }
    pub fn of_length<'a>(&'a mut self, n: u32) -> &'a mut Hotp {
        self.digits = Some(n);
        self
    }
    pub fn with_digest<'a>(&'a mut self, digest: Vec<u8>) -> &'a mut Hotp {
        self.digest = Some(digest);
        self
    }
    pub fn with_window<'a>(&'a mut self, window: u32) -> &'a mut Hotp {
        self.window = Some(window);
        self
    }
    pub fn generate<'a>(&'a self) -> std::result::Result<String, GenerationError> {
        generate_root(self.key.clone(), self.counter, self.digits, self.digest.clone())
    }
    pub fn verify<'a>(&'a mut self, token: String) -> std::result::Result<bool, GenerationError> {
        verify_delta_root(token, self.key.clone(), self.counter, self.digits, self.window, self.digest.clone())
    }
}


/// This section works to fill up the unsigned 32 bit number by:
/// 1.  Taking the 8 bits at the offset from the digest, AND'ing with 0x7f so that we can ignore the sign bit
/// and then bit shifting 24 to the left to fill the most significant bits.
/// 2.  Taking the next 8 bits from the digest at (offset + 1), AND'ing with 0xff to get the set bits, shifting 16 to fill
/// the next 8 significant bits.
/// 3.  Same as (2.) but taking the bits from (offset + 2)
/// 4.  Same as (2.) but taking the bits from (offset + 3)
/// 5.  OR'ing each of these u32 so that we collapse all of the set bits into one u32
#[doc(hidden)]
fn generate_root(
    key: String,
    counter: u128,
    digits: Option<u32>,
    digest_arg: Option<Vec<u8>>,
) -> std::result::Result<String, GenerationError> {
    let defined_digits = if let Some(d) = digits { d } else { 6 };
    let defined_digest = if let Some(d) = digest_arg {
        d
    } else {
        digest(key, counter, Algorithm::Sha1)?
    };

    let offset = if let Some(o) = defined_digest.last() {
        o & 0xf
    } else {
        0
    };

    let no_offset = if let Some(o) = defined_digest.get(offset as usize) {
        u32::from(o.clone() & 0x7f) << 24
    } else {
        0
    };
    let one_offset = if let Some(o) = defined_digest.get((offset + 1) as usize) {
        u32::from(o.clone() & 0xff) << 16
    } else {
        0
    };
    let two_offset = if let Some(o) = defined_digest.get((offset + 2) as usize) {
        u32::from(o.clone() & 0xff) << 8
    } else {
        0
    };
    let three_offset = if let Some(o) = defined_digest.get((offset + 3) as usize) {
        u32::from(o.clone() & 0xff)
    } else {
        0
    };
    let code = no_offset | one_offset | two_offset | three_offset;

    if code == 0 {
        Err(GenerationError::FailedToGenerateHOTP())
    } else {
        let padded_string = format!(
            "{:0>width$}",
            code.to_string(),
            width = defined_digits as usize
        );
        Ok(
            (&padded_string[(padded_string.len() - defined_digits as usize)..padded_string.len()])
                .to_string(),
        )
    }
}

#[doc(hidden)]
fn verify_delta_root(
    token: String,
    key: String,
    counter: u128,
    digits: Option<u32>,
    window: Option<u32>,
    digest_arg: Option<Vec<u8>>,
) -> std::result::Result<bool, GenerationError> {

    let defined_digits = if let Some(d) = digits { d } else { 6 };
    let defined_window = if let Some(w) = window { w } else { 10 };
    let defined_digest = if let Some(d) = digest_arg {
        d
    } else {
        digest(key.clone(), counter, Algorithm::Sha1)?
    };

    if token.len() as u32 != defined_digits {
        return Ok(false);
    }

    for i in counter..=counter + defined_window as u128 {
        let test_otp = if let Ok(otp) =
            generate_root(key.clone(), i, Some(defined_digits), Some(defined_digest.clone()))
        {
            otp
        } else {
            String::from("")
        };
        if test_otp == token {
            return Ok(true);
        }
    }

    // Default false
    Ok(false)
}

#[cfg(test)]
mod tests_generate {
    use crate::generate_secret;
    use crate::hotp::{Hotp};

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
        hotp.of_length(50);
        let pad = match hotp.generate() {
            Ok(h) => h,
            _ => String::from(""),
        };
        assert_eq!(pad.len(), 50);
    }
}

#[cfg(test)]
mod tests_verify {
    use crate::hotp::{Hotp};
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
        hotp.of_length(digits);
        hotp.with_digest(defined_digest.clone());
        let pad = match hotp.generate() {
            Ok(h) => h,
            _ => String::from(""),
        };
        let verified = if let Ok(v) =
            hotp.verify(pad)
        {
            v
        } else {
            false
        };
        assert_eq!(true, verified);
    }
}

#[cfg(test)]
mod test_builder_pattern {
    use crate::hotp::{Hotp};

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
        hotp.of_length(10);
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
        hotp.of_length(10);
        let pad = match hotp.generate() {
            Ok(h) => h,
            _ => String::from(""),
        };
        let result_correct = if let Ok(v) =
            hotp.verify(pad)
        {
            v
        } else {
            false
        };
        let result_fail = if let Ok(v) =
            hotp.verify(String::from("This should not verify"))
        {
            v
        } else {
            false
        };
        assert_eq!(true, result_correct);
        assert_eq!(false, result_fail);
    }
}
