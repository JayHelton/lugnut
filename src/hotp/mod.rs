use crate::{digest, Algorithm, GenerationError};

/// Default layer to generate a HOTP using the SHA1 hash algorithm
///
/// # Arguments
///
/// * `key` - A string of the secret
/// * `counter` - The counter to hash
///
pub fn generate(
    key: String,
    counter: u128
) -> std::result::Result<String, GenerationError> {
    generate_root(key, counter, None, None)
}

/// Layer to generate a HOTP of size N using the SHA1 hash algorithm
///
/// # Arguments
///
/// * `key` - A string of the secret
/// * `counter` - The counter to hash
/// * `n` - The length of the one time pad
///
pub fn generate_n_length(
    key: String,
    counter: u128,
    n: u32
) -> std::result::Result<String, GenerationError> {
    generate_root(key, counter, Some(n), None)
}

/// Layer to generate a HOTP with a custom hash digest
///
/// # Arguments
///
/// * `key` - A string of the secret
/// * `counter` - The counter to hash
/// * `digest` - Custom hash digest to use
///
pub fn generate_with_custom_digest(
    key: String,
    counter: u128,
    digest: Vec<u8>
) -> std::result::Result<String, GenerationError> {
    generate_root(key, counter, None, Some(digest))
}

/// Layer to generate a HOTP of size N with a custom hash digest
///
/// # Arguments
///
/// * `key` - A string of the secret
/// * `counter` - The counter to hash
/// * `n` - The length of the one time pad
///
pub fn generate_n_length_with_custom_digest(
    key: String,
    counter: u128,
    n: u32,
    digest: Vec<u8>
) -> std::result::Result<String, GenerationError> {
    generate_root(key, counter, Some(n), Some(digest))
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
    digest_arg: Option<Vec<u8>>
) -> std::result::Result<String, GenerationError> {
    let defined_digits = match digits {
        Some(d) => d,
        None => 6
    };

    let defined_digest = match digest_arg {
        Some(d) => d,
        None => match digest(key, counter, Algorithm::Sha1) {
            Ok(d) => d,
            _ => return Err(GenerationError::FailedToGenerateHOTP())
        }
    };

    let offset = match defined_digest.last() {
        Some(o) => o & 0xf,
        None => 0 // 0 & 0xf == 0
    };

    let f_msg = "Failed to pull from digest.";
    let code = 
        (u32::from(defined_digest.get(offset as usize).expect(f_msg) & 0x7f) << 24) | 
        (u32::from(defined_digest.get((offset + 1) as usize).expect(f_msg) & 0xff) << 16) |
        (u32::from(defined_digest.get((offset + 2) as usize).expect(f_msg) & 0xff) << 8) |
        (u32::from(defined_digest.get((offset + 3) as usize).expect(f_msg) & 0xff));

    let padded_string = format!("{:0>width$}", code.to_string(), width=defined_digits as usize);
    Ok((&padded_string[(padded_string.len() - defined_digits as usize)..padded_string.len()]).to_string())
}

pub fn verify() {}
pub fn verify_delta() {}

#[cfg(test)]
mod hotp_tests {
    use crate::hotp::{generate, generate_n_length};
    use crate::{generate_secret};

    #[test]
    fn test_generate_hotp_default() {
        let key = generate_secret();
        let hotp = match generate(key, 100) {
            Ok(h) => h,
            _ => String::from("")
        };
        assert_eq!(hotp.len(), 6);
    }

    #[test]
    fn test_generate_hotp_custom_length() {
        let key = generate_secret();
        let hotp = match generate_n_length(key, 100, 50) {
            Ok(h) => h,
            _ => String::from("")
        };
        assert_eq!(hotp.len(), 50);
    }
}