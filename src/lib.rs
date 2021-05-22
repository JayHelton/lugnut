use hmac::{crypto_mac, Hmac, Mac, NewMac};
use rand;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use thiserror::Error;
use url::form_urlencoded::byte_serialize;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

pub mod hotp;
pub mod totp;

/// GenerationError enumerates all possible errors returned by this library.
#[derive(Error, Debug)]
pub enum GenerationError {
    #[error("Invalid Key Length")]
    InvalidKeyLength(#[from] crypto_mac::InvalidKeyLength),
    #[error("Failed to generate One-Time Password")]
    FailedToGenerateOTP(),
}

enum HmacFunction<A, B, C> {
    Sha1(A),
    Sha256(B),
    Sha512(C),
}

pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

static CHAR_SET: [char; 62] = [
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
    'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b',
    'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
    'v', 'w', 'x', 'y', 'z',
];
static SYMBOL_SET: [char; 22] = [
    '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '<', '>', '?', '/', '[', ']', '{', '}', ',',
    '.', ':', ';',
];

/// Applys a specified keyed hashing function (hmac).
///
/// # Arguments
///
/// * `secret` - A string of the secret
/// * `counter` - The counter to hash
/// * `algorithm` - The preferred algorithm
///
/// # Examples
///
/// ```
/// use lugnut::{ digest, Algorithm };
/// let hash = digest("My secret".to_string(), 5000, Algorithm::Sha1);
///
pub fn digest(
    secret: String,
    counter: u128,
    algorithm: Algorithm,
) -> std::result::Result<Vec<u8>, GenerationError> {
    let mac = get_hmac(secret, algorithm)?;

    // Convert the counter into a u8 array of base16 values
    let mut buf = vec![0; 8];
    let mut tmp = counter;
    for i in 0..8 {
        buf[7 - i] = (tmp & 0xff) as u8;
        tmp = tmp >> 8;
    }

    // Unwrap enum and apply the hmac alg
    Ok(match mac {
        HmacFunction::Sha1(mut _mac) => {
            _mac.update(&buf);
            _mac.finalize().into_bytes().to_vec()
        }
        HmacFunction::Sha256(mut _mac) => {
            _mac.update(&buf);
            _mac.finalize().into_bytes().to_vec()
        }
        HmacFunction::Sha512(mut _mac) => {
            _mac.update(&buf);
            _mac.finalize().into_bytes().to_vec()
        }
    })
}

/// Default layer to generate a secret key in ASCII representations
///
/// # Examples
///
/// ```
/// use lugnut::{ generate_secret };
/// let secret_key = generate_secret();
/// ```
pub fn generate_secret() -> String {
    generate_secret_default(None, None)
}

/// Length defining layer to generate a secret key in ASCII representation
///
/// # Examples
///
/// ```
/// use lugnut::{ generate_sized_secret };
/// let secret_key = generate_sized_secret(100);
/// ```
pub fn generate_sized_secret(length: u32) -> String {
    generate_secret_default(Some(length), None)
}

/// Symbol defining layer to generate a secret key in ASCII representation
///
/// # Examples
///
/// ```
/// use lugnut::{ generate_secret_without_symbols };
/// let secret_key = generate_secret_without_symbols();
/// ```
pub fn generate_secret_without_symbols() -> String {
    generate_secret_default(None, Some(false))
}

/// Symbol and length defining layer to generate a secret key in ASCII representation
///
/// # Examples
///
/// ```
/// use lugnut::{ generate_secret_without_symbols };
/// let secret_key = generate_secret_without_symbols();
/// ```
pub fn generate_sized_secret_without_symbols(length: u32) -> String {
    generate_secret_default(Some(length), Some(true))
}

pub fn get_otp_auth_url() {}

/// This section works to fill up the unsigned 32 bit number by:
/// 1.  Taking the 8 bits at the offset from the digest, AND'ing with 0x7f so that we can ignore the sign bit
/// and then bit shifting 24 to the left to fill the most significant bits.
/// 2.  Taking the next 8 bits from the digest at (offset + 1), AND'ing with 0xff to get the set bits, shifting 16 to fill
/// the next 8 significant bits.
/// 3.  Same as (2.) but taking the bits from (offset + 2)
/// 4.  Same as (2.) but taking the bits from (offset + 3)
/// 5.  OR'ing each of these u32 so that we collapse all of the set bits into one u32
#[doc(hidden)]
fn generate(
    key: String,
    counter: u128,
    digits: u32,
    digest_hash: Vec<u8>,
) -> std::result::Result<String, GenerationError> {
    let offset = if let Some(o) = digest_hash.last() {
        o & 0xf
    } else {
        0
    };

    let no_offset = if let Some(o) = digest_hash.get(offset as usize) {
        u32::from(o.clone() & 0x7f) << 24
    } else {
        0
    };
    let one_offset = if let Some(o) = digest_hash.get((offset + 1) as usize) {
        u32::from(o.clone() & 0xff) << 16
    } else {
        0
    };
    let two_offset = if let Some(o) = digest_hash.get((offset + 2) as usize) {
        u32::from(o.clone() & 0xff) << 8
    } else {
        0
    };
    let three_offset = if let Some(o) = digest_hash.get((offset + 3) as usize) {
        u32::from(o.clone() & 0xff)
    } else {
        0
    };
    let code = no_offset | one_offset | two_offset | three_offset;

    if code == 0 {
        Err(GenerationError::FailedToGenerateOTP())
    } else {
        let padded_string = format!("{:0>width$}", code.to_string(), width = digits as usize);
        Ok(
            (&padded_string[(padded_string.len() - digits as usize)..padded_string.len()])
                .to_string(),
        )
    }
}

#[doc(hidden)]
fn verify_delta(
    token: String,
    key: String,
    counter: u128,
    digits: u32,
    window: u64,
    digest_hash: Vec<u8>,
) -> std::result::Result<bool, GenerationError> {
    if token.len() as u32 != digits {
        return Ok(false);
    }

    for _ in counter..=counter + window as u128 {
        let test_otp = generate(key.clone(), counter, digits, digest_hash.clone())?;
        if test_otp == token {
            return Ok(true);
        }
    }

    // Default false
    Ok(false)
}

#[doc(hidden)]
fn generate_secret_default(length: Option<u32>, symbols: Option<bool>) -> String {
    let defined_symbols = if let Some(s) = symbols { s } else { true };
    let defined_length = if let Some(l) = length { l } else { 32 };
    generate_secret_ascii(defined_length, defined_symbols)
}

#[doc(hidden)]
fn get_hmac(
    secret: String,
    algorithm: Algorithm,
) -> std::result::Result<HmacFunction<HmacSha1, HmacSha256, HmacSha512>, GenerationError> {
    Ok(match algorithm {
        Algorithm::Sha1 => HmacFunction::Sha1(HmacSha1::new_varkey(secret.as_bytes())?),
        Algorithm::Sha256 => HmacFunction::Sha256(HmacSha256::new_varkey(secret.as_bytes())?),
        Algorithm::Sha512 => HmacFunction::Sha512(HmacSha512::new_varkey(secret.as_bytes())?),
    })
}

#[doc(hidden)]
fn generate_secret_ascii(length: u32, symbols: bool) -> String {
    let byte_array: Vec<u8> = (0..length).map(|_| rand::random::<u8>()).collect();

    let mut secret: String = String::from("");
    for (_, value) in byte_array.iter().enumerate() {
        // Need to decide to grab from the symbol/char set if configuration wants to add symbols to secret
        if symbols {
            secret.push(match value % 2 {
                0 => CHAR_SET[((usize::from(value / 1)) * (CHAR_SET.len() - 1)) / 255],
                1 => SYMBOL_SET[((usize::from(value / 1)) * (SYMBOL_SET.len() - 1)) / 255],
                _ => unreachable!("Error: Reached the unreachable match arm of `u8` modulo 2"),
            })
        } else {
            secret.push(CHAR_SET[((usize::from(value / 1)) * (CHAR_SET.len() - 1)) / 255])
        }
    }
    secret
}

#[doc(hidden)]
fn encode_uri_component(string: String) -> String {
    byte_serialize(string.as_bytes()).collect()
}

#[doc(hidden)]
fn generate_otpauth_url() {}

#[cfg(test)]
mod digest_tests {
    use crate::digest;
    use crate::Algorithm::Sha1;

    #[test]
    fn it_works() {
        let test = digest("My secret".to_string(), 5000, Sha1);
        match test {
            Ok(result) => println!("Testing {:02x?}", result),
            Err(_) => panic!("There was an error in the test"),
        }
    }
}

#[cfg(test)]
mod generate_secret_tests {
    use crate::{
        generate_secret_ascii, generate_secret_without_symbols, generate_sized_secret, SYMBOL_SET,
    };

    #[test]
    fn test_generate_secret_ascii_no_symbols() {
        let secret = generate_secret_ascii(2000, false);
        assert_eq!(secret.len(), 2000);
    }

    #[test]
    fn test_generate_secret_ascii_symbols() {
        let secret = generate_secret_ascii(2000, true);
        assert_eq!(secret.len(), 2000);
        assert_eq!(secret.contains("!"), true);
    }

    //    #[test]
    //    fn test_generate_secret_defaults() {
    //        assert_eq!(generate_secret().len(), 32);
    //        assert_eq!(
    //            generate_secret()
    //                .chars()
    //                .any(|c| match SYMBOL_SET.binary_search(&c) {
    //                    Ok(_) => true,
    //                    _ => false,
    //                }),
    //            true
    //        )
    //    }

    #[test]
    fn test_generate_secret_non_default_length() {
        assert_eq!(generate_sized_secret(2000).len(), 2000);
    }

    #[test]
    fn test_generate_secret_non_default_symbols() {
        assert_eq!(
            generate_secret_without_symbols()
                .chars()
                .any(|c| match SYMBOL_SET.binary_search(&c) {
                    Ok(_) => true,
                    _ => false,
                }),
            false
        )
    }
}
