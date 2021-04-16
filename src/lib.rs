use hmac::{crypto_mac, Hmac, Mac, NewMac};
use rand;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::fmt;
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

pub struct SecretKey {
    ascii: Option<String>,
    otpauth_url: Option<String>,
}

impl fmt::Display for SecretKey {
    #[doc(inline)]
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut str = "";
        match &self.ascii {
            Some(a) => fmt.write_str(&format!("ASCII: {}\n", a)),
            None => fmt.write_str("No ASCII representation.\n"),
        };
        Ok(())
    }
}

impl SecretKey {
    #[doc(inline)]
    fn new() -> Self {
        SecretKey {
            ascii: None,
            otpauth_url: None,
        }
    }
    #[doc(inline)]
    fn with_ascii(a: String) -> Self {
        SecretKey {
            ascii: Some(a),
            otpauth_url: None,
        }
    }
    #[doc(inline)]
    fn with_otpauth_url(url: String) -> Self {
        SecretKey {
            ascii: None,
            otpauth_url: Some(url),
        }
    }
    #[doc(inline)]
    fn add_otpauth_url(&self, url: String) -> Self {
        SecretKey {
            ascii: self.ascii.clone(),
            otpauth_url: Some(url),
        }
    }
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
/// ```
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

/// Generates a SecretKey with ASCII, Hex, and Base32 representations of the secret key
///
/// # Arguments
///
/// * `length` - Optional parameter that defines the length of the secret key (default: 32)
/// * `symbols` - Optional parameter that dictates whether symbols are allowed in the secret key (default: true)
///
/// # Examples
///
/// ```
/// use lugnut::{ generate_secret, SecretKey };
/// let secret_key = generate_secret(Some(200), Some(false)); // Secret key of length 200, no symbols allowed
/// let secret_key = generate_secret(Some(100), None); // Secret key of length 100, symbols allows
/// let secret_key = generate_secret(None, Some(true)); // Secret key of length 32, symbols allows
/// ```
pub fn generate_secret(length: Option<u32>, symbols: Option<bool>) -> SecretKey {
    let defined_symbols = match symbols {
        Some(s) => s,
        None => true,
    };
    let key = generate_secret_ascii(length, defined_symbols);
    SecretKey::with_ascii(key)
}

pub fn get_otp_auth_url() {}

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
fn generate_secret_ascii(length: Option<u32>, symbols: bool) -> String {
    let byte_array_length = match length {
        Some(l) => l,
        None => 32,
    };

    let byte_array: Vec<u8> = (0..byte_array_length)
        .map(|_| rand::random::<u8>())
        .collect();

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
fn encodeURIComponent(string: String) -> String {
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
    use crate::{generate_secret, generate_secret_ascii};

    #[test]
    fn test_generate_secret_ascii_no_symbols() {
        let secret = generate_secret_ascii(Some(2000), false);
        assert_eq!(secret.len(), 2000);
    }

    #[test]
    fn test_generate_secret_ascii_symbols() {
        let secret = generate_secret_ascii(Some(2000), true);
        assert_eq!(secret.len(), 2000);

        // Chances are that a secret of length 2000 will have one arbitrary symbol
        // TODO (kevinburchfield) - Fix this to check against all of the symbols to be certain
        assert_eq!(secret.contains("!"), true);
    }

    #[test]
    fn test_generate_secret_ascii_no_defined_length() {
        let secret = generate_secret_ascii(None, false);
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn test_generate_secret_defaults() {
        let secret_key = generate_secret(None, None);
        let key_length = match secret_key.ascii {
            Some(a) => a.len(),
            None => 0,
        };
        assert_eq!(key_length, 32);
    }

    #[test]
    fn test_generate_secret_non_default_length() {
        let secret_key = generate_secret(Some(2000), None);
        let key_length = match secret_key.ascii {
            Some(a) => a.len(),
            None => 0,
        };
        assert_eq!(key_length, 2000);
    }

    #[test]
    fn test_generate_secret_non_default_symbols() {
        let secret_key = generate_secret(Some(100), Some(false));
        let ascii = match secret_key.ascii {
            Some(a) => a,
            None => String::new(),
        };
        // Chances are that a secret of length 2000 will have one arbitrary symbol
        // TODO (kevinburchfield) - Fix this to check against all of the symbols to be certain
        assert_eq!(ascii.contains("!"), false);
    }
}
