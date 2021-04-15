use hmac::{crypto_mac, Hmac, Mac, NewMac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use thiserror::Error;

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

pub fn generate_secret() {}
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
