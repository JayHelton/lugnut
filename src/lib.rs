use hmac::{
    crypto_mac::InvalidKeyLength,
    digest::{
        consts::{B0, B1},
        generic_array::{
            typenum::{UInt, UTerm},
            ArrayLength, GenericArray,
        },
        BlockInput, FixedOutput, Reset, Update,
    },
    Hmac, Mac, NewMac,
};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

pub mod hotp;
pub mod totp;

enum HmacFunction<A> {
    Sha1(A),
}

pub enum Algorithm {
    Sha1,
    // Todo (Jayhelton)Implement other hash functions
    // Sha256,
    // Sha512,
}

// pub enum Encoding {
//     Ascii,
//     Hex,
//     Base32,
//     Base64,
// }

pub fn digest(
    secret: String,
    counter: u128,
    algorithm: Algorithm,
) -> std::result::Result<Vec<u8>, InvalidKeyLength> {
    let mac = match get_hmac(secret, algorithm) {
        Ok(_hmac) => _hmac,
        Err(e) => return Err(e),
    };

    match mac {
        HmacFunction::Sha1(mut _mac) => {
            _mac.update(b"input mdddessage");
            Ok(_mac.finalize().into_bytes().to_vec())
        }
    }
}

pub fn generate_secret() {}
pub fn get_otp_auth_url() {}

fn get_hmac(
    secret: String,
    algorithm: Algorithm,
) -> Result<HmacFunction<HmacSha1>, InvalidKeyLength> {
    let hash = match algorithm {
        Algorithm::Sha1 => {
            let hmac = match HmacSha1::new_varkey(secret.as_bytes()) {
                Ok(_hmac) => _hmac,
                Err(e) => return Err(e),
            };
            HmacFunction::Sha1(hmac)
        }
    };
    Ok(hash)
}

#[cfg(test)]
mod digest_tests {
    use crate::digest;

    #[test]
    fn it_works() {
        let test = digest(
            "My secret".to_string(),
            5000,
            crate::Encoding::Ascii,
            crate::Algorithm::Sha1,
        );
        match test {
            Ok(result) => println!("Testing {:02x?}", result),
            Err(_) => panic!("There was an error in the test"),
        }
    }
}
