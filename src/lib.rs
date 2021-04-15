use hmac::{
    crypto_mac::InvalidKeyLength,
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

pub fn digest(
    secret: String,
    counter: u128,
    algorithm: Algorithm,
) -> std::result::Result<Vec<u8>, InvalidKeyLength> {
    let mac = match get_hmac(secret, algorithm) {
        Ok(_hmac) => _hmac,
        Err(e) => return Err(e),
    };

    let mut buf = vec![0; 8];
    let mut tmp = counter;
    for i in 0 ..8 {
      buf[7 - i] = (tmp & 0xff) as u8;
      tmp = tmp >> 8;
    }

    match mac {
        HmacFunction::Sha1(mut _mac) => {
            _mac.update(&buf);
            Ok(_mac.finalize().into_bytes().to_vec())
        }
    }
}

pub fn generate_secret() {}
pub fn get_otp_auth_url() {}

fn get_hmac(
    secret: String,
    algorithm: Algorithm,
) -> std::result::Result<HmacFunction<HmacSha1>, InvalidKeyLength> {
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
            crate::Algorithm::Sha1,
        );
        match test {
            Ok(result) => println!("Testing {:02x?}", result),
            Err(_) => panic!("There was an error in the test"),
        }
    }
}
