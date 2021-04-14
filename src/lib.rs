use rand::Rng;

mod totp;
mod hotp;

pub struct SecretKey {
    ascii: Option<String>,
    hex: Option<String>,
    base32: Option<String>,
    otpauth_url: Option<String>
}

pub fn digest() {}

pub fn generate_secret(
    length: Option<u8>, // Revisit the size of the integer. This is 0-255. We could make it larger.
    symbols: Option<bool>,
    otpauth_url: Option<bool>,
    name: Option<&str>,
    issuer: Option<&str>,
) -> SecretKey {
    println!("{:?}", length);
    println!("{:?}", symbols);
    println!("{:?}", otpauth_url);
    println!("{:?}", name);
    println!("{:?}", issuer);
    SecretKey { ascii: None, hex: None, base32: None, otpauth_url: None } // TODO (kevinburchfield) - fix. Only did this so it would compile
}

pub fn get_otp_auth_url(){}

// Helpers
fn generate_secret_ascii(
    length: Option<u8>, // Revisit the size of the integer. This is 0-255. We could make it larger.
    symbols: bool
) -> String {

    // NodeJS generates random byte arrays using unsigned 32bit ints - so use u32 here
    // https://github.com/nodejs/node/blob/e46c680bf2b211bbd52cf959ca17ee98c7f657f5/src/crypto/crypto_random.cc

    static char_set: [char; 62] = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
    ];
    static symbol_set: [char; 22] = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '<', '>', '?', '/', '[', ']', '{', '}', ',', '.', ':', ';'];

    // TODO (kevinburchfield) - fix. Only did this so it would compile
    String::from("doing this to compile")
}

fn encodeURIComponent() {

}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
