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
    length: Option<u32>,
    symbols: Option<bool>,
    otpauth_url: Option<bool>,
    name: Option<&str>,
    issuer: Option<&str>,
) -> SecretKey {
    SecretKey { ascii: None, hex: None, base32: None, otpauth_url: None } // TODO (kevinburchfield) - fix. Only did this so it would compile
}

pub fn get_otp_auth_url(){}

// Helpers
fn generate_secret_ascii(
    length: Option<u32>,
    symbols: bool
) -> String {
    let byte_array_length = match length {
        Some(l) => l,
        None => 32 
    };

    let byte_array: Vec<u8> = (0..byte_array_length).map(|_| { rand::random::<u8>() }).collect();

    // Static for efficiency rather than leaving it to runtime to init a vector of chars
    static CHAR_SET: [char; 62] = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
    ];
    static SYMBOL_SET: [char; 22] = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '<', '>', '?', '/', '[', ']', '{', '}', ',', '.', ':', ';'];

    let mut secret: String = String::from("");
    for (_, value) in byte_array.iter().enumerate() {
        // Need to decide to grab from the symbol/char set if configuration wants to add symbols to secret
        if symbols {
            secret.push(
                match value % 2 {
                    0 => CHAR_SET[((usize::from(value / 1)) * (CHAR_SET.len() - 1)) / 255],
                    1 => SYMBOL_SET[(((usize::from(value / 1)) * (SYMBOL_SET.len() - 1))) / 255],
                    _ => unreachable!("Error: Reached the unreachable match arm of `u8` modulo 2")
                }
            )
        } else {
            secret.push(CHAR_SET[(((usize::from(value / 1)) * (CHAR_SET.len() - 1))) / 255])
        }
    }
    secret
}

fn encodeURIComponent() {

}

#[cfg(test)]
mod tests {
    use crate::generate_secret_ascii;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

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
}
