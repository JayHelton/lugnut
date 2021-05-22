use lugnut::{Totp, Hotp};

fn main() {
    let totp = Totp::new();
    let hotp = Hotp::new();
    println!("{:?}", totp.generate("my key".to_string()));
    println!("{:?}", hotp.generate("my key".to_string(), 100));
}
