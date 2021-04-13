mod totp;
mod hotp;

pub fn digest() {}
pub fn generate_secret(){}
pub fn get_otp_auth_url(){}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
