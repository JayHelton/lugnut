use lugnut::webauthn::attestation::generate::{generate_attestation_options, AttestationOptions};
use serde_json::to_string;

fn main() {
    let options = AttestationOptions::new(
        "example.com".to_string(),
        "example".to_string(),
        "asdfasdfasdfasdfasdfas".to_string(),
        "somebytes".to_string(),
        "someusername".to_string(),
    );
    let generated_options = generate_attestation_options(options);
    println!("{:?}", to_string(&generated_options))
}
