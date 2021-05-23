<!-- <p align="center"><img src="logo.png" /></p> -->

<h1 align="center"> Lugnut </h1>

<p align="center"> A One-time Password Crate for Rust</p>

<!-- [![crates.io](https://img.shields.io/crates/v/lugnut.svg)](https://crates.io/crates/reqwest)
[![Documentation](https://docs.rs/reqwest/badge.svg)](https://docs.rs/lugnut) -->
[![MIT/Apache-2 licensed](https://img.shields.io/crates/l/reqwest.svg)](./LICENSE-APACHE)
<!-- [![CI](https://github.com/jayhelton/lugnut/workflows/CI/badge.svg)](https://github.com/seanmonstar/reqwest/actions?query=workflow%3ACI) -->


<hr/>

> Lugnut is still experimental and under construction.

Lugnut is a one-time password generator that supports specification compliant HOTP and TOTP generation and verification. 

<h3> Examples </h3>

<p>Add to Cargo.toml</p>

```toml
[dependencies]
lugnut = "0.1.0
```


<h3> HOTP </h3>

```rust
use lugnut::hotp::Hotp;

let key = String::from("SuperSecretKey");
let counter = 100;

let mut hotp = Hotp::new();
let code = hotp.generate(key, counter).expect("error generating hotp");
let verified = hotp.verify(code, key, counter).expect("error verifying hotp");

assert!(verified);
```
<h3> TOTP </h3>

```rust
use lugnut::totp::Totp;

let key = String::from("SuperSecretKey");

let mut totp = Totp::new();
let code = totp.generate(key).expect("error generating totp");
let verified = totp.verify(code, key).expect("error verifying totp");
assert!(verified);
```

<h3> Upcoming for Lugnut</h3>
<ul>
  <li>Better Test Coverage</li>
  <li>Support for OTP Auth Url generation</li>
  <li>Support for forward and backward window configuration for TOTP (currently only support one value that is used for both</li>
</ul>

<br/><br/>
<h3>License</h3>
This project is licensed under the MIT License
