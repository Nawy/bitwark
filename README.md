# Bitwark &emsp;  [![Build Status]][actions] [![Latest Version]][crates.io] [![bitwark: rustc 1.66+]][Rust 1.65]

[Build Status]: https://img.shields.io/github/actions/workflow/status/versolid/bitwark/rust.yml?branch=main
[actions]: https://github.com/versolid/bitwark/actions?query=branch%3Amain
[Latest Version]: https://img.shields.io/crates/v/bitwark.svg
[crates.io]: https://crates.io/crates/bitwark
[bitwark: rustc 1.66+]: https://img.shields.io/badge/bitwark-rustc_1.65+-lightgray.svg
[Rust 1.65]: https://blog.rust-lang.org/2021/10/21/Rust-1.65.0.html

**Provides robust security for Rust applications through compact binary tokens and automated cryptographic defenses.**

---

## 🚀 Introduction
**Bitwark** is your go-to library for enhancing security in Rust applications. It offers a streamlined, bandwidth-friendly version of JSON Web Tokens (JWTs) and includes features like automatic key rotation and data salting to bolster your app's defenses.

### 🔐 Key Features:

* **Compact Tokens**: Uses binary format for signed payloads, saving space compared to traditional JWTs.
* **Advanced Encryption**: Employs EdDSA with Blake3 for robust signing and verification out of the box.
* **Dynamic Key Rotation**: Simplifies the process to update keys and salts, keeping your security measures up-to-date.
* **Enhanced Security with Salting**: Adds random data to payloads, making it tougher for attackers to crack.
* **Performance Optimized**: Designed to be lightweight, ensuring your applications run smoothly under pressure.

## 🛠️ Getting Started
Explore the secure features of Bitwark for your Rust applications:
#### All-in-One Example (Alternative to JWT)
Imagine you have a structure you wish to sign and send back to the user:
```rust
#[derive(Serialize, Deserialize, Clone)]
pub struct Token {
    pub user_id: u32,
    pub permissions: Vec<String>,
}
```
First, generate a key that expires after 10 minutes, though you can set it for days, months, or years as needed. For a non-expiring key, simply use `EdDsaKey::generate()`:
```rust
let exp_key = AutoExpiring::<EdDsaKey>::generate(
    Duration::minutes(10)
).unwrap();
```
Next, create the token. `SaltyExpiringSigned` adds a default 64-byte salt and includes an expiration time:
```rust
let token_object = Token { user_id: 123, permissions: vec!["Read".to_string(), "Write".to_string()] };

let token = SaltyExpiringSigned::<Token>::new(
    chrono::Duration::minutes(10),
    token_object
).unwrap();
```
Finally, prepare the token for the client. You can return it as bytes or convert it to base64:
```rust
let token_bytes: Vec<u8> = token.encode_and_sign(&*exp_key).unwrap();
```
When the user provides this token to your service, verifying it is straightforward:
```rust
let token = SaltyExpiringSigned::<Token>::decode_and_verify(&token_bytes, &*exp_key).unwrap();

if token.permissions.contains(&String::from("Read")) {
    // Proceed with the user's request
}
```

### More Comprehensive Examples Follow
#### Signed Payload decoded as binary (alternative to JWT)
```rust
use bitwark::{
    exp::AutoExpiring,
    signed_exp::ExpiringSigned,
    salt::Salt64,
    keys::{ed::EdDsaKey},
};
use serde::{Serialize, Deserialize};
use chrono::Duration;

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub permissions: Vec<String>,
}

// Generate an EdDSA key pair and salt with a validity period
let exp_key = AutoExpiring::<EdDsaKey>::generate(
    Duration::minutes(10)
).unwrap();

let exp_salt = AutoExpiring::<Salt64>::generate(
    Duration::minutes(5)
).unwrap();

// Instantiate a token with specified claims.
let claims = Claims { 
    permissions: vec![
        "users:read".to_string(), 
        "users:write".to_string()
    ],
};

let token = ExpiringSigned::<Claims>::new(
    Duration::seconds(120), claims
).unwrap();

// Create a binary encoding of the token, signed with key and salt.
let signed_token_bytes = token.encode_and_sign_salted(
    &exp_salt, &*exp_key
).expect("Failed to sign token");

// Decode the token and verify its signature and validity.
let decoded_token = ExpiringSigned::<Claims>::decode_and_verify_salted(
    &signed_token_bytes, &exp_salt, &*exp_key
).expect("Failed to decode a token");

assert_eq!(
    2, 
    decoded_token.permissions.len(), 
    "Failed to find 2 permissions"
);
```
#### Key Rotation
```rust
use bitwark::{payload::SignedPayload, keys::ed::EdDsaKey, keys::CryptoKey, Generator};
use chrono::Duration;

// creating a key
let key = EdDsaKey::generate()?;

// Rotating key
let mut expiring_key = Expiring<EdDsaKey>::new(Duration::seconds(10), key);
if expiring_key.has_expired() {
    expiring_key.roll()?;
}

// Creating a payload
let payload = SignedPayload::<String>::new("A signed message".to_string());

// Encode the payload with signature based on the expiring key
let signed_payload_bytes = payload.encode_and_sign(&expiring_key)?;

// Decode the signed payload with verifying signature with payload's integrity
let decoded_payload = SignedPayload::<String>::decode_and_verify(&signed_payload_bytes, &expiring_key)?;
assert_eq!(*decoded_payload, *payload);
```

#### Salt Example
```rust
use bitwark::{
    salt::Salt64, 
    exp::AutoExpiring, 
    key::ed::EdDsaKey, 
    Rotation, Generator
};
use bitwark::payload::SignedPayload;
use chrono::Duration;

// Make a new salt.
let salt = Salt64::generate().unwrap();

// Make a salt that lasts for 10 seconds.
let mut expiring_salt = AutoExpiring::<Salt64>::new(
    Duration::seconds(10), salt
).unwrap();

// Change the salt if it's too old.
if expiring_salt.has_expired() {
    expiring_salt
        .rotate()
        .expect("Salt rotation failed.");
}

// Make a key that lasts for 120 seconds.
let key = AutoExpiring::<EdDsaKey>::generate(
    Duration::seconds(120)
).unwrap();

// Make a payload for signing
let payload = SignedPayload::<String>::new(
    "Hello, world!".to_string()
);

// Combine message and signature into one piece.
let signature_bytes = payload.encode_and_sign_salted(
    &expiring_salt, &*key
).expect("Failed to encode");

// Separate message and signature, verifying validity.
let decoded_result = 
    SignedPayload::<String>::decode_and_verify_salted(
        &signature_bytes, &expiring_salt, &*key
    );

assert!(decoded_result.is_ok());
```

## 💡 Motivation
In today's digital landscape, security must not come at the expense of performance. Bitwark addresses this challenge by:
* Providing lightweight, bandwidth-efficient tokens for data exchange.
* Offering robust security features like automatic key rotation and salting to adapt to evolving threats.

## 🌱 Contribution
### Be a Part of Bitwark’s Journey!
We believe in the power of community, and Bitwark thrives on contributions from developers like you:
* **Propose Ideas**: Found a bug or have an idea? Open an **Issue!**
* **Code Contributions**: Enhance Bitwark by submitting **Pull Requests** with your code.
* **Documentation**: Help us keep our documentation clear and helpful.
* **Engage**: Participate in community discussions to shape Bitwark's future.

## 📜 License
**Bitwark** is licensed under the MIT License or Apache-2.0 to ensure it remains accessible for all developers.
