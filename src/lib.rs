//! # 🛡️ Bitwark: Binary Bulwark in Rust
//! Bitwark is a cryptographic Rust library (used ring, ed25519-dalek, blake3), designed to facilitate secure digital interactions through a meticulous amalgamation of lightweight binary JWT tokens, dynamic key rotation, and strategic salt functionalities, all embedded in a minimalistic API.
//! Through Bitwark, developers can seamlessly perform crucial security operations, such as key and salt generation, payload signing, and integrity message verification, all whilst ensuring optimal performance and security in their applications.
//!
//! ## 🚀 Getting Started
//! Engage in a fortified cryptographic experience with Bitwark, utilizing functionalities like secure payload creation, signature encoding, and strategic key rotation with simplicity and efficacy.
//!
//! ### 🔐 Key Features:
//! * **Compact Tokens**: Uses binary format for signed payloads, saving space compared to traditional JWTs.
//! * **Advanced Encryption**: Employs EdDSA with Blake3 for robust signing and verification out of the box.
//! * **Dynamic Key Rotation**: Simplifies the process to update keys and salts, keeping your security measures up-to-date.
//! * **Enhanced Security with Salting**: Adds random data to payloads, making it tougher for attackers to crack.
//! * **Performance Optimized**: Designed to be lightweight, ensuring your applications run smoothly under pressure.
//!
//! ## Signed Payload decoded as binary (alternative to JWT)
//! ```
//! # use bitwark::{exp::AutoExpiring, signed_exp::ExpiringSigned, salt::{Salt64,SaltInfo}, keys::{ed::EdDsaKey}};
//! # use serde::{Serialize, Deserialize};
//! # use chrono::Duration;
//! #[derive(Serialize,Deserialize, Clone)]
//! pub struct Claims {
//!     pub permissions: Vec<String>,
//! }
//! // Generate an EdDSA key pair with a validity period of 10 minutes and a salt with a validity of 5 minutes.
//! let exp_key = AutoExpiring::<EdDsaKey>::generate(
//!     Duration::minutes(10)
//! ).unwrap();
//! let exp_salt = AutoExpiring::<Salt64>::generate(
//!     Duration::minutes(5)
//! ).unwrap();
//!
//! // Instantiate a token with specified claims.
//! let claims = Claims { permissions: vec!["users:read".to_string(), "users:write".to_string()]};
//! let token = ExpiringSigned::<Claims>::new(Duration::seconds(120), claims).unwrap();
//!
//! // Create a binary encoding of the token, signed with the key and salt.
//! let signed_token_bytes = token.encode_and_sign_salted(exp_salt.as_bytes(), &*exp_key)
//!     .expect("Failed to sign token");
//!
//! // Decode the token and verify its signature and validity.
//! let decoded_token = ExpiringSigned::<Claims>::decode_and_verify_salted(
//!     &signed_token_bytes, exp_salt.as_bytes(), &*exp_key
//! ).expect("Failed to decode a token");
//! assert_eq!(2, decoded_token.permissions.len(), "Failed to find 2 permissions");
//! ```
//! ## Key Generation and Management
//! Bitwark enables the generation and rotation of cryptographic keys, ensuring persistent security through periodic key renewals.
//! ```
//! # use bitwark::keys::ed::EdDsaKey;
//! # use bitwark::Generator;
//! // Generate an EdDSA key pair.
//! let key = EdDsaKey::generate().unwrap();
//! ```
//! ## Key Rotation for Enhanced Security
//! Effortlessly manage and rotate your keys, maintaining a fresh and secure application environment through time-based key expiration and renewals.
//! ```
//! # use bitwark::keys::ed::EdDsaKey;
//! # use bitwark::Rotation;
//! # use bitwark::exp::AutoExpiring;
//! # use bitwark::Generator;
//! # use chrono::Duration;
//! let key = EdDsaKey::generate().unwrap();
//! let mut expiring_key = AutoExpiring::new(Duration::seconds(10), key).unwrap();
//! if expiring_key.is_expired() {
//!     // update key internally
//!     expiring_key.rotate().unwrap();
//! }
//! ```
//!
//! ## Payload Creation and Management
//! Construct, encode, and decode secure payloads, ensuring message integrity through signature verification.
//! ```
//! # use bitwark::keys::ed::EdDsaKey;
//! # use bitwark::exp::AutoExpiring;
//! # use bitwark::keys::{BwVerifier, BwSigner};
//! # use bitwark::payload::SignedPayload;
//! # use bitwark::Generator;
//! # use chrono::Duration;
//! let key = EdDsaKey::generate().unwrap();
//! // Construct a payload.
//! let payload = SignedPayload::<String>::new("A signed message".to_string());
//!
//! // Encode the payload.
//! let signed_payload_bytes = payload.encode_and_sign(&key).unwrap();
//!
//! // Decode, verifying the signature.
//! let decoded_payload = SignedPayload::<String>::decode_and_verify(&signed_payload_bytes, &key).unwrap();
//! assert_eq!(*decoded_payload, *payload);
//! ```
//!
//! ## Salting
//! The `Salt[N]` struct can be utilized to generate random salts which are pivotal in
//! cryptographic operations to safeguard against various forms of attack and to ensure
//! that identical inputs do not produce identical outputs across different users or sessions.
//!
//! ### Salt variants
//! * `Salt126` - 126 bytes length
//! * `Salt64`
//! * `Salt32`
//! * `Salt16`
//! * `Salt12`
//!
//! ```
//! use bitwark::salt::Salt64;
//! use bitwark::Generator;
//!
//! let salt1 = Salt64::generate().unwrap();
//! let salt2 = Salt64::generate().unwrap();
//!
//! // Assert that different generated salts are not equal.
//! // In cryptographic operations, unique salts are pivotal to secure storage and transmission.
//! assert_ne!(*salt1, *salt2, "Salts should be unique across generations.");
//! ```
//!
//! Salts can also be seamlessly integrated into rotation operations, frequently refreshing
//! them to enhance security further. This is particularly valuable in contexts where the
//! same data might be encrypted multiple times, ensuring each instance yields different ciphertext.
//!
//! Example with Rotation (Assuming `Expiring` is a structure which utilizes the `Rotation` trait):
//!
//! ```
//! use bitwark::{salt::{Salt64, SaltInfo}, exp::AutoExpiring, keys::ed::EdDsaKey, Rotation, Generator};
//! use bitwark::payload::SignedPayload;
//! use chrono::Duration;
//!
//! // Make a new salt.
//! let salt = Salt64::generate().unwrap();
//!
//! // Make a salt that lasts for 10 seconds.
//! let mut expiring_salt = AutoExpiring::<Salt64>::new(Duration::seconds(10), salt).unwrap();
//!
//! // Change the salt if it's too old.
//! if expiring_salt.is_expired() {
//!     expiring_salt.rotate().expect("Salt rotation failed.");
//! }
//!
//! // Make a key that lasts for 120 seconds.
//! let key = AutoExpiring::<EdDsaKey>::generate(Duration::seconds(120)).unwrap();
//! // Make a payload for signing
//! let payload = SignedPayload::<String>::new("Hello, world!".to_string());
//!
//! // Combine the message and a special code (signature) into one piece.
//! let signature_bytes = payload.encode_and_sign_salted(expiring_salt.as_bytes(), &*key).expect("Failed to encode");
//!
//! // Separate the message and the signature, checking they're valid.
//! let decoded_result = SignedPayload::<String>::decode_and_verify_salted(&signature_bytes, expiring_salt.as_bytes(), &*key);
//! assert!(decoded_result.is_ok());
//! ```
//!
//! Using salts and rotating them regularly strengthens security by ensuring
//! that even repeated data or credentials produce different hashes or ciphertexts
//! across different instances or sessions.
//!
pub use error::BwError;

pub mod error;
pub mod exp;
pub mod keys;
pub mod payload;
pub mod salt;
pub mod signed_exp;

/// The `Generator` trait defines a common interface for types that require
/// a generation phase, typically resulting in the instantiation of a unique
/// or random state.
///
/// # Example
///
/// ```
/// # use bitwark::Generator;
/// # use bitwark::keys::ed::EdDsaKey;
/// let generated_key = EdDsaKey::generate().expect("Key generation failed");
/// ```
///
/// Implementing `Generator` trait for your own types enables the structured
/// creation of instances, particularly in cryptographic or secure contexts
/// where randomness or uniqueness is crucial.
pub trait Generator {
    /// Generates and returns an instance of the implementing type.
    ///
    /// # Errors
    ///
    /// Returns [`crate::BwError`] in cases where generation
    /// fails, e.g., due to insufficient system entropy, internal failures, etc.
    fn generate() -> Result<Self, BwError>
    where
        Self: Sized;
}

/// The `Rotation` trait encapsulates the best practice of rotating
/// cryptographic or sensitive materials, minimizing the potential
/// impact of key compromise or algorithmic predictions.
///
/// Secure systems often implement rotation to limit the utility
/// of compromised keys and to periodically refresh cryptographic
/// materials, ensuring persistent protection against evolving threats.
///
/// # Example
///
/// ```
/// # use bitwark::{Generator, Rotation};
/// # use bitwark::keys::ed::EdDsaKey;
/// # use bitwark::exp::AutoExpiring;
/// # use chrono::Duration;
///
/// let key = EdDsaKey::generate().expect("Key generation failed");
/// let mut expiring_key = AutoExpiring::new(Duration::seconds(10), key).unwrap();
/// expiring_key.rotate().expect("Key generation failed");
/// ```
///
/// # Good Practices
///
/// Implement the `Rotation` trait for entities in your application
/// where periodical change or refreshment is vital for sustaining
/// security, especially for cryptographic keys, tokens, or salts.
pub trait Rotation {
    fn rotate(&mut self) -> Result<(), BwError>;
}
