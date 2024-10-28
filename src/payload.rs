use std::ops::Deref;

use ed25519_dalek::SIGNATURE_LENGTH;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::BwError;
use crate::keys::{BwSigner, BwVerifier};

const MIN_MSG_SIZE: usize = 16;
const MIN_TOKEN_LENGTH: usize = SIGNATURE_LENGTH + MIN_MSG_SIZE;

/// A utility for working with digitally signed payloads.
///
/// `SignedPayload` allows encapsulating a payload of type `T` with a digital signature, which can be
/// encoded and decoded for secure transport.
///
/// # Type Parameters
///
/// * `T`: The payload type, which must implement `Serialize` and `DeserializeOwned`.
/// * `H`: The hashing algorithm, which must implement `Digest` (default is `Sha3_384`).
///
/// # Examples
///
/// Creating a new `SignedPayload`:
///
/// ```rust
/// # use bitwark::payload::SignedPayload;
/// let payload = SignedPayload::<String>::new("Hello, world!".to_string());
/// ```
#[derive(Debug, Clone)]
pub struct SignedPayload<T: Serialize + DeserializeOwned> {
    payload: T,
}

impl<T: Serialize + DeserializeOwned> SignedPayload<T> {
    /// Creates a new `SignedPayload` with the provided payload.
    ///
    /// # Parameters
    ///
    /// * `payload`: The data to be encapsulated in the `SignedPayload`.
    #[inline]
    pub fn new(payload: T) -> Self {
        SignedPayload {
            payload,
        }
    }

    /// Encodes the payload and its signature into a byte vector.
    ///
    /// The payload is serialized and signed using the provided cryptographic key.
    /// The signature and serialized payload are concatenated and returned as a `Vec<u8>`.
    ///
    /// # Parameters
    ///
    /// * `key`: The cryptographic key used for signing.
    ///
    /// # Returns
    ///
    /// A `Result` containing the encoded payload and signature, or a `BwError` if an error occurs.
    ///
    /// # Example
    ///
    /// ```rust
    ///
    /// # use bitwark::{payload::SignedPayload, keys::ed::EdDsaKey, keys::{BwSigner, BwVerifier}, Generator};
    /// let key = EdDsaKey::generate().unwrap();
    /// let payload = SignedPayload::<String>::new("Hello, world!".to_string());
    /// let signed_payload = payload.encode_and_sign(&key).unwrap();
    /// ```
    #[inline]
    pub fn encode_and_sign(&self, key: &(impl BwSigner + ?Sized)) -> Result<Vec<u8>, BwError> {
        let payload_bytes = bincode::serialize(&self.payload).expect("Serialization failed");
        let mut encoded = key.sign(&payload_bytes)?;
        encoded.extend(payload_bytes);
        Ok(encoded)
    }

    /// Decodes a signed payload, verifying its signature in the process.
    ///
    /// The method splits the input bytes into signature and payload, verifies the signature,
    /// and then deserializes the payload, returning a `SignedPayload` instance.
    ///
    /// # Parameters
    ///
    /// * `bytes`: The signed payload and signature bytes.
    /// * `key`: The cryptographic key used for verification.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `SignedPayload` instance or a `BwError` if decoding or verification fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use bitwark::{payload::SignedPayload, keys::ed::EdDsaKey, keys::{BwVerifier,BwSigner}, Generator};
    /// let key = EdDsaKey::generate().unwrap();
    /// let payload = SignedPayload::<String>::new("Hello, world!".to_string());
    /// let signed_bytes = payload.encode_and_sign(&key).unwrap();
    /// let decoded_payload = SignedPayload::<String>::decode_and_verify(&signed_bytes, &key)
    ///     .unwrap();
    /// assert_eq!(*decoded_payload, *payload);
    /// ```
    pub fn decode_and_verify(
        bytes: &[u8],
        key: &(impl BwVerifier + ?Sized),
    ) -> Result<Self, BwError> {
        if bytes.len() < MIN_TOKEN_LENGTH {
            return Err(BwError::InvalidTokenFormat);
        }

        let (signature, body) = bytes.split_at(SIGNATURE_LENGTH);

        // Verify signature
        key.verify(body, signature)
            .map_err(|_| BwError::InvalidSignature)?;

        let payload = bincode::deserialize(body).map_err(|_| BwError::InvalidTokenFormat)?;

        Ok(SignedPayload {
            payload,
        })
    }

    /// Decodes a byte slice into an unverified signed payload.
    ///
    /// This function attempts to decode the given byte slice into a `SignedPayloadUnverified` struct, which contains the raw bytes, the deserialized payload, and a type marker for the digest algorithm used.
    ///
    /// The decoding process ignores the signature, meaning that the payload is not verified during this step. It allows the caller to inspect the payload before deciding on further actions, such as verification with the appropriate key.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A slice of bytes representing the signed message to be decoded.
    ///
    /// # Returns
    ///
    /// This function returns a `Result` which is:
    ///
    /// - `Ok(SignedPayloadUnverified<T, H>)` when decoding is successful. The generic `T` represents the payload type, while `H` refers to the digest algorithm's marker type.
    /// - `Err(BwError)` when the byte slice does not meet the minimum length requirement or if the deserialization of the payload fails. `BwError::InvalidTokenFormat` is returned in such cases.
    ///
    /// # Errors
    ///
    /// This function will return an error in the following situations:
    ///
    /// - If the length of `bytes` is less than `MIN_TOKEN_LENGTH`, indicating that the byte slice is too short to contain a valid signed message.
    /// - If the deserialization of the payload using `bincode` fails, which may indicate corruption or an invalid format.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitwark::{payload::{SignedPayloadUnverified, SignedPayload}, BwError, keys::ed::EdDsaKey, Generator};
    /// # fn main() -> Result<(), BwError> {
    /// # let key = EdDsaKey::generate().unwrap();
    /// # let payload_string = "Hello, world!".to_string();
    /// # let signed_payload = SignedPayload::<String>::new(payload_string.clone());
    /// let signed_bytes = signed_payload.encode_and_sign(&key).unwrap();
    /// let decoded_unverified = SignedPayload::<String>::decode(&signed_bytes)?;
    ///
    /// // You can now inspect the result without verifying the signature
    /// assert_eq!(*decoded_unverified, *signed_payload);
    /// // To verify the signature, further steps are needed involving the payload and a verification key
    /// let decoded_verified = decoded_unverified.verify(&key)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Security
    ///
    /// The returned `SignedPayloadUnverified` has not been checked for authenticity or integrity. It is crucial to not trust the contents until after a successful signature verification step.
    pub fn decode(bytes: &[u8]) -> Result<SignedPayloadUnverified<T>, BwError> {
        if bytes.len() < MIN_TOKEN_LENGTH {
            return Err(BwError::InvalidTokenFormat);
        }

        let (_, body) = bytes.split_at(SIGNATURE_LENGTH);
        let payload = bincode::deserialize(body).map_err(|_| BwError::InvalidTokenFormat)?;

        Ok(SignedPayloadUnverified {
            bytes: bytes.to_vec(),
            payload,
        })
    }
    pub fn encode_and_sign_salted(
        &self,
        salt: &[u8],
        key: &(impl BwSigner + ?Sized),
    ) -> Result<Vec<u8>, BwError> {
        let payload_bytes = bincode::serialize(&self.payload).expect("Serialization failed");
        let mut salted_body = payload_bytes.clone();
        salted_body.extend(salt);

        let signature = key.sign(&salted_body)?;

        let mut encoded = Vec::with_capacity(SIGNATURE_LENGTH + payload_bytes.len());
        encoded.extend_from_slice(&signature);
        encoded.extend_from_slice(&payload_bytes);

        Ok(encoded)
    }

    pub fn decode_and_verify_salted(
        bytes: &[u8],
        salt: &[u8],
        key: &(impl BwVerifier + ?Sized),
    ) -> Result<Self, BwError> {
        if bytes.len() < MIN_TOKEN_LENGTH {
            return Err(BwError::InvalidTokenFormat);
        }

        let (signature, payload) = bytes.split_at(SIGNATURE_LENGTH);

        let mut to_verify = Vec::with_capacity(payload.len() + salt.len());
        to_verify.extend_from_slice(payload);
        to_verify.extend_from_slice(salt);

        // Verify signature
        key.verify(&to_verify, signature)
            .map_err(|_| BwError::InvalidSignature)?;

        let payload = bincode::deserialize(payload).map_err(|_| BwError::InvalidTokenFormat)?;

        Ok(SignedPayload {
            payload,
        })
    }

    #[inline]
    pub fn into_payload(self) -> T {
        self.payload
    }
}

impl<T: Serialize + DeserializeOwned> Deref for SignedPayload<T> {
    type Target = T;

    fn deref(&self) -> &<Self as Deref>::Target {
        &self.payload
    }
}

impl<T: Serialize + DeserializeOwned> AsRef<T> for SignedPayload<T> {
    fn as_ref(&self) -> &T {
        &self.payload
    }
}

pub struct SignedPayloadUnverified<T: Serialize + DeserializeOwned> {
    bytes: Vec<u8>,
    payload: T,
}

impl<T: Serialize + DeserializeOwned> SignedPayloadUnverified<T> {
    pub fn verify(self, key: &(impl BwVerifier + ?Sized)) -> Result<SignedPayload<T>, BwError> {
        if self.bytes.len() < MIN_TOKEN_LENGTH {
            return Err(BwError::InvalidTokenFormat);
        }

        let (signature, body) = self.bytes.split_at(SIGNATURE_LENGTH);

        // Verify signature
        key.verify(body, signature)
            .map_err(|_| BwError::InvalidSignature)?;

        Ok(SignedPayload {
            payload: self.payload,
        })
    }

    pub fn verify_salted(
        self,
        salt: &[u8],
        key: &(impl BwVerifier + ?Sized),
    ) -> Result<SignedPayload<T>, BwError> {
        if self.bytes.len() < MIN_TOKEN_LENGTH {
            return Err(BwError::InvalidTokenFormat);
        }

        let (signature, payload) = self.bytes.split_at(SIGNATURE_LENGTH);

        let mut to_verify = Vec::with_capacity(payload.len() + salt.len());
        to_verify.extend_from_slice(payload);
        to_verify.extend_from_slice(salt);

        // Verify signature
        key.verify(&to_verify, signature)
            .map_err(|_| BwError::InvalidSignature)?;

        let payload = bincode::deserialize(payload).map_err(|_| BwError::InvalidTokenFormat)?;

        Ok(SignedPayload {
            payload,
        })
    }

    #[inline]
    pub fn into_payload(self) -> T {
        self.payload
    }
}

impl<T: Serialize + DeserializeOwned> Deref for SignedPayloadUnverified<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &<Self as Deref>::Target {
        &self.payload
    }
}

impl<T: Serialize + DeserializeOwned> PartialEq for SignedPayloadUnverified<T> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<K: Serialize + DeserializeOwned + PartialEq> PartialEq for SignedPayload<K> {
    fn eq(&self, other: &Self) -> bool {
        self.payload == other.payload
    }
}

// Tests --------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::keys::ed::EdDsaKey;
    use crate::salt::{Salt64, SaltInfo};
    use crate::Generator;

    use super::*;

    #[test]
    fn test_encode() {
        let key = EdDsaKey::generate().unwrap();
        let payload = SignedPayload::<String>::new("Hello, world!".to_string());
        let _signed_payload = payload.encode_and_sign(&key).unwrap();
    }

    #[test]
    fn test_decoded() {
        let key = EdDsaKey::generate().unwrap();
        let payload = SignedPayload::<String>::new("Hello, world!".to_string());
        let signed_bytes = payload.encode_and_sign(&key).unwrap();
        let decoded_payload =
            SignedPayload::<String>::decode_and_verify(&signed_bytes, &key).unwrap();
        assert_eq!(*decoded_payload, *payload);
    }

    #[test]
    fn test_decoded_and_verify_separation() {
        let key = EdDsaKey::generate().unwrap();
        let payload = SignedPayload::<String>::new("Hello, world!".to_string());
        let signed_bytes = payload.encode_and_sign(&key).unwrap();

        let decoded_payload = SignedPayload::<String>::decode(&signed_bytes).unwrap();
        let decoded_payload = decoded_payload.verify(&key);
        assert!(decoded_payload.is_ok());
        assert_eq!(*decoded_payload.unwrap(), *payload);
    }

    #[test]
    fn test_encode_salted() {
        let key = EdDsaKey::generate().unwrap();
        let salt = Salt64::generate().unwrap();
        let payload = SignedPayload::<String>::new("Hello, world!".to_string());

        let _encoded = payload.encode_and_sign_salted(salt.as_bytes(), &key).unwrap();
    }

    #[test]
    fn test_decoded_salted() {
        let key = EdDsaKey::generate().unwrap();
        let salt = Salt64::generate().unwrap();
        let payload = SignedPayload::<String>::new("Hello, world!".to_string());

        let signed_bytes = payload.encode_and_sign_salted(salt.as_bytes(), &key).unwrap();
        let decoded_payload =
            SignedPayload::<String>::decode_and_verify_salted(&signed_bytes, salt.as_bytes(), &key);
        assert!(decoded_payload.is_ok());
    }

    #[test]
    fn test_decoded_and_verify_salted() {
        let key = EdDsaKey::generate().unwrap();
        let salt = Salt64::generate().unwrap();
        let payload = SignedPayload::<String>::new("Hello, world!".to_string());

        let signed_bytes = payload.encode_and_sign_salted(salt.as_bytes(), &key).unwrap();
        let decoded_payload = SignedPayload::<String>::decode(&signed_bytes).unwrap();
        let decoded_payload = decoded_payload.verify_salted(salt.as_bytes(), &key);
        assert!(decoded_payload.is_ok());
        assert_eq!(*decoded_payload.unwrap(), *payload);
    }

    #[test]
    fn test_decoded_salted_with_another_salt_error() {
        let key = EdDsaKey::generate().unwrap();
        let salt = Salt64::generate().unwrap();
        let payload = SignedPayload::<String>::new("Hello, world!".to_string());

        let signed_bytes = payload.encode_and_sign_salted(salt.as_bytes(), &key).unwrap();

        let another_salt = Salt64::generate().unwrap();
        let decoded_payload =
            SignedPayload::<String>::decode_and_verify_salted(&signed_bytes, another_salt.as_bytes(), &key);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn test_decoded_salted_with_another_key_error() {
        let key = EdDsaKey::generate().unwrap();
        let salt = Salt64::generate().unwrap();
        let payload = SignedPayload::<String>::new("Hello, world!".to_string());

        let signed_bytes = payload.encode_and_sign_salted(salt.as_bytes(), &key).unwrap();

        let another_key = EdDsaKey::generate().unwrap();
        let decoded_payload =
            SignedPayload::<String>::decode_and_verify_salted(&signed_bytes, salt.as_bytes(), &another_key);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn into_payload() {
        let payload = "This is payload".to_string();
        let signed = SignedPayload::<String>::new(payload.clone());

        let unwrapped_payload = signed.into_payload();
        assert_eq!(unwrapped_payload, payload);
    }
}
