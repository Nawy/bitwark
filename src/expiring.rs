use std::ops::Deref;

use chrono::Utc;

use crate::error::BwError;
use crate::keys::RollingKey;
use crate::Generator;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct Expiring<K: Generator> {
    init_exp: i64,
    exp: i64,
    object: K,
}

impl<K: Generator> Expiring<K> {
    #[inline]
    pub fn generate(exp_sec: i64) -> Result<Self, BwError> {
        Self::new(exp_sec, K::generate())
    }

    #[inline]
    pub fn new(exp_sec: i64, object: K) -> Result<Self, BwError> {
        let expiration = Utc::now()
            .checked_add_signed(chrono::Duration::seconds(exp_sec))
            .ok_or(|| BwError::IncorrectTimestamp)?
            .timestamp();
        Ok(Self {
            init_exp,
            exp: expiration,
            object
        })
    }

    #[inline(always)]
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() > self.exp
    }
}

impl<K: Generator> RollingKey for Expiring<K> {
    #[inline]
    fn roll(&mut self) -> Result<(), BwError> {
        self.object = K::generate()?;
        self.exp = Utc::now()
            .checked_add_signed(chrono::Duration::seconds(self.init_exp))
            .expect("valid timestamp")
            .timestamp();
        Ok(())
    }
}

impl<K: Generator> Deref for Expiring<K> {
    type Target = K;

    fn deref(&self) -> &Self::Target {
        &self.object
    }
}

// Tests --------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::keys::ed::EdKey;
    use crate::expiring::Expiring;
    use crate::keys::CryptoKey;
    use crate::keys::RollingKey;

    #[test]
    fn test_generate() {
        let key = Expiring::<EdKey>::generate(10);
        assert!(key.is_ok());
    }
    #[test]
    fn test_update_key_verify_failed() {
        let mut key = Expiring::<EdKey>::generate(10).unwrap();
        let message = b"Hello world!";
        let signature_bytes = key.sign(&message[..]).unwrap();

        assert!(key.roll().is_ok(), "failed to roll key");
        let result = key.verify(message.as_slice(), &signature_bytes);
        assert!(result.is_err(), "Failed to regenerate properly");
    }

    #[test]
    fn test_sign_with_same_signature() {
        let key = Expiring::<EdKey>::generate(10).unwrap();
        let message = b"Hello world!";
        let signature_bytes_1 = key.sign(&message[..]).unwrap();
        let signature_bytes_2 = key.sign(&message[..]).unwrap();
        assert_eq!(
            signature_bytes_1, signature_bytes_2,
            "Failed to sign properly"
        );
    }

    #[test]
    fn test_update_key_sign_with_different_signature() {
        let mut key = Expiring::<EdKey>::generate(10).unwrap();
        let message = b"Hello world!";
        let signature_bytes_1 = key.sign(&message[..]).unwrap();
        key.roll().expect("Must roll correctly");

        let signature_bytes_2 = key.sign(&message[..]).unwrap();
        assert_ne!(
            signature_bytes_1, signature_bytes_2,
            "Failed to regenerate properly"
        );
    }
}
