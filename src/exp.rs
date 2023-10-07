use std::ops::Deref;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::BwError;
use crate::Generator;
use crate::Rotation;

#[derive(Serialize, Deserialize)]
pub struct Expiring<K> {
    init_exp: i64,
    exp: i64,
    object: K,
}

impl<K: Generator> Expiring<K> {
    #[inline]
    pub fn new(exp: chrono::Duration, object: K) -> Result<Self, BwError> {
        let expiration = Utc::now()
            .checked_add_signed(exp)
            .ok_or(BwError::IncorrectTimestamp)?
            .timestamp();
        Ok(Self {
            init_exp: exp.num_milliseconds(),
            exp: expiration,
            object,
        })
    }

    #[inline(always)]
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() > self.exp
    }
}

impl<K: Generator> Deref for Expiring<K> {
    type Target = K;

    fn deref(&self) -> &Self::Target {
        &self.object
    }
}

#[derive(Serialize, Deserialize)]
pub struct AutoExpiring<K: Generator> {
    expiring: Expiring<K>,
}

impl<K: Generator> Deref for AutoExpiring<K> {
    type Target = K;

    fn deref(&self) -> &Self::Target {
        &self.expiring.object
    }
}

impl<K: Generator> AutoExpiring<K> {
    #[inline]
    pub fn generate(exp: chrono::Duration) -> Result<Self, BwError> {
        Self::new(exp, K::generate()?)
    }

    #[inline]
    pub fn new(exp: chrono::Duration, object: K) -> Result<Self, BwError> {
        Ok(Self {
            expiring: Expiring::new(exp, object)?,
        })
    }

    #[inline(always)]
    pub fn is_expired(&self) -> bool {
        self.expiring.is_expired()
    }
}

impl<K: Generator> Rotation for AutoExpiring<K> {
    #[inline]
    fn rotate(&mut self) -> Result<(), BwError> {
        self.expiring.object = K::generate()?;
        self.expiring.exp = Utc::now()
            .checked_add_signed(chrono::Duration::milliseconds(self.expiring.init_exp))
            .ok_or(BwError::IncorrectTimestamp)?
            .timestamp();
        Ok(())
    }
}

// Tests --------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::exp::{AutoExpiring, Expiring};
    use crate::keys::ed::EdKey;
    use crate::keys::{PublicKey, SecretKey};
    use crate::{Generator, Rotation};

    #[test]
    fn test_generate() {
        let key = AutoExpiring::<EdKey>::generate(chrono::Duration::seconds(60));
        assert!(key.is_ok());
    }
    #[test]
    fn test_update_key_verify_failed() {
        let mut key = AutoExpiring::<EdKey>::generate(chrono::Duration::seconds(60)).unwrap();
        let message = b"Hello world!";
        let signature_bytes = key.sign(&message[..]).unwrap();

        assert!(key.rotate().is_ok(), "failed to roll key");
        let result = key.verify(message.as_slice(), &signature_bytes);
        assert!(result.is_err(), "Failed to regenerate properly");
    }

    #[test]
    fn test_sign_with_same_signature() {
        let key = AutoExpiring::<EdKey>::generate(chrono::Duration::seconds(60)).unwrap();
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
        let mut key = AutoExpiring::<EdKey>::generate(chrono::Duration::seconds(60)).unwrap();
        let message = b"Hello world!";
        let signature_bytes_1 = key.sign(&message[..]).unwrap();
        key.rotate().expect("Must roll correctly");

        let signature_bytes_2 = key.sign(&message[..]).unwrap();
        assert_ne!(
            signature_bytes_1, signature_bytes_2,
            "Failed to regenerate properly"
        );
    }

    #[test]
    fn test_expired_expiring() {
        let key =
            Expiring::<EdKey>::new(chrono::Duration::seconds(-60), EdKey::generate().unwrap())
                .unwrap();
        assert!(key.is_expired(), "AutoExpiring must be expired");
    }

    #[test]
    fn test_expired_auth_expiring() {
        let key = AutoExpiring::<EdKey>::generate(chrono::Duration::seconds(-60)).unwrap();
        assert!(key.is_expired(), "AutoExpiring must be expired");
    }

    #[test]
    fn test_serialize_expiring_secure_key() {
        let secret_key = AutoExpiring::<EdKey>::generate(chrono::Duration::seconds(60)).unwrap();

        let message = b"Hello world!";
        let signature_bytes = secret_key.sign(&message[..]).unwrap();
        let result = secret_key.verify(message.as_slice(), &signature_bytes);
        assert!(result.is_ok(), "Failed to verify signature");

        let secret_key_bytes = bincode::serialize(&secret_key).unwrap();
        let new_secret_key =
            bincode::deserialize::<AutoExpiring<EdKey>>(&secret_key_bytes).unwrap();
        assert!(!new_secret_key.is_expired(), "Key must be not expired");

        let result = new_secret_key.verify(message.as_slice(), &signature_bytes);
        assert!(result.is_ok(), "Failed to verify signature");
    }
}
