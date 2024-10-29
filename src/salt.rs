use std::ops::Deref;

use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::{error::BwError, Generator};

pub trait SaltInfo {
    fn salt_length() -> usize;
    fn as_bytes(&self) -> &[u8];
}

macro_rules! impl_salt {
    ($name:ident, $length:expr) => {
        #[derive(Serialize, Deserialize, Debug)]
        pub struct $name(#[serde(with = "serde_bytes")] [u8; $length]);

        impl Generator for $name {
            fn generate() -> Result<Self, BwError>
            where
                Self: Sized,
            {
                let rng = SystemRandom::new();
                let mut bytes = [0u8; $length];
                rng.fill(&mut bytes)
                    .map_err(|_| BwError::FailedSaltGeneration)?;
                Ok(Self(bytes))
            }
        }

        impl SaltInfo for $name {
            fn salt_length() -> usize {
                $length
            }

            fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }

        impl Deref for $name {
            type Target = [u8; $length];

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.0 == other.0
            }
        }

        impl Clone for $name {
            fn clone(&self) -> Self {
                $name(self.0.clone())
            }
        }

        impl From<$name> for Vec<u8> {
            fn from(value: $name) -> Self {
                value.0.to_vec()
            }
        }

        impl From<[u8; $length]> for $name {
            fn from(value: [u8; $length]) -> Self {
                Self(value)
            }
        }

        impl TryFrom<Vec<u8>> for $name {
            type Error = BwError;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                if value.len() != $length {
                    return Err(BwError::InvalidSaltLength {
                        expected: $length,
                        actual: value.len(),
                    });
                }

                let mut bytes = [0u8; $length];
                bytes.copy_from_slice(&value);
                Ok(Self(bytes))
            }
        }
    };
}

impl_salt!(Salt126, 128);
impl_salt!(Salt64, 64);
impl_salt!(Salt32, 32);
impl_salt!(Salt16, 16);
impl_salt!(Salt12, 12);

// Tests --------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::{exp::AutoExpiring, Rotation};

    use super::*;

    #[test]
    fn generate_salt() {
        let salt = Salt64::generate();
        assert!(salt.is_ok());
    }

    #[test]
    fn generate_different_salt() {
        let salt1 = Salt64::generate().unwrap();
        let salt2 = Salt64::generate().unwrap();
        assert_ne!(*salt1, *salt2);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn generate_expiring_salt() {
        let mut salt1 = AutoExpiring::<Salt64>::generate(chrono::Duration::seconds(60)).unwrap();
        let bytes = salt1.clone();
        salt1.rotate().unwrap();
        assert_ne!(&*bytes, &*salt1, "Failed to compare");
    }
}
