use std::ops::Deref;

use chrono::Utc;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::BwError;
use crate::Generator;
use crate::keys::{BwSigner, BwVerifier};
use crate::payload::{SignedPayload, SignedPayloadUnverified};
use crate::salt::SaltInfo;

#[derive(Serialize, Deserialize)]
struct ExpiringBlock<T> {
    exp: i64,
    payload: T,
}

impl<T: Clone> Clone for ExpiringBlock<T> {
    fn clone(&self) -> Self {
        Self {
            exp: self.exp,
            payload: self.payload.clone(),
        }
    }
}

pub struct ExpiringSigned<T: Serialize + DeserializeOwned> {
    signed_payload: SignedPayload<ExpiringBlock<T>>,
}

impl<T: Serialize + DeserializeOwned + Clone> ExpiringSigned<T> {
    pub fn new(exp: chrono::Duration, payload: T) -> Result<Self, BwError> {
        let expiration = Utc::now()
            .checked_add_signed(exp)
            .ok_or(BwError::IncorrectTimestamp)?
            .timestamp();

        let block = ExpiringBlock {
            exp: expiration,
            payload,
        };
        Ok(ExpiringSigned {
            signed_payload: SignedPayload::<ExpiringBlock<T>>::new(block),
        })
    }

    #[inline]
    pub fn encode_and_sign(&self, key: &(impl BwSigner + ?Sized)) -> Result<Vec<u8>, BwError> {
        self.signed_payload.encode_and_sign(key)
    }

    #[inline]
    pub fn decode(bytes: &[u8]) -> Result<ExpiringSignedUnverified<T>, BwError> {
        let signed_payload_unverified = SignedPayload::<ExpiringBlock<T>>::decode(bytes)?;
        Ok(ExpiringSignedUnverified {
            signed_payload_unverified,
        })
    }

    #[inline]
    pub fn decode_and_verify(
        bytes: &[u8],
        key: &(impl BwVerifier + ?Sized),
    ) -> Result<Self, BwError> {
        let signed_payload = SignedPayload::<ExpiringBlock<T>>::decode_and_verify(bytes, key)?;
        // Verify expiration
        if Utc::now().timestamp() > signed_payload.exp {
            return Err(BwError::Expired);
        }

        Ok(ExpiringSigned { signed_payload })
    }

    #[inline]
    pub fn encode_and_sign_salted(
        &self,
        salt: &[u8],
        key: &(impl BwSigner + ?Sized),
    ) -> Result<Vec<u8>, BwError> {
        self.signed_payload.encode_and_sign_salted(salt, key)
    }

    #[inline]
    pub fn decode_and_verify_salted(
        bytes: &[u8],
        salt: &[u8],
        key: &(impl BwVerifier + ?Sized),
    ) -> Result<Self, BwError> {
        let signed_payload =
            SignedPayload::<ExpiringBlock<T>>::decode_and_verify_salted(bytes, salt, key)?;

        if Utc::now().timestamp() > signed_payload.exp {
            return Err(BwError::Expired);
        }

        Ok(ExpiringSigned { signed_payload })
    }

    #[inline]
    pub fn into_payload(self) -> T {
        self.signed_payload.into_payload().payload
    }
}

impl<T: Serialize + DeserializeOwned> Deref for ExpiringSigned<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &(*self.signed_payload).payload
    }
}

impl<T: Serialize + DeserializeOwned + Clone> Clone for ExpiringSigned<T> {
    fn clone(&self) -> Self {
        Self {
            signed_payload: self.signed_payload.clone(),
        }
    }
}

pub struct ExpiringSignedUnverified<T: Serialize + DeserializeOwned> {
    signed_payload_unverified: SignedPayloadUnverified<ExpiringBlock<T>>,
}

impl<T: Serialize + DeserializeOwned + Clone> ExpiringSignedUnverified<T> {
    #[inline]
    pub fn verify(self, key: &(impl BwVerifier + ?Sized)) -> Result<ExpiringSigned<T>, BwError> {
        let signed_payload = self.signed_payload_unverified.verify(key)?;
        // Verify expiration
        if Utc::now().timestamp() > signed_payload.exp {
            return Err(BwError::Expired);
        }

        Ok(ExpiringSigned { signed_payload })
    }

    pub fn verify_salted(
        self,
        salt: &[u8],
        key: &(impl BwVerifier + ?Sized),
    ) -> Result<ExpiringSigned<T>, BwError> {
        let signed_payload = self.signed_payload_unverified.verify_salted(salt, key)?;

        if Utc::now().timestamp() > signed_payload.exp {
            return Err(BwError::Expired);
        }

        Ok(ExpiringSigned { signed_payload })
    }
}
impl<T: Serialize + DeserializeOwned> Deref for ExpiringSignedUnverified<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &(*self.signed_payload_unverified).payload
    }
}

pub struct SaltyExpiringSigned<T: Serialize + DeserializeOwned, S = crate::salt::Salt64>
where
    S: Generator + SaltInfo + TryFrom<Vec<u8>>,
    <S as TryFrom<Vec<u8>>>::Error: Into<BwError>,
{
    expiring_payload: ExpiringSigned<T>,
    salt: S
}

impl<T: Serialize + DeserializeOwned + Clone, S> SaltyExpiringSigned<T, S>
where
    S: Generator + SaltInfo + TryFrom<Vec<u8>>,
    <S as TryFrom<Vec<u8>>>::Error: Into<BwError>,
    BwError: From<<S as TryFrom<Vec<u8>>>::Error>
{

    pub fn new(exp: chrono::Duration, payload: T) -> Result<Self, BwError> {
        Ok(Self {
            expiring_payload: ExpiringSigned::<T>::new(exp, payload)?,
            salt: S::generate()?,
        })
    }

    pub fn encode_and_sign(self, key: &(impl BwSigner + ?Sized)) -> Result<Vec<u8>, BwError> {
        let mut res_digest = self.expiring_payload.encode_and_sign_salted(self.salt.as_bytes(), key)?;
        res_digest.extend_from_slice(self.salt.as_bytes());
        Ok(res_digest)
    }

    pub fn decode_and_verify(
        bytes: &[u8],
        key: &(impl BwVerifier + ?Sized)
    ) -> Result<ExpiringSigned<T>, BwError> {
        let (payload, salt) = bytes.split_at(bytes.len() - S::salt_length());
        ExpiringSigned::decode_and_verify_salted(payload, salt, key)
    }

    pub fn decode_and_verify_raw(
        bytes: &[u8],
        key: &(impl BwVerifier + ?Sized)
    ) -> Result<SaltyExpiringSigned<T, S>, BwError> {
        let (payload, salt) = bytes.split_at(bytes.len() - S::salt_length());
        Ok(Self {
            expiring_payload: ExpiringSigned::decode_and_verify_salted(payload, salt, key)?,
            salt: S::try_from(salt.to_vec())?,
        })
    }
}

impl<T: Serialize + DeserializeOwned, S> Deref for SaltyExpiringSigned<T, S>
where
    S: Generator + SaltInfo + TryFrom<Vec<u8>>,
    <S as TryFrom<Vec<u8>>>::Error: Into<BwError>,
    BwError: From<<S as TryFrom<Vec<u8>>>::Error>
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.expiring_payload
    }
}

// Tests --------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::exp::{AutoExpiring, Expiring};
    use crate::keys::ed::{EdDsaKey, EdDsaPubKey};
    use crate::salt::Salt64;
    use crate::Generator;
    use crate::Rotation;
    use chrono::Duration;

    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn encode_decode_test() {
        let token = ExpiringSigned::<String>::new(
            chrono::Duration::seconds(60),
            "This is payload".to_string(),
        )
        .unwrap();
        let ed_key = EdDsaKey::generate().expect("Must generate a key");

        let encoded = token.encode_and_sign(&ed_key).unwrap();
        let decoded = ExpiringSigned::<String>::decode_and_verify(&encoded, &ed_key);

        assert!(decoded.is_ok());
        let decoded = decoded.unwrap();
        assert_eq!(*decoded, "This is payload".to_string());
    }

    #[test]
    fn encode_decode_with_exp_pub_key() {
        let key = EdDsaKey::generate().unwrap();

        let exp_salt =
            Expiring::<Salt64>::new(chrono::Duration::seconds(60), Salt64::generate().unwrap())
                .unwrap();

        // Instantiate a token with specified claims.
        let token =
            ExpiringSigned::<String>::new(Duration::seconds(120), "Hello".to_string()).unwrap();

        // Create a binary encoding of the token, signed with the key and salt.
        let signed_token_bytes = token
            .encode_and_sign_salted(exp_salt.as_bytes(), &key)
            .expect("Failed to sign token");

        let exp_pub_key =
            Expiring::<EdDsaPubKey>::new(chrono::Duration::seconds(60), key.public_key().unwrap())
                .unwrap();

        // Decode the token and verify its signature and validity.
        let _decoded_token = ExpiringSigned::<String>::decode_and_verify_salted(
            &signed_token_bytes,
            exp_salt.as_bytes(),
            &*exp_pub_key,
        )
        .expect("Failed to decode a token");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn decode_incorrect_token_test() {
        let ed_key = EdDsaKey::generate().expect("Must generate a key");
        let decoded = ExpiringSigned::<String>::decode_and_verify(b"Something", &ed_key);

        assert!(matches!(decoded, Err(BwError::InvalidTokenFormat)));
    }
    #[test]
    #[cfg_attr(miri, ignore)]
    fn decode_correct_token_test() {
        let salt = Salt64::generate().unwrap();
        let ed_key = EdDsaKey::generate().expect("Must generate a key");
        let object =
            ExpiringSigned::<String>::new(chrono::Duration::seconds(100), "Something".to_string())
                .unwrap();
        let encoded_bytes = object.encode_and_sign_salted(salt.as_bytes(), &ed_key).unwrap();
        let decoded = ExpiringSigned::<String>::decode(&encoded_bytes).unwrap();

        assert_eq!(*decoded, *object);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn decode_invalid_signature_token_test() {
        let token = ExpiringSigned::<String>::new(
            chrono::Duration::seconds(60),
            "This is payload".to_string(),
        )
        .unwrap();
        let mut ed_key = AutoExpiring::<EdDsaKey>::generate(chrono::Duration::seconds(60))
            .expect("Must create a token");

        let encoded = token.encode_and_sign(&*ed_key).unwrap();
        // change token
        ed_key.rotate().unwrap();
        let decoded = ExpiringSigned::<String>::decode_and_verify(&encoded, &*ed_key);

        assert!(matches!(decoded, Err(BwError::InvalidSignature)));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn decode_expired_token_test() {
        let token =
            ExpiringSigned::<String>::new(Duration::seconds(-60), "This is payload".to_string())
                .unwrap();
        let ed_key = EdDsaKey::generate().expect("Must generate a key");

        let encoded = token.encode_and_sign(&ed_key).unwrap();
        let decoded = ExpiringSigned::<String>::decode_and_verify(&encoded, &ed_key);

        assert!(matches!(decoded, Err(BwError::Expired)));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn encode_decode_with_salt_test() {
        let salt = b"Secret Salt";
        let token = ExpiringSigned::<String>::new(
            chrono::Duration::seconds(60),
            "This is payload".to_string(),
        )
        .unwrap();
        let ed_key = EdDsaKey::generate().expect("Must generate a key");

        let encoded = token
            .encode_and_sign_salted(salt.as_slice(), &ed_key)
            .unwrap();
        let decoded =
            ExpiringSigned::<String>::decode_and_verify_salted(&encoded, salt.as_slice(), &ed_key);

        assert!(decoded.is_ok());
        let decoded = decoded.unwrap();
        assert_eq!(*decoded, "This is payload".to_string());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn encode_decode_with_incorrect_salt_test() {
        let salt = b"Secret Salt";
        let token = ExpiringSigned::<String>::new(
            chrono::Duration::seconds(60),
            "This is payload".to_string(),
        )
        .unwrap();
        let ed_key = EdDsaKey::generate().expect("Must generate a key");

        let encoded = token
            .encode_and_sign_salted(salt.as_slice(), &ed_key)
            .unwrap();
        let decoded = ExpiringSigned::<String>::decode_and_verify_salted(
            &encoded,
            b"Wrong Salt".as_slice(),
            &ed_key,
        );

        assert!(matches!(decoded, Err(BwError::InvalidSignature)));
    }

    #[test]
    fn into_payload() {
        let payload = "This is payload".to_string();
        let token =
            ExpiringSigned::<String>::new(chrono::Duration::seconds(60), payload.clone()).unwrap();

        let unwrapped_payload = token.into_payload();
        assert_eq!(unwrapped_payload, payload);
    }

    #[test]
    fn encode_decode_salty_expiring_signed() {
        let payload = "This is payload";
        let token = SaltyExpiringSigned::<String>::new(
            chrono::Duration::seconds(60),
            payload.to_string(),
        ).unwrap();
        let ed_key = EdDsaKey::generate().expect("Must generate a key");

        let token_bytes = token.encode_and_sign(&ed_key).unwrap();

        // verify
        let decoded_token_res = SaltyExpiringSigned::<String>::decode_and_verify(&token_bytes, &ed_key);
        assert!(decoded_token_res.is_ok());
        let decoded_token = decoded_token_res.unwrap();
        assert_eq!(&*decoded_token, payload)
    }
}
