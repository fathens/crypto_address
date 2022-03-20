use crate::ExtendError;
use crypto_bigint::{Encoding, U256};
use elliptic_curve::{group::GroupEncoding, Curve, NonZeroScalar};
use hmac::digest::InvalidLength;
use k256::{AffinePoint, Secp256k1};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

#[macro_use]
mod local_macro {
    macro_rules! fixed_bytes {
        ($t:ident) => {
            impl TryFrom<&[u8]> for $t {
                type Error = InvalidLength;

                fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                    Ok(Self(value.try_into().map_err(|_| InvalidLength)?))
                }
            }

            impl AsRef<[u8]> for $t {
                fn as_ref(&self) -> &[u8] {
                    &self.0
                }
            }
        };
    }
}

//----------------------------------------------------------------

pub const KEY_SIZE: usize = 32;

const GENERATOR: AffinePoint = AffinePoint::GENERATOR;

const ORDER: U256 = Secp256k1::ORDER;

type EcdsaScalar = NonZeroScalar<Secp256k1>;

pub trait KeyBytes: Sized + AsRef<[u8]> {
    fn new_child(&self, key: &[u8]) -> Result<Self, ExtendError>;
}

pub trait PrvKey: KeyBytes {
    type Public: PubKey;

    fn get_public(&self) -> Result<Self::Public, ExtendError>;
}

pub trait PubKey: KeyBytes {
    fn fingerprint(&self) -> Fingerprint;
}

//----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 4]);
fixed_bytes!(Fingerprint);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PrvKeyBytes([u8; KEY_SIZE]);
fixed_bytes!(PrvKeyBytes);

impl KeyBytes for PrvKeyBytes {
    fn new_child(&self, salt: &[u8]) -> Result<Self, ExtendError> {
        let a = U256::from_be_bytes(self.0);
        let b = U256::from_be_slice(salt);
        let c = a.add_mod(&b, &ORDER);
        Ok(Self(c.to_be_bytes()))
    }
}

impl PrvKey for PrvKeyBytes {
    type Public = PubKeyBytes;

    fn get_public(&self) -> Result<Self::Public, ExtendError> {
        let a = EcdsaScalar::try_from(self.as_ref())?;
        let b = GENERATOR * *a;
        Ok(b.to_bytes().as_slice().try_into()?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PubKeyBytes([u8; KEY_SIZE + 1]);
fixed_bytes!(PubKeyBytes);

impl PubKeyBytes {
    fn to_point(&self) -> Result<AffinePoint, ExtendError> {
        let bs = self.as_ref().into();
        let o: Option<_> = AffinePoint::from_bytes(bs).into();
        o.ok_or_else(|| ExtendError("Unrecognizable bytes of public key.".to_owned()))
    }
}

impl KeyBytes for PubKeyBytes {
    fn new_child(&self, salt: &[u8]) -> Result<Self, ExtendError> {
        let a = EcdsaScalar::try_from(salt)?;
        let b = GENERATOR * *a;
        let c = b + self.to_point()?;
        Ok(c.to_bytes().as_slice().try_into()?)
    }
}

impl PubKey for PubKeyBytes {
    fn fingerprint(&self) -> Fingerprint {
        let sha = Sha256::digest(self.as_ref());
        let ds = Ripemd160::digest(&sha);
        ds[..4].try_into().expect("taken 4 bytes must be 4 bytes")
    }
}
