use crate::node::Node;
use crypto_bigint::{Encoding, U256};
use elliptic_curve::{group::GroupEncoding, Curve, NonZeroScalar};
use hmac::{digest::InvalidLength, Hmac, Mac};
use k256::{AffinePoint, Secp256k1};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};

#[macro_use]
mod local_macro {
    macro_rules! fixed_bytes {
        ($t:ident) => {
            impl TryFrom<&[u8]> for $t {
                type Error = InvalidLength;

                fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                    Ok(Self(fix_array(value)?))
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

const GENERATOR: AffinePoint = AffinePoint::GENERATOR;

const ORDER: U256 = Secp256k1::ORDER;

const KEY_SIZE: usize = 32;

type HmacSha512 = Hmac<Sha512>;

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

#[derive(Debug)]
pub struct ExtendError(String);

impl From<InvalidLength> for ExtendError {
    fn from(src: InvalidLength) -> Self {
        Self(src.to_string())
    }
}
impl From<elliptic_curve::Error> for ExtendError {
    fn from(src: elliptic_curve::Error) -> Self {
        Self(src.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChainCode([u8; KEY_SIZE]);
fixed_bytes!(ChainCode);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChildNumber([u8; 4]);
fixed_bytes!(ChildNumber);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 4]);
fixed_bytes!(Fingerprint);

impl From<u32> for ChildNumber {
    fn from(v: u32) -> Self {
        Self(v.to_be_bytes())
    }
}

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExtKey<A> {
    parent: Fingerprint,
    chain_code: ChainCode,
    key: A,
    child_number: ChildNumber,
}

impl<A: KeyBytes> ExtKey<A> {
    fn mk_child<K: AsRef<[u8]>>(
        &self,
        parent: Fingerprint,
        child_number: ChildNumber,
        key: &K,
    ) -> Result<Self, ExtendError> {
        let key_bytes = key.as_ref();
        let prefix = vec![0; (KEY_SIZE + 1) - key_bytes.len()];

        let mut hash = HmacSha512::new_from_slice(self.chain_code.as_ref())?;
        hash.update(&prefix);
        hash.update(key_bytes);
        hash.update(child_number.as_ref());
        let hashed = &hash.finalize().into_bytes();

        let (child_key, chain_code) = hashed.split_at(hashed.len() / 2);
        let next = ExtKey {
            parent,
            chain_code: chain_code.try_into()?,
            key: self.key.new_child(child_key)?,
            child_number,
        };
        Ok(next)
    }
}

impl<A: PubKey> ExtKey<A> {
    pub fn get_child_normal_only(&self, node: Node) -> Result<Self, ExtendError> {
        if let Node::Normal(index) = node {
            self.mk_child(self.key.fingerprint(), index.into(), &self.key)
        } else {
            Err(ExtendError(
                "public key can not derive hardened key".to_owned(),
            ))
        }
    }
}

impl<A: PrvKey> ExtKey<A> {
    pub fn get_child(&self, node: Node) -> Result<Self, ExtendError> {
        let fp = self.key.get_public()?.fingerprint();
        match node {
            Node::Normal(index) => self.mk_child(fp, index.into(), &self.key.get_public()?),
            Node::Hardened(index) => self.mk_child(fp, index.into(), &self.key),
        }
    }
}

#[inline]
fn fix_array<const N: usize>(bs: &[u8]) -> Result<[u8; N], InvalidLength> {
    bs.try_into().ok().ok_or(InvalidLength)
}
