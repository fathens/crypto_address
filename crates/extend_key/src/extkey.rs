use crate::base58;
use crate::ecdsa_key::{Fingerprint, KeyBytes, PrvKey, PubKey, KEY_SIZE};
use crate::fixed_bytes::FixedBytes;
use crate::local_macro::fixed_bytes;
use crate::ExtendError;
use core::fmt;
use hdpath::node::Node;
use hmac::{Hmac, Mac};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChainCode([u8; KEY_SIZE]);
fixed_bytes!(ChainCode);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Depth([u8; 1]);
fixed_bytes!(Depth);

impl Depth {
    fn increment(&self) -> Result<Self, ExtendError> {
        let next = self.0[0]
            .checked_add(1)
            .ok_or(ExtendError::depth_exceeded())?;
        Ok(Self([next]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChildNumber([u8; 4]);
fixed_bytes!(ChildNumber);

impl From<u32> for ChildNumber {
    fn from(v: u32) -> Self {
        Self(v.to_be_bytes())
    }
}

//----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExtKey<A> {
    pub prefix: base58::Prefix,
    pub parent: Fingerprint,
    pub chain_code: ChainCode,
    pub key: A,
    pub depth: Depth,
    pub child_number: ChildNumber,
}

impl<A: KeyBytes> ExtKey<A> {
    fn mk_child<K: AsRef<[u8]>>(
        &self,
        prefix: base58::Prefix,
        parent: Fingerprint,
        child_number: ChildNumber,
        key: &K,
    ) -> Result<Self, ExtendError> {
        let key_bytes = key.as_ref();
        let padding = vec![0; (KEY_SIZE + 1) - key_bytes.len()];

        let mut hash = HmacSha512::new_from_slice(self.chain_code.as_ref())?;
        hash.update(&padding);
        hash.update(key_bytes);
        hash.update(child_number.as_ref());
        let hashed = &hash.finalize().into_bytes();

        let (child_key, chain_code) = hashed.split_at(hashed.len() / 2);
        let next = ExtKey {
            prefix,
            parent,
            chain_code: chain_code.try_into()?,
            key: self.key.new_child(child_key)?,
            depth: self.depth.increment()?,
            child_number,
        };
        Ok(next)
    }
}

impl<A: PubKey> ExtKey<A> {
    pub fn get_child_normal_only(&self, node: Node) -> Result<Self, ExtendError> {
        if node.is_hardened() {
            return Err(ExtendError::cannot_hardened());
        }
        self.mk_child(
            self.prefix.clone(),
            self.key.fingerprint(),
            node.raw_index().into(),
            &self.key,
        )
    }
}

impl<A: PrvKey> ExtKey<A> {
    pub fn get_child(&self, node: Node) -> Result<Self, ExtendError> {
        let fp = self.key.get_public()?.fingerprint();
        if node.is_hardened() {
            self.mk_child(self.prefix.clone(), fp, node.raw_index().into(), &self.key)
        } else {
            self.mk_child(
                self.prefix.get_public()?,
                fp,
                node.raw_index().into(),
                &self.key.get_public()?,
            )
        }
    }
}

//----------------------------------------------------------------

impl<A: KeyBytes> From<&ExtKey<A>> for base58::DecodedExtKey {
    fn from(src: &ExtKey<A>) -> Self {
        base58::DecodedExtKey {
            prefix: src.prefix.clone(),
            depth: src.depth.copy_bytes(),
            parent: src.parent.copy_bytes(),
            child_number: src.child_number.copy_bytes(),
            chain_code: src.chain_code.copy_bytes(),
            key: src.key.copy_bytes(),
        }
    }
}

impl<A> TryFrom<base58::DecodedExtKey> for ExtKey<A>
where
    A: KeyBytes,
    A: TryFrom<bytes::Bytes, Error = ExtendError>,
{
    type Error = ExtendError;

    fn try_from(src: base58::DecodedExtKey) -> Result<Self, Self::Error> {
        let r = Self {
            prefix: src.prefix.clone(),
            depth: src.depth.try_into()?,
            parent: src.parent.try_into()?,
            child_number: src.child_number.try_into()?,
            chain_code: src.chain_code.try_into()?,
            key: src.key.try_into()?,
        };
        Ok(r)
    }
}

impl<A: KeyBytes> fmt::Display for ExtKey<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d: base58::DecodedExtKey = self.into();
        d.fmt(f)
    }
}
