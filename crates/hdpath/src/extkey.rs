use crate::ecdsa_key::{Fingerprint, KeyBytes, PrvKey, PubKey};
use crate::node::Node;
use crate::ExtendError;
use hmac::{digest::InvalidLength, Hmac, Mac};
use sha2::Sha512;

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

const KEY_SIZE: usize = 32;

type HmacSha512 = Hmac<Sha512>;

//----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChainCode([u8; KEY_SIZE]);
fixed_bytes!(ChainCode);

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
