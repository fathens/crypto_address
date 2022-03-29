use core::fmt;

use extend_key::ecdsa_key::PubKeyBytes;
use sha3::{Digest, Keccak256};

pub struct EvmAddress([u8; 20]);

impl fmt::Display for EvmAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().fold(f.write_str("0x"), |prev, b| {
            prev.and_then(|_| f.write_fmt(format_args!("{b:02x}")))
        })
    }
}

impl From<PubKeyBytes> for EvmAddress {
    fn from(src: PubKeyBytes) -> Self {
        let data = src.uncompressed_bytes();
        let mut keccak = Keccak256::new();
        keccak.update(&data[1..]);
        let result32 = keccak.finalize();
        let array = &result32[12..];
        Self(array.try_into().expect("Should be 20 bytes"))
    }
}

#[cfg(test)]
mod test {
    use extend_key::{
        base58::Prefix,
        ecdsa_key::{PrvKey, PrvKeyBytes},
        extkey::ExtKey,
    };

    use super::EvmAddress;

    const SAMPLE_MNEMONIC: &'static str =
        "oyster steel news moment oval south spider special divide rule cream army";
    const SAMPLE_ADDRESS: &'static str = "0x46718B1e73047a691c259995ed135f4933214f2c";
    const SAMPLE_HDPATH: &'static str = "m/44'/60'/0'/0/0";

    type ExtPrvKey = ExtKey<PrvKeyBytes>;

    #[test]
    fn sample_01() {
        let words: Vec<_> = SAMPLE_MNEMONIC.split(' ').collect();
        let seed = mnemonic::calcseed::to_seed(&words).unwrap();
        let m = ExtPrvKey::from_seed(Prefix::XPRV, seed).unwrap();
        let prvkey = m.derive_child(SAMPLE_HDPATH.parse().unwrap()).unwrap();
        let address: EvmAddress = prvkey.get_key().get_public().unwrap().into();
        assert_eq!(SAMPLE_ADDRESS.to_lowercase(), address.to_string());
    }
}
