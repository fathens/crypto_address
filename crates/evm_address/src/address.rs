use crate::error::EAddressError;
use core::{fmt, str};
use extend_key::ecdsa_key::PubKeyBytes;
use sha3::{Digest, Keccak256};

const BYTE_SIZE: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvmAddress([u8; BYTE_SIZE]);

impl EvmAddress {
    fn lower_hex(&self) -> String {
        let mut result = String::with_capacity(self.0.len() * 2);
        self.0.iter().for_each(|b| {
            result.push_str(format!("{b:02x}").as_str());
        });
        result
    }

    pub fn encode_with_checksum(&self) -> String {
        Self::to_with_checksum(self.lower_hex().as_str())
    }

    fn to_with_checksum(src: &str) -> String {
        let lowers = src.trim_start_matches("0x").to_lowercase();
        let mut keccak = Keccak256::new();
        keccak.update(lowers.as_bytes());
        let hashed = keccak.finalize();
        assert!(hashed.len() >= lowers.len() / 2);

        let mut result = String::with_capacity(lowers.len() + 2);
        result.push_str("0x");
        lowers.chars().enumerate().for_each(|(i, c)| {
            let v = hashed[i / 2];
            let p = if i % 2 == 0 { v >> 4 } else { v & 15 };
            let a = if p < 8 { c } else { c.to_ascii_uppercase() };
            result.push(a);
        });
        result
    }
}

impl fmt::Display for EvmAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.encode_with_checksum().as_str())
    }
}

impl str::FromStr for EvmAddress {
    type Err = EAddressError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        if src.len() != (BYTE_SIZE + 1) * 2 {
            return Err(EAddressError::wrong_format());
        }
        let hexes = src
            .strip_prefix("0x")
            .ok_or(EAddressError::wrong_format())?;
        (0..BYTE_SIZE)
            .fold(Ok([0u8; BYTE_SIZE]), |prev, index| {
                prev.and_then(|mut bs| {
                    let i = index * 2;
                    let hex = &hexes[i..(i + 2)];
                    bs[index] = u8::from_str_radix(hex, 16)?;
                    Ok(bs)
                })
            })
            .map(EvmAddress)
    }
}

impl From<PubKeyBytes> for EvmAddress {
    fn from(src: PubKeyBytes) -> Self {
        let data = src.uncompressed_bytes();
        let mut keccak = Keccak256::new();
        keccak.update(&data[1..]);
        let result32 = keccak.finalize();
        let drop = result32.len() - BYTE_SIZE;
        let array = &result32[drop..];
        Self(array.try_into().expect("Should be 20 bytes"))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use extend_key::{
        base58::Prefix,
        ecdsa_key::{PrvKey, PrvKeyBytes},
        extkey::ExtKey,
    };

    type ExtPrvKey = ExtKey<PrvKeyBytes>;

    #[test]
    fn from_pubkey() {
        let words = vec![
            "oyster", "steel", "news", "moment", "oval", "south", "spider", "special", "divide",
            "rule", "cream", "army",
        ];
        let address = "0x46718B1e73047a691c259995ed135f4933214f2c";
        let hdpath = "m/44'/60'/0'/0/0";

        let seed = mnemonic::calcseed::to_seed(&words).unwrap();
        let m = ExtPrvKey::from_seed(Prefix::XPRV, seed).unwrap();
        let prvkey = m.derive_child(hdpath.parse().unwrap()).unwrap();
        let ea: EvmAddress = prvkey.get_key().get_public().unwrap().into();
        assert_eq!(address, ea.to_string());
    }

    #[test]
    fn parse_and_checksum() {
        [
            "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
            "0x5c8b3c7fcd0aED659054A83d8a9aD08e16CbeD9b",
            "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE",
            "0x7D2846FEe032fA5087257FaB6f27Ba1E165Ced94",
            "0x44d71f3C57E0fe9E1a3D79B006aB95b49fbb2C45",
            "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
            "0xA5d30762Ce541742F04751754eBe0fd1758DbBf1",
            "0x430483843bb82655C38E0eE56480Bd0Aa7a0a1Cf",
        ]
        .into_iter()
        .for_each(|src| {
            assert_eq!(src, EvmAddress::to_with_checksum(&src.to_lowercase()));
            assert_eq!(src, EvmAddress::to_with_checksum(&src.to_lowercase()[2..]));

            let ea: EvmAddress = src.parse().unwrap();
            assert_eq!(src, ea.to_string());
        });
    }

    #[test]
    fn parse_failures() {
        ["", "0xabc", "0x1x3", "abcd"].into_iter().for_each(|src| {
            let r: Result<EvmAddress, _> = src.parse();
            assert!(r.is_err());
        });
    }
}
