use super::words::convert_to_num;
use bytes::Bytes;
use hmac::Hmac;
use num_bigint::BigUint;
use pbkdf2::pbkdf2;
use sha2::{Digest, Sha256, Sha512};
use std::{
    io::{Error, ErrorKind, Result},
    ops::{BitAnd, Shl},
    ops::{Shr, Sub},
};

fn checksum(bs: &[u8], len_cbits: usize) -> BigUint {
    let mut hash = Sha256::new();
    hash.update(bs);
    let hb = hash.finalize();
    let num = BigUint::from_bytes_be(&hb);
    num.shr(256 - len_cbits)
}

fn validate(mnemonic: &Vec<&str>) -> Result<()> {
    let length = mnemonic.len();
    if length < 12 || length % 3 != 0 {
        return Result::Err(Error::new(ErrorKind::InvalidInput, "Wrong length of words"));
    }
    let len_cbits = length / 3;
    let len_target = length + len_cbits;

    let nums = convert_to_num(mnemonic)?;
    let value: BigUint = nums.iter().fold(0_u8.into(), |n, v| n.shl(11_u8) + v);

    let actual_checksum = {
        let mut bs = value.clone().shr(len_cbits).to_bytes_le();
        while bs.len() < len_target {
            bs.push(0);
        }
        bs.reverse();
        checksum(bs.as_ref(), len_cbits)
    };
    let expected_checksum = {
        let mask = BigUint::from(1_u8).shl(len_cbits).sub(1_u8);
        value.bitand(mask)
    };

    if expected_checksum == actual_checksum {
        Result::Ok(())
    } else {
        Result::Err(Error::new(ErrorKind::InvalidInput, "Wrong checksum"))
    }
}

pub fn to_seed(mnemonic: &Vec<&str>, salt: &str) -> Result<Bytes> {
    validate(mnemonic)?;

    let mut result = vec![0; 64];

    pbkdf2::<Hmac<Sha512>>(
        mnemonic.join(" ").as_bytes(),
        ("mnemonic".to_string() + salt).as_bytes(),
        2048,
        &mut result,
    );
    println!("length = {}", result.len());

    Result::Ok(result.into())
}

#[cfg(test)]
mod test {
    use bytes::Bytes;

    use super::to_seed;

    #[test]
    fn sample256_seed() {
        let mnemonic = vec![
            "menu", "blade", "suit", "police", "family", "snap", "guide", "powder", "protect",
            "topic", "unfold", "weapon", "remain", "solid", "jacket", "expire", "mind", "certain",
            "reveal", "cool", "excite", "noise", "stand", "hood",
        ];
        let expected_seed = decode_hex("7ec22a3b2a5380aec912b336b89fed7d595cb21e66ba08d99c8012f2bdb1d988d32fd158ee0b8a57f4a4d97e6e34546e1ae7f89ed1ac6dfac2ea312ca93232de").unwrap();
        let actual_seed = to_seed(&mnemonic, "").unwrap();
        assert_eq!(expected_seed, actual_seed);
    }

    #[test]
    fn sample128_seed() {
        let mnemonic = vec![
            "bundle", "elephant", "observe", "exile", "glance", "desk", "above", "flag", "neither",
            "squeeze", "denial", "day",
        ];
        let expected_seed = decode_hex("00e93e7f34b53297cfa9bebffb48bac5e0fe6f79eb88598ea61881d3bde1e50125e56a8bbe6d333be3bf2be8309e2137977c9ac22c3a15ce0212fe26bfbc4b6d").unwrap();
        let actual_seed = to_seed(&mnemonic, "").unwrap();
        assert_eq!(expected_seed, actual_seed);
    }

    fn decode_hex(s: &str) -> Result<Bytes, std::num::ParseIntError> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect()
    }
}
