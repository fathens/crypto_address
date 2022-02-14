use super::words::convert_to_num;
use bytes::Bytes;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
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

pub fn to_seed(mnemonic: &Vec<&str>, password: &str) -> Result<Bytes> {
    validate(mnemonic)?;
    // TODO Impl
    Result::Ok(Bytes::default())
}
