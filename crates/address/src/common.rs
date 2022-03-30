use extend_key::ecdsa_key::PubKeyBytes;
use sha3::{Digest, Keccak256};

pub const BYTE_SIZE: usize = 20;

pub fn mk_hash(src: PubKeyBytes) -> [u8; 20] {
    let data = src.uncompressed_bytes();
    let mut keccak = Keccak256::new();
    keccak.update(&data[1..]);
    let result32 = keccak.finalize();
    let drop = result32.len() - BYTE_SIZE;
    let array = &result32[drop..];
    array.try_into().expect("Should be 20 bytes")
}
