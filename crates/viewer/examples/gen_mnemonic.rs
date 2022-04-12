use bytes::Bytes;
use getrandom::getrandom;
use mnemonic::calcseed::to_mnemonic;
use std::env;

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        panic!("Bits length must be specified.");
    }
    let arg = &args[1];
    let bits_len: u16 = arg.parse().expect("Must be number");
    if !(bits_len == 128 || bits_len == 256 || bits_len == 512) {
        panic!("bits length must be 128, 256 or 512");
    }
    let bytes = random_bytes((bits_len / 8) as usize);
    let words = to_mnemonic(bytes).unwrap();
    println!("{}", words.join(" "));
}

fn random_bytes(len_bytes: usize) -> Bytes {
    let mut buf = vec![0; len_bytes];
    getrandom(&mut buf).unwrap();
    buf.into()
}
