use evm_address::address::EvmAddress;
use extend_key::{base58, ecdsa_key::PrvKeyBytes, extkey::ExtKey};
use std::env;

type ExtPrvKey = ExtKey<PrvKeyBytes>;

fn main() {
    let mut args = env::args();
    args.next().unwrap();

    let file_path = args.next().expect("mnemonic file must be specified");
    let lines = std::fs::read_to_string(file_path).unwrap();
    let words: Vec<_> = lines.trim().split(" ").collect();
    let seed = mnemonic::calcseed::to_seed(&words).unwrap();

    let hdpath = args.next().unwrap_or("m/44'/60'/0'/0/0".to_owned());

    let root = ExtPrvKey::from_seed(base58::Prefix::XPRV, seed).unwrap();
    let extprv = root.derive_child(hdpath.parse().unwrap()).unwrap();

    let mut prvbytes = String::new();
    prvbytes.push_str("0x");
    extprv.key.as_ref().iter().for_each(|b| {
        prvbytes.push_str(format!("{b:02x}").as_str());
    });
    println!("{}", prvbytes);

    let address: EvmAddress = extprv.get_public().unwrap().key.into();
    println!("{}", address);
}
