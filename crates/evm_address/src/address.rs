use core::fmt;

use extend_key::ecdsa_key::PubKeyBytes;

pub struct EvmAddress([u8; 20]);

impl fmt::Display for EvmAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().fold(Ok(()), |prev, b| {
            prev.and_then(|_| f.write_fmt(format_args!("{b:02x}")))
        })
    }
}

pub fn to_address(key: PubKeyBytes) -> EvmAddress {
    todo!()
}

#[cfg(text)]
mod test {
    const SAMPLE_MNEMONIC: &'static str =
        "oyster steel news moment oval south spider special divide rule cream army";
    const SAMPLE_ADDRESS: &'static str = "0x46718B1e73047a691c259995ed135f4933214f2c";
    const SAMPLE_HDPATH: &'static str = "	m/44'/60'/0'/0/0";

}
