use hmac::digest::InvalidLength;

#[derive(Debug)]
pub struct ExtendError(String);

impl ExtendError {
    pub fn wrong_length_bytes() -> ExtendError {
        ExtendError("Wrong length bytes".to_owned())
    }

    pub fn cannot_hardened() -> ExtendError {
        ExtendError("public key can not derive hardened key".to_owned())
    }

    pub fn invalid_format(target: &str) -> ExtendError {
        ExtendError(format!("Invalid bytes format for {target}"))
    }
}

impl From<InvalidLength> for ExtendError {
    fn from(src: InvalidLength) -> Self {
        Self(src.to_string())
    }
}
impl From<elliptic_curve::Error> for ExtendError {
    fn from(src: elliptic_curve::Error) -> Self {
        Self(src.to_string())
    }
}
