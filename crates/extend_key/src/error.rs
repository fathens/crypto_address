use hmac::digest::InvalidLength;

#[derive(Debug)]
pub struct ExtendError(String);

impl ExtendError {
    pub fn depth_exceeded() -> ExtendError {
        ExtendError("Exceeded depth".to_owned())
    }

    pub fn wrong_length_bytes() -> ExtendError {
        ExtendError("Wrong length bytes".to_owned())
    }

    pub fn cannot_hardened() -> ExtendError {
        ExtendError("Public key can not derive hardened key".to_owned())
    }

    pub fn invalid_format(target: &str) -> ExtendError {
        ExtendError(format!("Invalid bytes format for {target}"))
    }

    pub fn type_missmatched() -> ExtendError {
        ExtendError("Type miss-matched".to_owned())
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
