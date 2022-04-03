use hmac::digest::InvalidLength;

#[derive(Debug)]
pub struct ExtendError(String);

impl core::fmt::Display for ExtendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.as_str())
    }
}

impl ExtendError {
    pub fn invalid_hdpath() -> ExtendError {
        ExtendError("Invalid hdpath".to_owned())
    }

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

    pub fn unsupported_version() -> ExtendError {
        ExtendError("unsupported version".to_owned())
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
