use hmac::digest::InvalidLength;

#[derive(Debug)]
pub struct ExtendError(pub String);

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
