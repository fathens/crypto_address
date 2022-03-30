use core::num::ParseIntError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EAddressError(String);

impl EAddressError {
    pub fn wrong_format() -> EAddressError {
        EAddressError("Wrong format address".to_owned())
    }
}

impl From<ParseIntError> for EAddressError {
    fn from(src: ParseIntError) -> Self {
        EAddressError(src.to_string())
    }
}
