macro_rules! fixed_bytes {
    ($t:ident) => {
        impl TryFrom<&[u8]> for $t {
            type Error = crate::ExtendError;

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                Ok(Self(value.try_into().map_err(|_| crate::ExtendError::wrong_length_bytes())?))
            }
        }

        impl AsRef<[u8]> for $t {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
    };
}
pub(crate) use fixed_bytes;
