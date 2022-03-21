pub trait FixedBytes {
    fn copy_bytes(&self) -> bytes::Bytes;
}
