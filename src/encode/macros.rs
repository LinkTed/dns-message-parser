macro_rules! impl_encode_without_result {
    ($i:path, $m:ident) => {
        impl $i {
            pub fn encode(&self) -> bytes::BytesMut {
                let mut encoder = crate::encode::Encoder::default();
                encoder.$m(self);
                encoder.bytes
            }
        }
    };
}

macro_rules! impl_encode {
    ($i:path, $m:ident) => {
        impl $i {
            pub fn encode(&self) -> crate::EncodeResult<bytes::BytesMut> {
                let mut encoder = crate::encode::Encoder::default();
                encoder.$m(self)?;
                Ok(encoder.bytes)
            }
        }
    };
}
