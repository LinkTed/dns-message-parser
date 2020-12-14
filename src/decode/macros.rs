macro_rules! impl_decode {
    ($i:path, $m:ident) => {
        impl $i {
            pub fn decode(bytes: bytes::Bytes) -> crate::DecodeResult<$i> {
                let mut decoder = crate::decode::Decoder::main(bytes);
                decoder.$m()
            }
        }
    };
}
