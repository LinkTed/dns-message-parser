macro_rules! impl_decode {
    ($i:path, $m:ident) => {
        impl_decode!($i, $m, decode);
    };
    ($i:path, $m:ident, $n:ident) => {
        impl $i {
            pub fn $n(bytes: bytes::Bytes) -> crate::DecodeResult<$i> {
                let mut decoder = crate::decode::Decoder::main(bytes);
                decoder.$m()
            }
        }
    };
}
