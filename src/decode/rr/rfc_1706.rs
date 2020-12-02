use crate::decode::Decoder;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    impl_decode_rr_vec!(NSAP, data, rr_nsap);
}
