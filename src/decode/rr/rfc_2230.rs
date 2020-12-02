use crate::decode::Decoder;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    impl_decode_rr_u16_domain_name!(KX, preference, exchanger, rr_kx);
}
