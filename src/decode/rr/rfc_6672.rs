use crate::decode::Decoder;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    impl_decode_rr_domain_name!(DNAME, target, rr_dname);
}
