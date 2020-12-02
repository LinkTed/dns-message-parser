use crate::encode::Encoder;

impl Encoder {
    impl_encode_rr_u16_domain_name!(KX, preference, exchanger, rr_kx);
}

impl_encode_rr!(KX, rr_kx);
