use crate::encode::Encoder;

impl Encoder {
    impl_encode_rr_domain_name!(DNAME, target, rr_dname);
}

impl_encode_rr!(DNAME, rr_dname);
