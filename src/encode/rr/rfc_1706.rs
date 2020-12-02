use crate::encode::Encoder;

impl Encoder {
    impl_encode_rr_vec!(NSAP, data, rr_nsap);
}

impl_encode_rr!(NSAP, rr_nsap);
