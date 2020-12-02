use crate::encode::Encoder;

impl Encoder {
    impl_encode_rr_vec!(EID, data, rr_eid);

    impl_encode_rr_vec!(NIMLOC, data, rr_nimloc);
}

impl_encode_rr!(EID, rr_eid);

impl_encode_rr!(NIMLOC, rr_nimloc);
