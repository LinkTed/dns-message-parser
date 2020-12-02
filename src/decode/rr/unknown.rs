use crate::decode::Decoder;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    impl_decode_rr_vec!(EID, data, rr_eid);

    impl_decode_rr_vec!(NIMLOC, data, rr_nimloc);
}
