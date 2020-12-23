use crate::encode::Encoder;
use crate::rr::{Type, L32};
use crate::EncodeResult;

impl Encoder {
    impl_encode_rr_u16_u64!(NID, preference, node_id, rr_nid);

    pub(super) fn rr_l32(&mut self, l_32: &L32) -> EncodeResult<()> {
        self.domain_name(&l_32.domain_name)?;
        self.rr_type(&Type::L32);
        self.rr_class(&l_32.class);
        self.u32(l_32.ttl);
        let length_index = self.create_length_index();
        self.u16(l_32.preference);
        self.u32(l_32.locator_32);
        self.set_length_index(length_index)
    }

    impl_encode_rr_u16_u64!(L64, preference, locator_64, rr_l64);

    impl_encode_rr_u16_domain_name!(LP, preference, fqdn, rr_lp);
}
