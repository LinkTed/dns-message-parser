use super::Header;
use crate::decode::Decoder;
use crate::rr::L32;
use crate::DecodeResult;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    impl_decode_rr_u16_u64!(NID, preference, node_id, rr_nid);

    pub(super) fn rr_l32(&mut self, header: Header) -> DecodeResult<L32> {
        let class = header.get_class()?;
        let preference = self.u16()?;
        let locator_32 = self.u32()?;
        let l_32 = L32 {
            domain_name: header.domain_name,
            ttl: header.ttl,
            class,
            preference,
            locator_32,
        };
        Ok(l_32)
    }

    impl_decode_rr_u16_u64!(L64, preference, locator_64, rr_l64);

    impl_decode_rr_u16_domain_name!(LP, preference, fqdn, rr_lp);
}
