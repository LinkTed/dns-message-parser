use super::Header;
use crate::decode::Decoder;
use crate::rr::PX;
use crate::DecodeResult;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    pub(super) fn rr_px(&mut self, header: Header) -> DecodeResult<PX> {
        let class = header.get_class()?;

        let preference = self.u16()?;
        let map822 = self.domain_name()?;
        let mapx400 = self.domain_name()?;
        let px = PX {
            domain_name: header.domain_name,
            ttl: header.ttl,
            class,
            preference,
            map822,
            mapx400,
        };
        Ok(px)
    }
}
