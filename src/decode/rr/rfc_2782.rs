use super::Header;
use crate::decode::Decoder;
use crate::rr::SRV;
use crate::DecodeResult;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    pub(super) fn rr_srv(&mut self, header: Header) -> DecodeResult<SRV> {
        let class = header.get_class()?;
        let priority = self.u16()?;
        let weight = self.u16()?;
        let port = self.u16()?;
        let target = self.domain_name()?;
        let srv = SRV {
            domain_name: header.domain_name,
            ttl: header.ttl,
            class,
            priority,
            weight,
            port,
            target,
        };
        Ok(srv)
    }
}
