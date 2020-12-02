use super::Header;
use crate::decode::Decoder;
use crate::rr::URI;
use crate::DecodeResult;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    pub(super) fn rr_uri(&mut self, header: Header) -> DecodeResult<URI> {
        let class = header.get_class()?;
        let priority = self.u16()?;
        let weight = self.u16()?;
        let buffer = self.vec()?;
        let uri = String::from_utf8(buffer)?;
        let uri = URI {
            domain_name: header.domain_name,
            ttl: header.ttl,
            class,
            priority,
            weight,
            uri,
        };
        Ok(uri)
    }
}
