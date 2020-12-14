use super::Header;
use crate::decode::Decoder;
use crate::rr::URI;
use crate::DecodeResult;
use std::str::from_utf8;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    pub(super) fn rr_uri(&mut self, header: Header) -> DecodeResult<URI> {
        let class = header.get_class()?;
        let priority = self.u16()?;
        let weight = self.u16()?;
        let buffer = self.vec()?;
        let uri = from_utf8(buffer.as_ref())?.to_owned();
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
