use super::Header;
use crate::decode::Decoder;
use crate::rr::{Tag, CAA};
use crate::DecodeResult;
use std::convert::TryFrom;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    fn rr_caa_tag(&mut self) -> DecodeResult<Tag> {
        let tag = self.string()?;
        let tag = Tag::try_from(tag)?;
        Ok(tag)
    }

    pub(super) fn rr_caa(&mut self, header: Header) -> DecodeResult<CAA> {
        let class = header.get_class()?;
        let flags = self.u8()?;
        let tag = self.rr_caa_tag()?;
        let value = self.vec()?;

        let caa = CAA {
            domain_name: header.domain_name,
            ttl: header.ttl,
            class,
            flags,
            tag,
            value,
        };
        Ok(caa)
    }
}
