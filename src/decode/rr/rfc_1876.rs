use super::Header;
use crate::decode::Decoder;
use crate::rr::LOC;
use crate::DecodeResult;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    pub(super) fn rr_loc(&mut self, header: Header) -> DecodeResult<LOC> {
        let class = header.get_class()?;

        let version = self.u8()?;
        let size = self.u8()?;
        let horiz_pre = self.u8()?;
        let vert_pre = self.u8()?;

        let latitube = self.u32()?;
        let longitube = self.u32()?;
        let altitube = self.u32()?;

        let loc = LOC {
            domain_name: header.domain_name,
            ttl: header.ttl,
            class,
            version,
            size,
            horiz_pre,
            vert_pre,
            latitube,
            longitube,
            altitube,
        };
        Ok(loc)
    }
}
