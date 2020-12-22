use super::Header;
use crate::decode::Decoder;
use crate::rr::{EUI48, EUI64};
use crate::DecodeResult;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    pub(super) fn rr_eui48(&mut self, header: Header) -> DecodeResult<EUI48> {
        let class = header.get_class()?;
        let mut eui_48: [u8; 6] = [0; 6];
        eui_48[0] = self.u8()?;
        eui_48[1] = self.u8()?;
        eui_48[2] = self.u8()?;
        eui_48[3] = self.u8()?;
        eui_48[4] = self.u8()?;
        eui_48[5] = self.u8()?;

        let eui_48 = EUI48 {
            domain_name: header.domain_name,
            ttl: header.ttl,
            class,
            eui_48,
        };
        Ok(eui_48)
    }

    pub(super) fn rr_eui64(&mut self, header: Header) -> DecodeResult<EUI64> {
        let class = header.get_class()?;
        let mut eui_64: [u8; 8] = [0; 8];
        eui_64[0] = self.u8()?;
        eui_64[1] = self.u8()?;
        eui_64[2] = self.u8()?;
        eui_64[3] = self.u8()?;
        eui_64[4] = self.u8()?;
        eui_64[5] = self.u8()?;
        eui_64[6] = self.u8()?;
        eui_64[7] = self.u8()?;

        let eui_64 = EUI64 {
            domain_name: header.domain_name,
            ttl: header.ttl,
            class,
            eui_64,
        };
        Ok(eui_64)
    }
}
