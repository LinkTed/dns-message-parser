use super::Header;
use crate::decode::Decoder;
use crate::rr::GPOS;
use crate::{DecodeError, DecodeResult};

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    pub(super) fn rr_gpos(&mut self, header: Header) -> DecodeResult<GPOS> {
        let class = header.get_class()?;

        // TODO String value check
        let longitude = self.string_with_len()?;
        let longitude_len = longitude.len();
        if !(1..=256).contains(&longitude_len) {
            return Err(DecodeError::GPOS);
        }

        let latitude = self.string_with_len()?;
        let latitude_len = latitude.len();
        if !(1..=256).contains(&latitude_len) {
            return Err(DecodeError::GPOS);
        }

        let altitude = self.string_with_len()?;
        let altitude_len = altitude.len();
        if !(1..=256).contains(&altitude_len) {
            return Err(DecodeError::GPOS);
        }

        let gpos = GPOS {
            domain_name: header.domain_name,
            ttl: header.ttl,
            class,
            longitude,
            latitude,
            altitude,
        };
        Ok(gpos)
    }
}
