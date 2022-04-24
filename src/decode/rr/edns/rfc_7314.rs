use crate::{decode::Decoder, rr::edns::Expire, DecodeResult};

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    pub(super) fn rr_edns_expire(&mut self) -> DecodeResult<Expire> {
        if self.is_finished()? {
            Ok(Expire { seconds: None })
        } else {
            Ok(Expire {
                seconds: Some(self.u32()?),
            })
        }
    }
}
