use super::Header;
use crate::decode::Decoder;
use crate::rr::{Class, AAAA};
use crate::{DecodeError, DecodeResult};

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    pub(super) fn rr_aaaa(&mut self, header: Header) -> DecodeResult<AAAA> {
        match header.get_class()? {
            Class::IN => {
                let ipv6_addr = self.ipv6_addr()?;
                let aaaa = AAAA {
                    domain_name: header.domain_name,
                    ttl: header.ttl,
                    ipv6_addr,
                };
                Ok(aaaa)
            }
            class => Err(DecodeError::AAAAError(class)),
        }
    }
}
