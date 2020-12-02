use crate::encode::Encoder;
use crate::rr::{Class, Type, AAAA};
use crate::EncodeResult;

impl Encoder {
    pub(super) fn rr_aaaa(&mut self, aaaa: &AAAA) -> EncodeResult<()> {
        self.domain_name(&aaaa.domain_name)?;
        self.rr_type(&Type::AAAA)?;
        self.rr_class(&Class::IN)?;
        self.u32(aaaa.ttl);
        let length_index = self.create_length_index();
        self.ipv6_addr(&aaaa.ipv6_addr);
        self.set_length_index(length_index)
    }
}

impl_encode_rr!(AAAA, rr_aaaa);
