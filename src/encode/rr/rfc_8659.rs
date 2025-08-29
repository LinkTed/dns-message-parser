use crate::encode::Encoder;
use crate::rr::{Tag, Type, CAA};
use crate::EncodeResult;

impl Encoder {
    fn rr_caa_tag(&mut self, tag: &Tag) -> EncodeResult<()> {
        self.string_with_len(tag.as_ref())
    }

    pub(super) fn rr_caa(&mut self, caa: &CAA) -> EncodeResult<()> {
        self.domain_name(&caa.domain_name)?;
        self.rr_type(&Type::CAA);
        self.rr_class(&caa.class);
        self.u32(caa.ttl);
        let length_index = self.create_length_index();
        self.u8(caa.flags);
        self.rr_caa_tag(&caa.tag)?;
        self.vec(&caa.value);
        self.set_length_index(length_index)
    }
}
