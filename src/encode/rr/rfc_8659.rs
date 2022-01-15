use crate::{
    encode::Encoder,
    rr::{Tag, Type, CAA},
    EncodeResult,
};

impl Encoder {
    fn rr_caa_tag(&mut self, tag: &Tag) -> EncodeResult<()> {
        self.string(tag.as_ref())
    }

    pub(super) fn rr_caa(&mut self, caa: &CAA) -> EncodeResult<()> {
        self.domain_name(&caa.domain_name)?;
        self.rr_type(&Type::CAA);
        self.rr_class(&caa.class);
        self.u32(caa.ttl);
        let length_index = self.create_length_index_u16();
        self.u8(caa.flags);
        self.rr_caa_tag(&caa.tag)?;
        self.vec(&caa.value);
        self.set_length_index_u16(length_index)
    }
}
