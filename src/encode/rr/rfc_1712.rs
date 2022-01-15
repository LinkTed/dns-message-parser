use crate::{
    encode::Encoder,
    rr::{Type, GPOS},
    EncodeResult,
};

impl Encoder {
    pub(super) fn rr_gpos(&mut self, gpos: &GPOS) -> EncodeResult<()> {
        self.domain_name(&gpos.domain_name)?;
        self.rr_type(&Type::GPOS);
        self.rr_class(&gpos.class);
        self.u32(gpos.ttl);
        let length_index = self.create_length_index_u16();
        self.string(&gpos.longitude)?;
        self.string(&gpos.latitude)?;
        self.string(&gpos.altitude)?;
        self.set_length_index_u16(length_index)
    }
}

impl_encode_rr!(GPOS, rr_gpos);
