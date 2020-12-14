use crate::encode::Encoder;
use crate::rr::{Type, GPOS};
use crate::EncodeResult;

impl Encoder {
    pub(super) fn rr_gpos(&mut self, gpos: &GPOS) -> EncodeResult<()> {
        self.domain_name(&gpos.domain_name)?;
        self.rr_type(&Type::GPOS);
        self.rr_class(&gpos.class);
        self.u32(gpos.ttl);
        let length_index = self.create_length_index();
        self.string(&gpos.longitude)?;
        self.string(&gpos.latitude)?;
        self.string(&gpos.altitude)?;
        self.set_length_index(length_index)
    }
}

impl_encode_rr!(GPOS, rr_gpos);
