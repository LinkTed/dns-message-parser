use crate::encode::Encoder;
use crate::rr::{Type, PX};
use crate::EncodeResult;

impl Encoder {
    pub(super) fn rr_px(&mut self, px: &PX) -> EncodeResult<()> {
        self.domain_name(&px.domain_name)?;
        self.rr_type(&Type::PX)?;
        self.rr_class(&px.class)?;
        self.u32(px.ttl);
        let length_index = self.create_length_index();
        self.u16(px.preference);
        self.domain_name(&px.map822)?;
        self.domain_name(&px.mapx400)?;
        self.set_length_index(length_index)
    }
}

impl_encode_rr!(PX, rr_px);
