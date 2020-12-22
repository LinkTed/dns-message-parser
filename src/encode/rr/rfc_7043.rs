use crate::encode::Encoder;
use crate::rr::{Type, EUI48, EUI64};
use crate::EncodeResult;

impl Encoder {
    pub(super) fn rr_eui48(&mut self, eui_48: &EUI48) -> EncodeResult<()> {
        self.domain_name(&eui_48.domain_name)?;
        self.rr_type(&Type::EUI48);
        self.rr_class(&eui_48.class);
        self.u32(eui_48.ttl);
        let length_index = self.create_length_index();
        self.u8(eui_48.eui_48[0]);
        self.u8(eui_48.eui_48[1]);
        self.u8(eui_48.eui_48[2]);
        self.u8(eui_48.eui_48[3]);
        self.u8(eui_48.eui_48[4]);
        self.u8(eui_48.eui_48[5]);
        self.set_length_index(length_index)
    }

    pub(super) fn rr_eui64(&mut self, eui_64: &EUI64) -> EncodeResult<()> {
        self.domain_name(&eui_64.domain_name)?;
        self.rr_type(&Type::EUI64);
        self.rr_class(&eui_64.class);
        self.u32(eui_64.ttl);
        let length_index = self.create_length_index();
        self.u8(eui_64.eui_64[0]);
        self.u8(eui_64.eui_64[1]);
        self.u8(eui_64.eui_64[2]);
        self.u8(eui_64.eui_64[3]);
        self.u8(eui_64.eui_64[4]);
        self.u8(eui_64.eui_64[5]);
        self.u8(eui_64.eui_64[6]);
        self.u8(eui_64.eui_64[7]);
        self.set_length_index(length_index)
    }
}
