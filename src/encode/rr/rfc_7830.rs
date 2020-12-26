use crate::encode::Encoder;
use crate::rr::{EDNSOptionCode, Padding};

impl Encoder {
    pub(super) fn rr_edns_padding(&mut self, padding: &Padding) {
        self.rr_edns_option_code(&EDNSOptionCode::Padding);
        self.u16(padding.0);
        for _ in 0..padding.0 {
            self.u8(0);
        }
    }
}
