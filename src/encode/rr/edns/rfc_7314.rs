use crate::{
    encode::Encoder,
    rr::edns::{EDNSOptionCode, Expire},
};
use std::mem::size_of;

impl Encoder {
    pub(super) fn rr_edns_expire(&mut self, expire: &Expire) {
        self.rr_edns_option_code(&EDNSOptionCode::Expire);
        if let Some(seconds) = expire.seconds {
            self.u16(size_of::<u32>() as u16);
            self.u32(seconds);
        } else {
            self.u16(0);
        }
    }
}
