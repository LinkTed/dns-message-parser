use crate::encode::Encoder;
use crate::rr::edns::{Cookie, EDNSOptionCode};
use crate::EncodeResult;

impl Encoder {
    pub(super) fn rr_edns_cookie(&mut self, cookie: &Cookie) -> EncodeResult<()> {
        self.rr_edns_option_code(&EDNSOptionCode::Cookie);
        let length_index = self.create_length_index();
        self.vec(&cookie.client_cookie);
        if let Some(server_cookie) = cookie.get_server_cookie() {
            self.vec(server_cookie);
        }
        self.set_length_index(length_index)
    }
}
