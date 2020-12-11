use crate::encode::Encoder;
use crate::rr::{Cookie, EDNSOptionCode};
use crate::{EncodeError, EncodeResult};

impl Encoder {
    pub(super) fn rr_edns_cookie(&mut self, cookie: &Cookie) -> EncodeResult<()> {
        self.rr_edns_option_code(&EDNSOptionCode::Cookie)?;
        let length_index = self.create_length_index();
        self.vec(&cookie.client_cookie);
        let server_cookie_len = cookie.server_cookie.len();
        if server_cookie_len != 0 {
            if (8..=32).contains(&server_cookie_len) {
                self.vec(&cookie.server_cookie);
            } else {
                return Err(EncodeError::CookieServerLength(server_cookie_len));
            }
        }
        self.set_length_index(length_index)
    }
}
