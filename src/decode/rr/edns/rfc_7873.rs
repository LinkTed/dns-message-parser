use crate::decode::Decoder;
use crate::rr::edns::{
    Cookie, CLIENT_COOKIE_LENGTH, MAXIMUM_SERVER_COOKIE_LENGTH, MINIMUM_SERVER_COOKIE_LENGTH,
};
use crate::{DecodeError, DecodeResult};
use std::convert::TryInto;

const MINIMUM_COOKIE_LENGTH: usize = CLIENT_COOKIE_LENGTH + MINIMUM_SERVER_COOKIE_LENGTH;
const MAXIMUM_COOKIE_LENGTH: usize = CLIENT_COOKIE_LENGTH + MAXIMUM_SERVER_COOKIE_LENGTH;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    pub(super) fn rr_edns_cookie(&mut self) -> DecodeResult<Cookie> {
        let vec = self.vec()?;
        let vec_len = vec.len();

        if CLIENT_COOKIE_LENGTH == vec_len {
            let client_cookie = vec[0..8].try_into().unwrap();
            let cookie = Cookie::new(client_cookie, None)?;
            Ok(cookie)
        } else if (MINIMUM_COOKIE_LENGTH..MAXIMUM_COOKIE_LENGTH).contains(&vec_len) {
            let client_cookie = vec[0..8].try_into().unwrap();
            let server_cookie = Some(vec[8..].to_vec());
            let cookie = Cookie::new(client_cookie, server_cookie)?;
            Ok(cookie)
        } else {
            Err(DecodeError::CookieLength(vec_len))
        }
    }
}
