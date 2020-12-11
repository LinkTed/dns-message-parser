use crate::decode::Decoder;
use crate::rr::Cookie;
use crate::{DecodeError, DecodeResult};
use std::convert::TryInto;
use std::mem::size_of;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    pub(super) fn rr_edns_cookie(&mut self) -> DecodeResult<Cookie> {
        let vec = self.vec()?;
        let vec_len = vec.len();
        if vec_len == size_of::<[u8; 8]>() {
            let client_cookie = vec[0..8].try_into().unwrap();
            let cookie = Cookie {
                client_cookie,
                server_cookie: Vec::new(),
            };
            Ok(cookie)
        } else if (16..=40).contains(&vec_len) {
            let client_cookie = vec[0..8].try_into().unwrap();
            let server_cookie = vec[8..].to_vec();
            let cookie = Cookie {
                client_cookie,
                server_cookie,
            };
            Ok(cookie)
        } else {
            Err(DecodeError::CookieLength(vec_len))
        }
    }
}
