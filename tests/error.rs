use dns_message_parser::rr::{Cookie, CookieError};

#[test]
fn opt_cookie_server_cookie_length() {
    let client_cookie = b"\xd5\xa7\xe3\x00\x4d\x79\x05\x1e".to_owned();
    let server_cookie = Some(b"\x01\x00\x00\x00".to_vec());
    let cookie = Cookie::new(client_cookie, server_cookie);
    assert_eq!(cookie, Err(CookieError::ServerCookieLength(4)))
}
