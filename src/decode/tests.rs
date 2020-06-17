use super::{
    decode_ipv4_addr, decode_ipv6_addr, decode_string, decode_u16, decode_u32, decode_u8,
    DecodeError,
};
use bytes::Bytes;
use std::str::from_utf8;

#[test]
fn u8_error() {
    let bytes = Bytes::copy_from_slice(&b""[..]);
    let mut offset = 0;
    let result = decode_u8(&bytes, &mut offset);
    assert_eq!(result, Err(DecodeError::NotEnoughData));
}

#[test]
fn u16_error() {
    let bytes = Bytes::copy_from_slice(&b"\x00"[..]);
    let mut offset = 0;
    let result = decode_u16(&bytes, &mut offset);
    assert_eq!(result, Err(DecodeError::NotEnoughData));
}

#[test]
fn u32_error() {
    let bytes = Bytes::copy_from_slice(&b"\x00\x00\x00"[..]);
    let mut offset = 0;
    let result = decode_u32(&bytes, &mut offset);
    assert_eq!(result, Err(DecodeError::NotEnoughData));
}

#[test]
fn string_error_1() {
    let bytes = Bytes::copy_from_slice(&b""[..]);
    let mut offset = 0;
    let result = decode_string(&bytes, &mut offset);
    assert_eq!(result, Err(DecodeError::NotEnoughData));
}

#[test]
fn string_error_2() {
    let bytes = Bytes::copy_from_slice(&b"\x0f\x41\x42"[..]);
    let mut offset = 0;
    let result = decode_string(&bytes, &mut offset);
    assert_eq!(result, Err(DecodeError::NotEnoughData));
}

#[test]
fn string_error_3() {
    let bytes = Bytes::copy_from_slice(&b"\x02\x00\xff"[..]);
    let mut offset = 0;
    let result = decode_string(&bytes, &mut offset);
    let excepted = from_utf8(&bytes[1..]).unwrap_err();
    assert_eq!(result, Err(DecodeError::Utf8Error(excepted)));
}

#[test]
fn ipv4_addr_1() {
    let bytes = Bytes::copy_from_slice(&b""[..]);
    let mut offset = 0;
    let result = decode_ipv4_addr(&bytes, &mut offset);
    assert_eq!(result, Err(DecodeError::NotEnoughData));
}

#[test]
fn ipv4_addr_2() {
    let bytes = Bytes::copy_from_slice(&b"\xff"[..]);
    let mut offset = 0;
    let result = decode_ipv4_addr(&bytes, &mut offset);
    assert_eq!(result, Err(DecodeError::NotEnoughData));
}

#[test]
fn ipv4_addr_3() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff"[..]);
    let mut offset = 0;
    let result = decode_ipv4_addr(&bytes, &mut offset);
    assert_eq!(result, Err(DecodeError::NotEnoughData));
}

#[test]
fn ipv4_addr_4() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff\xff"[..]);
    let mut offset = 0;
    let result = decode_ipv4_addr(&bytes, &mut offset);
    assert_eq!(result, Err(DecodeError::NotEnoughData));
}

#[test]
fn ipv6_addr_1() {
    let bytes = Bytes::copy_from_slice(&b""[..]);
    let mut offset = 0;
    let result = decode_ipv6_addr(&bytes, &mut offset);
    assert_eq!(result, Err(DecodeError::NotEnoughData));
}

#[test]
fn ipv6_addr_2() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff"[..]);
    let mut offset = 0;
    let result = decode_ipv6_addr(&bytes, &mut offset);
    assert_eq!(result, Err(DecodeError::NotEnoughData));
}

#[test]
fn ipv6_addr_3() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff\xff\xff"[..]);
    let mut offset = 0;
    let result = decode_ipv6_addr(&bytes, &mut offset);
    assert_eq!(result, Err(DecodeError::NotEnoughData));
}

#[test]
fn ipv6_addr_4() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff\xff\xff\xff\xff"[..]);
    let mut offset = 0;
    let result = decode_ipv6_addr(&bytes, &mut offset);
    assert_eq!(result, Err(DecodeError::NotEnoughData));
}

#[test]
fn ipv6_addr_5() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff\xff\xff\xff\xff\xff\xff"[..]);
    let mut offset = 0;
    let result = decode_ipv6_addr(&bytes, &mut offset);
    assert_eq!(result, Err(DecodeError::NotEnoughData));
}

#[test]
fn ipv6_addr_6() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"[..]);
    let mut offset = 0;
    let result = decode_ipv6_addr(&bytes, &mut offset);
    assert_eq!(result, Err(DecodeError::NotEnoughData));
}

#[test]
fn ipv6_addr_7() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"[..]);
    let mut offset = 0;
    let result = decode_ipv6_addr(&bytes, &mut offset);
    assert_eq!(result, Err(DecodeError::NotEnoughData));
}

#[test]
fn ipv6_addr_8() {
    let bytes =
        Bytes::copy_from_slice(&b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"[..]);
    let mut offset = 0;
    let result = decode_ipv6_addr(&bytes, &mut offset);
    assert_eq!(result, Err(DecodeError::NotEnoughData));
}
