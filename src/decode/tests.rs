use crate::decode::Decoder;
use crate::DecodeError;
use bytes::Bytes;
use std::str::from_utf8;

#[test]
fn u8_error() {
    let bytes = Bytes::copy_from_slice(&b""[..]);
    let mut decoder = Decoder::main(bytes);
    let result = decoder.u8();
    assert_eq!(result, Err(DecodeError::NotEnoughBytes(0, 1)));
}

#[test]
fn u16_error() {
    let bytes = Bytes::copy_from_slice(&b"\x00"[..]);
    let mut decoder = Decoder::main(bytes);
    let result = decoder.u16();
    assert_eq!(result, Err(DecodeError::NotEnoughBytes(1, 2)));
}

#[test]
fn u32_error() {
    let bytes = Bytes::copy_from_slice(&b"\x00\x00\x00"[..]);
    let mut decoder = Decoder::main(bytes);
    let result = decoder.u32();
    assert_eq!(result, Err(DecodeError::NotEnoughBytes(3, 4)));
}

#[test]
fn string_error_1() {
    let bytes = Bytes::copy_from_slice(&b""[..]);
    let mut decoder = Decoder::main(bytes);
    let result = decoder.string();
    assert_eq!(result, Err(DecodeError::NotEnoughBytes(0, 1)));
}

#[test]
fn string_error_2() {
    let bytes = Bytes::copy_from_slice(&b"\x0f\x41\x42"[..]);
    let mut decoder = Decoder::main(bytes);
    let result = decoder.string();
    assert_eq!(result, Err(DecodeError::NotEnoughBytes(3, 16)));
}

#[test]
fn string_error_3() {
    let bytes = Bytes::copy_from_slice(&b"\x02\x00\xff"[..]);
    let mut decoder = Decoder::main(bytes);
    let result = decoder.string();
    let bytes = Bytes::copy_from_slice(&b"\x02\x00\xff"[..]);
    let excepted = from_utf8(&bytes[1..]).unwrap_err();
    assert_eq!(result, Err(DecodeError::Utf8Error(excepted)));
}

#[test]
fn ipv4_addr_1() {
    let bytes = Bytes::copy_from_slice(&b""[..]);
    let mut decoder = Decoder::main(bytes);
    let result = decoder.ipv4_addr();
    assert_eq!(result, Err(DecodeError::NotEnoughBytes(0, 4)));
}

#[test]
fn ipv4_addr_2() {
    let bytes = Bytes::copy_from_slice(&b"\xff"[..]);
    let mut decoder = Decoder::main(bytes);
    let result = decoder.ipv4_addr();
    assert_eq!(result, Err(DecodeError::NotEnoughBytes(1, 4)));
}

#[test]
fn ipv4_addr_3() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff"[..]);
    let mut decoder = Decoder::main(bytes);
    let result = decoder.ipv4_addr();
    assert_eq!(result, Err(DecodeError::NotEnoughBytes(2, 4)));
}

#[test]
fn ipv4_addr_4() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff\xff"[..]);
    let mut decoder = Decoder::main(bytes);
    let result = decoder.ipv4_addr();
    assert_eq!(result, Err(DecodeError::NotEnoughBytes(3, 4)));
}

#[test]
fn ipv6_addr_1() {
    let bytes = Bytes::copy_from_slice(&b""[..]);
    let mut decoder = Decoder::main(bytes);
    let result = decoder.ipv6_addr();
    assert_eq!(result, Err(DecodeError::NotEnoughBytes(0, 2)));
}

#[test]
fn ipv6_addr_2() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff"[..]);
    let mut decoder = Decoder::main(bytes);
    let result = decoder.ipv6_addr();
    assert_eq!(result, Err(DecodeError::NotEnoughBytes(2, 4)));
}

#[test]
fn ipv6_addr_3() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff\xff\xff"[..]);
    let mut decoder = Decoder::main(bytes);
    let result = decoder.ipv6_addr();
    assert_eq!(result, Err(DecodeError::NotEnoughBytes(4, 6)));
}

#[test]
fn ipv6_addr_4() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff\xff\xff\xff\xff"[..]);
    let mut decoder = Decoder::main(bytes);
    let result = decoder.ipv6_addr();
    assert_eq!(result, Err(DecodeError::NotEnoughBytes(6, 8)));
}

#[test]
fn ipv6_addr_5() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff\xff\xff\xff\xff\xff\xff"[..]);
    let mut decoder = Decoder::main(bytes);
    let result = decoder.ipv6_addr();
    assert_eq!(result, Err(DecodeError::NotEnoughBytes(8, 10)));
}

#[test]
fn ipv6_addr_6() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"[..]);
    let mut decoder = Decoder::main(bytes);
    let result = decoder.ipv6_addr();
    assert_eq!(result, Err(DecodeError::NotEnoughBytes(10, 12)));
}

#[test]
fn ipv6_addr_7() {
    let bytes = Bytes::copy_from_slice(&b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"[..]);
    let mut decoder = Decoder::main(bytes);
    let result = decoder.ipv6_addr();
    assert_eq!(result, Err(DecodeError::NotEnoughBytes(12, 14)));
}

#[test]
fn ipv6_addr_8() {
    let bytes =
        Bytes::copy_from_slice(&b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"[..]);
    let mut decoder = Decoder::main(bytes);
    let result = decoder.ipv6_addr();
    assert_eq!(result, Err(DecodeError::NotEnoughBytes(14, 16)));
}
