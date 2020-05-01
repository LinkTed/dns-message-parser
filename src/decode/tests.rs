use bytes::Bytes;

use super::{decode_string, decode_u16, decode_u32, decode_u8, DecodeError};

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
fn string_error() {
    let bytes = Bytes::copy_from_slice(&b"\x0f\x41\x42"[..]);
    let mut offset = 0;
    let result = decode_string(&bytes, &mut offset);
    assert_eq!(result, Err(DecodeError::NotEnoughData));
}
