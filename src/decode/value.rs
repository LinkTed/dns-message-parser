use bytes::{Buf, Bytes};

use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::from_utf8;

use super::{DecodeError, DecodeResult};

pub(super) fn decode_u8(bytes: &Bytes, offset: &mut usize) -> DecodeResult<u8> {
    let start = *offset;
    *offset += size_of::<u8>();

    if let Some(buf) = bytes.get(start..*offset) {
        Ok(buf[0])
    } else {
        Err(DecodeError::NotEnoughData)
    }
}

pub(super) fn decode_u16(bytes: &Bytes, offset: &mut usize) -> DecodeResult<u16> {
    let start = *offset;
    *offset += size_of::<u16>();

    if let Some(mut buf) = bytes.get(start..*offset) {
        Ok(buf.get_u16())
    } else {
        Err(DecodeError::NotEnoughData)
    }
}

pub(super) fn decode_u32(bytes: &Bytes, offset: &mut usize) -> DecodeResult<u32> {
    let start = *offset;
    *offset += size_of::<u32>();

    if let Some(mut buf) = bytes.get(start..*offset) {
        Ok(buf.get_u32())
    } else {
        Err(DecodeError::NotEnoughData)
    }
}

pub(super) fn decode_string(bytes: &Bytes, offset: &mut usize) -> DecodeResult<String> {
    let length = decode_u8(bytes, offset)? as usize;
    let start = *offset;
    *offset += length;

    if let Some(buffer) = bytes.get(start..*offset) {
        let string = from_utf8(buffer)?;

        Ok(String::from(string))
    } else {
        Err(DecodeError::NotEnoughData)
    }
}

pub(super) fn decode_ipv4_addr(bytes: &Bytes, offset: &mut usize) -> DecodeResult<Ipv4Addr> {
    let a = decode_u8(bytes, offset)?;
    let b = decode_u8(bytes, offset)?;
    let c = decode_u8(bytes, offset)?;
    let d = decode_u8(bytes, offset)?;

    Ok(Ipv4Addr::new(a, b, c, d))
}

pub(super) fn decode_ipv6_addr(bytes: &Bytes, offset: &mut usize) -> DecodeResult<Ipv6Addr> {
    let a = decode_u16(bytes, offset)?;
    let b = decode_u16(bytes, offset)?;
    let c = decode_u16(bytes, offset)?;
    let d = decode_u16(bytes, offset)?;
    let e = decode_u16(bytes, offset)?;
    let f = decode_u16(bytes, offset)?;
    let g = decode_u16(bytes, offset)?;
    let h = decode_u16(bytes, offset)?;

    Ok(Ipv6Addr::new(a, b, c, d, e, f, g, h))
}
