use super::{DecodeError, DecodeResult};
use bytes::Buf;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::str::from_utf8;

pub(super) fn decode_u8<T>(bytes: &T, offset: &mut usize) -> DecodeResult<u8>
where
    T: Deref<Target = [u8]>,
{
    let start = *offset;
    *offset += size_of::<u8>();

    if let Some(buf) = bytes.get(start..*offset) {
        Ok(buf[0])
    } else {
        Err(DecodeError::NotEnoughData)
    }
}

pub(super) fn decode_u16<T>(bytes: &T, offset: &mut usize) -> DecodeResult<u16>
where
    T: Deref<Target = [u8]>,
{
    let start = *offset;
    *offset += size_of::<u16>();

    if let Some(mut buf) = bytes.get(start..*offset) {
        Ok(buf.get_u16())
    } else {
        Err(DecodeError::NotEnoughData)
    }
}

pub(super) fn decode_u32<T>(bytes: &T, offset: &mut usize) -> DecodeResult<u32>
where
    T: Deref<Target = [u8]>,
{
    let start = *offset;
    *offset += size_of::<u32>();

    if let Some(mut buf) = bytes.get(start..*offset) {
        Ok(buf.get_u32())
    } else {
        Err(DecodeError::NotEnoughData)
    }
}

pub(super) fn decode_string<T>(bytes: &T, offset: &mut usize) -> DecodeResult<String>
where
    T: Deref<Target = [u8]>,
{
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

pub(super) fn decode_ipv4_addr<T>(bytes: &T, offset: &mut usize) -> DecodeResult<Ipv4Addr>
where
    T: Deref<Target = [u8]>,
{
    let a = decode_u8(bytes, offset)?;
    let b = decode_u8(bytes, offset)?;
    let c = decode_u8(bytes, offset)?;
    let d = decode_u8(bytes, offset)?;

    Ok(Ipv4Addr::new(a, b, c, d))
}

pub(super) fn decode_ipv6_addr<T>(bytes: &T, offset: &mut usize) -> DecodeResult<Ipv6Addr>
where
    T: Deref<Target = [u8]>,
{
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
