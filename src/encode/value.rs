use bytes::{BufMut, BytesMut};

use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::EncodeError;

pub(super) fn encode_u8(bytes: &mut BytesMut, n: u8) {
    bytes.reserve(size_of::<u8>());
    bytes.put_u8(n)
}

pub(super) fn encode_u16(bytes: &mut BytesMut, n: u16) {
    bytes.reserve(size_of::<u16>());
    bytes.put_u16(n)
}

pub(super) fn encode_u32(bytes: &mut BytesMut, n: u32) {
    bytes.reserve(size_of::<u32>());
    bytes.put_u32(n)
}

pub(super) fn encode_ipv4_addr(bytes: &mut BytesMut, ipv4_addr: &Ipv4Addr) {
    let octets = ipv4_addr.octets();

    encode_u8(bytes, octets[0]);
    encode_u8(bytes, octets[1]);
    encode_u8(bytes, octets[2]);
    encode_u8(bytes, octets[3]);
}

pub(super) fn encode_ipv6_addr(bytes: &mut BytesMut, ipv6_addr: &Ipv6Addr) {
    let octets = ipv6_addr.octets();

    encode_u8(bytes, octets[0]);
    encode_u8(bytes, octets[1]);
    encode_u8(bytes, octets[2]);
    encode_u8(bytes, octets[3]);
    encode_u8(bytes, octets[4]);
    encode_u8(bytes, octets[5]);
    encode_u8(bytes, octets[6]);
    encode_u8(bytes, octets[7]);
    encode_u8(bytes, octets[8]);
    encode_u8(bytes, octets[9]);
    encode_u8(bytes, octets[10]);
    encode_u8(bytes, octets[11]);
    encode_u8(bytes, octets[12]);
    encode_u8(bytes, octets[13]);
    encode_u8(bytes, octets[14]);
    encode_u8(bytes, octets[15]);
}

pub(super) fn encode_string(bytes: &mut BytesMut, s: &str) -> Result<(), EncodeError> {
    let length = s.len();

    if length > 255 {
        return Err(EncodeError::TooMuchData);
    }

    encode_u8(bytes, length as u8);
    bytes.extend_from_slice(s.as_bytes());

    Ok(())
}
