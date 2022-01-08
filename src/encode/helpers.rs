use crate::encode::Encoder;
use crate::{EncodeError, EncodeResult};
use bytes::{BufMut, BytesMut};
use std::convert::TryInto;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Default, Debug)]
pub(super) struct BitMap(BytesMut);

impl BitMap {
    pub fn set_bit(&mut self, index: usize) {
        let bytes_index = index / u8::BITS as usize;
        let bit_index = index % u8::BITS as usize;
        let bytes_len = self.0.len();
        if bytes_len <= bytes_index {
            self.0.resize(bytes_index + 1, 0);
        }
        self.0[bytes_index] |= 0b1000_0000 >> bit_index;
    }
}

impl From<BitMap> for BytesMut {
    fn from(bit_map: BitMap) -> BytesMut {
        bit_map.0
    }
}

pub(super) struct LengthIndexU8(usize);

pub(super) struct LengthIndexU16(usize);

impl Encoder {
    pub(super) fn u8(&mut self, n: u8) {
        self.bytes.reserve(size_of::<u8>());
        self.bytes.put_u8(n)
    }

    pub(super) fn u16(&mut self, n: u16) {
        self.bytes.reserve(size_of::<u16>());
        self.bytes.put_u16(n)
    }

    pub(super) fn set_u8(&mut self, n: u8, index: usize) -> EncodeResult<()> {
        let bytes_len = self.bytes.len();
        if index + size_of::<u8>() - 1 < bytes_len {
            self.bytes[index] = n;
            Ok(())
        } else {
            Err(EncodeError::NotEnoughBytes(bytes_len, index))
        }
    }

    fn set_u16(&mut self, n: u16, index: usize) -> EncodeResult<()> {
        let bytes = n.to_be_bytes();
        let bytes_len = self.bytes.len();
        if index + size_of::<u16>() - 1 < bytes_len {
            self.bytes[index] = bytes[0];
            self.bytes[index + 1] = bytes[1];
            Ok(())
        } else {
            Err(EncodeError::NotEnoughBytes(bytes_len, index))
        }
    }

    pub(super) fn u32(&mut self, n: u32) {
        self.bytes.reserve(size_of::<u32>());
        self.bytes.put_u32(n)
    }

    pub(super) fn u64(&mut self, n: u64) {
        self.bytes.reserve(size_of::<u64>());
        self.bytes.put_u64(n)
    }

    pub(super) fn ipv4_addr(&mut self, ipv4_addr: &Ipv4Addr) {
        let octets = ipv4_addr.octets();

        self.u8(octets[0]);
        self.u8(octets[1]);
        self.u8(octets[2]);
        self.u8(octets[3]);
    }

    pub(super) fn ipv6_addr(&mut self, ipv6_addr: &Ipv6Addr) {
        let octets = ipv6_addr.octets();

        self.u8(octets[0]);
        self.u8(octets[1]);
        self.u8(octets[2]);
        self.u8(octets[3]);
        self.u8(octets[4]);
        self.u8(octets[5]);
        self.u8(octets[6]);
        self.u8(octets[7]);
        self.u8(octets[8]);
        self.u8(octets[9]);
        self.u8(octets[10]);
        self.u8(octets[11]);
        self.u8(octets[12]);
        self.u8(octets[13]);
        self.u8(octets[14]);
        self.u8(octets[15]);
    }

    pub(super) fn string(&mut self, s: &str) -> EncodeResult<()> {
        let length = s.len();
        if length > 255 {
            return Err(EncodeError::String(length));
        }

        self.u8(length as u8);
        self.bytes.extend_from_slice(s.as_bytes());

        Ok(())
    }

    pub(super) fn vec(&mut self, v: &[u8]) {
        self.bytes.extend_from_slice(v);
    }

    #[inline]
    pub(super) fn create_length_index_u8(&mut self) -> LengthIndexU8 {
        let length_index = self.bytes.len();
        self.u8(0);
        LengthIndexU8(length_index)
    }

    #[inline]
    pub(super) fn set_length_index_u8(&mut self, length_index: LengthIndexU8) -> EncodeResult<()> {
        let length_index = length_index.0;
        let length = self.bytes.len() - (length_index + size_of::<u8>());
        if let Ok(length) = length.try_into() {
            self.set_u8(length, length_index)
        } else {
            Err(EncodeError::Length(length))
        }
    }

    #[inline]
    pub(super) fn create_length_index_u16(&mut self) -> LengthIndexU16 {
        let length_index = self.bytes.len();
        self.u16(0);
        LengthIndexU16(length_index)
    }

    #[inline]
    pub(super) fn set_length_index_u16(
        &mut self,
        length_index: LengthIndexU16,
    ) -> EncodeResult<()> {
        let length_index = length_index.0;
        let length = self.bytes.len() - (length_index + size_of::<u16>());
        if let Ok(length) = length.try_into() {
            self.set_u16(length, length_index)
        } else {
            Err(EncodeError::Length(length))
        }
    }
}
