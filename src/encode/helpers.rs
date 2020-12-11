use crate::encode::Encoder;
use crate::{EncodeError, EncodeResult};
use bytes::BufMut;
use std::convert::TryInto;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};

impl Encoder {
    pub(super) fn u8(&mut self, n: u8) {
        self.bytes.reserve(size_of::<u8>());
        self.bytes.put_u8(n)
    }

    pub(super) fn u16(&mut self, n: u16) {
        self.bytes.reserve(size_of::<u16>());
        self.bytes.put_u16(n)
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
    pub(super) fn create_length_index(&mut self) -> usize {
        let length_index = self.bytes.len();
        self.u16(0);
        length_index
    }

    #[inline]
    pub(super) fn set_length_index(&mut self, length_index: usize) -> EncodeResult<()> {
        let length = self.bytes.len() - (length_index + size_of::<u16>());
        if let Ok(length) = length.try_into() {
            self.set_u16(length, length_index)
        } else {
            Err(EncodeError::Length(length))
        }
    }
}
