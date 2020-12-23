use crate::decode::Decoder;
use crate::{DecodeError, DecodeResult};
use bytes::Buf;
use bytes::Bytes;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::from_utf8;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    pub(super) fn u8(&mut self) -> DecodeResult<u8> {
        let buffer = self.read(size_of::<u8>())?;
        Ok(buffer[0])
    }

    pub(super) fn u16(&mut self) -> DecodeResult<u16> {
        let mut buffer = self.read(size_of::<u16>())?;
        Ok(buffer.get_u16())
    }

    pub(super) fn u32(&mut self) -> DecodeResult<u32> {
        let mut buffer = self.read(size_of::<u32>())?;
        Ok(buffer.get_u32())
    }

    pub(super) fn u64(&mut self) -> DecodeResult<u64> {
        let mut buffer = self.read(size_of::<u64>())?;
        Ok(buffer.get_u64())
    }

    pub(super) fn string(&mut self) -> DecodeResult<String> {
        let length = self.u8()? as usize;
        let buffer = self.read(length)?;
        let string = from_utf8(buffer.as_ref())?;
        Ok(String::from(string))
    }

    pub(super) fn ipv4_addr(&mut self) -> DecodeResult<Ipv4Addr> {
        let ipv4_addr = self.u32()?;
        let ipv4_addr = Ipv4Addr::from(ipv4_addr);
        Ok(ipv4_addr)
    }

    pub(super) fn ipv6_addr(&mut self) -> DecodeResult<Ipv6Addr> {
        let a = self.u16()?;
        let b = self.u16()?;
        let c = self.u16()?;
        let d = self.u16()?;
        let e = self.u16()?;
        let f = self.u16()?;
        let g = self.u16()?;
        let h = self.u16()?;

        Ok(Ipv6Addr::new(a, b, c, d, e, f, g, h))
    }

    pub(super) fn bytes(&mut self) -> DecodeResult<Bytes> {
        let bytes_len = self.bytes.len();
        if self.offset < bytes_len {
            let start = self.offset;
            self.offset = bytes_len;
            let bytes = self.bytes.slice(start..self.offset);
            Ok(bytes)
        } else {
            Err(DecodeError::NotEnoughBytes(bytes_len, self.offset))
        }
    }

    pub(super) fn vec(&mut self) -> DecodeResult<Vec<u8>> {
        let bytes = self.bytes()?;
        Ok(bytes.to_vec())
    }
}
