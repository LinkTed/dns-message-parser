use super::{decode_string, decode_u16, decode_u32, DecodeError, DecodeResult};
use crate::{Class, DomainName};
use std::mem::size_of;
use std::ops::Deref;

pub(super) struct DecodeData<'a, T>
where
    T: Deref<Target = [u8]>,
{
    pub(super) bytes: &'a T,
    pub(super) offset: &'a mut usize,
}

impl<'a, T> DecodeData<'a, T>
where
    T: Deref<Target = [u8]>,
{
    pub(super) fn new(bytes: &'a T, offset: &'a mut usize) -> DecodeData<'a, T> {
        DecodeData { bytes, offset }
    }

    pub(super) fn decode_generic_rr_header(&mut self) -> DecodeResult<(Class, u32, usize)> {
        let class = Class::decode(self.bytes, self.offset)?;
        let ttl = decode_u32(self.bytes, self.offset)?;
        let rdlength = decode_u16(self.bytes, self.offset)? as usize;

        Ok((class, ttl, rdlength))
    }

    pub(super) fn decode_domain(&mut self) -> DecodeResult<(Class, u32, DomainName)> {
        let (class, ttl, rdlength) = self.decode_generic_rr_header()?;
        let start = *self.offset;

        let domain_name = DomainName::decode(self.bytes, self.offset)?;

        if *self.offset == (start + rdlength) {
            Ok((class, ttl, domain_name))
        } else {
            Err(DecodeError::LengthError)
        }
    }

    pub(super) fn decode_u16_domain(&mut self) -> DecodeResult<(Class, u32, (u16, DomainName))> {
        let (class, ttl, rdlength) = self.decode_generic_rr_header()?;
        let start = *self.offset;

        if size_of::<u16>() + 1 > rdlength {
            return Err(DecodeError::LengthError);
        }

        let u = decode_u16(self.bytes, self.offset)?;
        let domain_name = DomainName::decode(self.bytes, self.offset)?;

        if *self.offset == (start + rdlength) {
            Ok((class, ttl, (u, domain_name)))
        } else {
            Err(DecodeError::LengthError)
        }
    }

    pub(super) fn decode_domain_domain(
        &mut self,
    ) -> DecodeResult<(Class, u32, (DomainName, DomainName))> {
        let (class, ttl, rdlength) = self.decode_generic_rr_header()?;
        let start = *self.offset;

        if rdlength < 2 {
            return Err(DecodeError::LengthError);
        }

        let end = start + rdlength;

        let domain_1 = DomainName::decode(self.bytes, self.offset)?;

        if end <= *self.offset {
            return Err(DecodeError::LengthError);
        }

        let domain_2 = DomainName::decode(self.bytes, self.offset)?;

        if end == *self.offset {
            Ok((class, ttl, (domain_1, domain_2)))
        } else {
            Err(DecodeError::LengthError)
        }
    }

    pub(super) fn decode_vec(&mut self) -> DecodeResult<(Class, u32, Vec<u8>)> {
        let (class, ttl, rdlength) = self.decode_generic_rr_header()?;
        let start = *self.offset;

        *self.offset += rdlength;

        if let Some(buffer) = self.bytes.get(start..*self.offset) {
            Ok((class, ttl, Vec::from(buffer)))
        } else {
            Err(DecodeError::LengthError)
        }
    }

    pub(super) fn decode_string(&mut self) -> DecodeResult<(Class, u32, String)> {
        let (class, ttl, rdlength) = self.decode_generic_rr_header()?;
        let start = *self.offset;

        let string = decode_string(self.bytes, self.offset)?;

        if *self.offset == (start + rdlength) {
            Ok((class, ttl, string))
        } else {
            Err(DecodeError::TXTError)
        }
    }
}
