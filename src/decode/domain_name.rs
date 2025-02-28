use crate::{
    decode::Decoder, domain_name::DOMAIN_NAME_MAX_RECURSION, DecodeError, DecodeResult, DomainName,
};
use std::{collections::HashSet, str::from_utf8, usize};

const COMPRESSION_BITS: u8 = 0b1100_0000;
const COMPRESSION_BITS_REV: u8 = 0b0011_1111;

#[inline]
const fn is_compressed(length: u8) -> bool {
    (length & COMPRESSION_BITS) == COMPRESSION_BITS
}

#[inline]
const fn get_offset(length_1: u8, length_2: u8) -> u16 {
    (((length_1 & COMPRESSION_BITS_REV) as u16) << 8) | length_2 as u16
}

enum DomainNameLength {
    Compressed(u16),
    Label(u8),
}

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    fn domain_name_length(&mut self) -> DecodeResult<DomainNameLength> {
        let length = self.u8()?;
        if is_compressed(length) {
            let offset = self.u8()?;
            Ok(DomainNameLength::Compressed(get_offset(length, offset)))
        } else {
            Ok(DomainNameLength::Label(length))
        }
    }

    pub(super) fn domain_name(&mut self) -> DecodeResult<DomainName> {
        let mut domain_name = DomainName::default();

        loop {
            match self.domain_name_length()? {
                DomainNameLength::Compressed(offset) => {
                    self.domain_name_recursion(&mut domain_name, offset)?;
                    return Ok(domain_name);
                }
                DomainNameLength::Label(0) => return Ok(domain_name),
                DomainNameLength::Label(length) => {
                    self.domain_name_label(&mut domain_name, length)?
                }
            }
        }
    }

    fn domain_name_label(&mut self, domain_name: &mut DomainName, length: u8) -> DecodeResult<()> {
        let buffer = self.read(length as usize)?;
        let label = from_utf8(buffer.as_ref())?;
        let label = label.parse()?;
        domain_name.append_label(label)?;
        Ok(())
    }

    fn domain_name_recursion(&self, domain_name: &mut DomainName, offset: u16) -> DecodeResult<()> {
        let mut decoder = self.new_main_offset(offset);
        let mut recursions = HashSet::new();

        loop {
            match decoder.domain_name_length()? {
                DomainNameLength::Compressed(offset) => {
                    if recursions.insert(offset) {
                        let recursions_len = recursions.len();
                        if recursions_len > DOMAIN_NAME_MAX_RECURSION {
                            return Err(DecodeError::MaxRecursion(recursions_len));
                        }
                    } else {
                        return Err(DecodeError::EndlessRecursion(offset));
                    }

                    decoder.offset = offset as usize;
                }
                DomainNameLength::Label(0) => return Ok(()),
                DomainNameLength::Label(length) => {
                    decoder.domain_name_label(domain_name, length)?;
                }
            }
        }
    }
}

impl_decode!(DomainName, domain_name);
