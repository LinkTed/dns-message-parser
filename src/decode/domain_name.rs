use crate::{
    decode::Decoder, domain_name::DOMAIN_NAME_MAX_RECURSION, DecodeError, DecodeResult, DomainName,
};
use std::{collections::HashSet, str::from_utf8};

const COMPRESSION_BITS: u8 = 0b1100_0000;
const COMPRESSION_BITS_REV: u8 = 0b0011_1111;

#[inline]
const fn is_compressed(length: u8) -> bool {
    (length & COMPRESSION_BITS) == COMPRESSION_BITS
}

#[inline]
const fn get_offset(length_1: u8, length_2: u8) -> usize {
    (((length_1 & COMPRESSION_BITS_REV) as usize) << 8) | length_2 as usize
}

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    pub(super) fn domain_name(&mut self) -> DecodeResult<DomainName> {
        let mut domain_name = DomainName::default();
        let mut recursions = HashSet::new();
        self.domain_name_recursion(&mut domain_name, &mut recursions)?;
        Ok(domain_name)
    }

    fn domain_name_recursion(
        &mut self,
        domain_name: &mut DomainName,
        recursions: &mut HashSet<usize>,
    ) -> DecodeResult<()> {
        let recursions_len = recursions.len();
        if recursions_len > DOMAIN_NAME_MAX_RECURSION {
            return Err(DecodeError::MaxRecursion(recursions_len));
        }

        let mut length = self.u8()?;
        while length != 0 {
            if is_compressed(length) {
                let buffer = self.u8()?;
                let offset = get_offset(length, buffer);
                if recursions.insert(offset) {
                    let mut decoder = self.new_main_offset(offset);
                    return decoder.domain_name_recursion(domain_name, recursions);
                } else {
                    return Err(DecodeError::EndlessRecursion(offset));
                }
            } else {
                let buffer = self.read(length as usize)?;
                let label = from_utf8(buffer.as_ref())?;
                let label = label.parse()?;
                domain_name.append_label(label)?;
                length = self.u8()?;
            }
        }

        Ok(())
    }
}

impl_decode!(DomainName, domain_name);
