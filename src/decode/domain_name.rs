use bytes::Bytes;

use crate::DomainName;

use super::{decode_u8, DecodeError, DecodeResult};

use std::str::from_utf8;

const DOMAIN_NAME_MAX_RECURSION: usize = 16;

impl DomainName {
    pub fn decode(bytes: &Bytes, offset: &mut usize) -> DecodeResult<DomainName> {
        let mut domain_name = DomainName::default();
        DomainName::decode_recursion(bytes, offset, &mut domain_name, 0)?;
        Ok(domain_name)
    }

    fn decode_recursion(
        bytes: &Bytes,
        offset: &mut usize,
        domain_name: &mut DomainName,
        recursion: usize,
    ) -> DecodeResult<()> {
        if recursion > DOMAIN_NAME_MAX_RECURSION {
            return Err(DecodeError::MaxRecursionError);
        }

        let mut length = decode_u8(bytes, offset)?;
        while length != 0 {
            let compressed = (length & 0b1100_0000) == 0b1100_0000;
            if compressed {
                let buffer = decode_u8(bytes, offset)?;
                let mut recursion_offset =
                    ((length as usize & 0b0011_1111) << 8) as usize | buffer as usize;
                DomainName::decode_recursion(
                    bytes,
                    &mut recursion_offset,
                    domain_name,
                    recursion + 1,
                )?;
                break;
            } else {
                let start = *offset;
                *offset += length as usize;
                if let Some(buffer) = bytes.get(start..*offset) {
                    let label = from_utf8(buffer)?;
                    domain_name.append_label(label)?;
                } else {
                    return Err(DecodeError::NotEnoughData);
                }
                length = decode_u8(bytes, offset)?;
            }
        }

        Ok(())
    }
}
