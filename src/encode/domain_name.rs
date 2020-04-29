use bytes::BytesMut;

use crate::DomainName;

use std::collections::HashMap;

use super::{encode_string, encode_u16, EncodeError};

fn compress(
    bytes: &mut BytesMut,
    domain_name: &str,
    offset: &usize,
    compression: &mut HashMap<String, usize>,
) -> Result<bool, EncodeError> {
    if let Some(index) = compression.get(domain_name) {
        let index = *index;
        if bytes.len() + *offset <= index {
            return Err(EncodeError::CompressionError);
        }

        if 0b0011_1111_1111_1111 < index {
            return Err(EncodeError::CompressionError);
        }

        let index = 0b1100_0000_0000_0000 | index as u16;
        encode_u16(bytes, index);

        Ok(true)
    } else {
        Ok(false)
    }
}

impl DomainName {
    pub(crate) fn encode(
        &self,
        bytes: &mut BytesMut,
        offset: &usize,
        compression: &mut HashMap<String, usize>,
    ) -> Result<(), EncodeError> {
        if !compress(bytes, &self.domain_name, offset, compression)? {
            let mut previous = self.domain_name.as_str();
            for (label, domain_name) in self.iter() {
                compression.insert(previous.to_string(), bytes.len() + *offset);
                encode_string(bytes, label)?;
                if compress(bytes, domain_name, offset, compression)? {
                    return Ok(());
                }
                previous = domain_name;
            }
            encode_string(bytes, "")?;
        }
        Ok(())
    }

    pub fn iter(&self) -> DomainNameIter {
        DomainNameIter {
            domain_name: &self.domain_name,
        }
    }
}

pub struct DomainNameIter<'a> {
    domain_name: &'a str,
}

impl<'a> Iterator for DomainNameIter<'a> {
    type Item = (&'a str, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.domain_name.find('.')?;
        let (label, remain) = self.domain_name.split_at(index);
        let remain = remain.get(1..)?;
        self.domain_name = remain;
        if label.is_empty() {
            None
        } else {
            Some((label, remain))
        }
    }
}
