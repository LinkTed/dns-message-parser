use crate::domain_name::DOMAIN_NAME_MAX_RECURSION;
use crate::encode::Encoder;
use crate::{DomainName, EncodeError, EncodeResult};
use std::collections::HashMap;

const MAX_OFFSET: u16 = 0b0011_1111_1111_1111;
const COMPRESSION_BITS: u16 = 0b1100_0000_0000_0000;

impl Encoder {
    #[inline]
    fn compress(&mut self, domain_name_str: &str) -> EncodeResult<Option<usize>> {
        if let Some((index, recursion)) = self.domain_name_index.get(domain_name_str) {
            let index = *index;
            if MAX_OFFSET < index {
                return Err(EncodeError::CompressionError(index));
            }

            let recursion = *recursion;
            if recursion > DOMAIN_NAME_MAX_RECURSION {
                return Ok(None);
            }

            let index = COMPRESSION_BITS | index;
            self.u16(index);

            Ok(Some(recursion))
        } else {
            Ok(None)
        }
    }

    #[inline]
    fn label(&mut self, label: &str) -> EncodeResult<u16> {
        let index = self.get_offset()?;
        self.string(label)?;
        Ok(index)
    }

    #[inline]
    fn merge_domain_name_index(
        &mut self,
        domain_name_index: HashMap<String, u16>,
        recursion: usize,
    ) -> EncodeResult<()> {
        if recursion > DOMAIN_NAME_MAX_RECURSION {
            return Err(EncodeError::MaxRecursionError(recursion));
        }

        for (domain_name_str, index) in domain_name_index {
            self.domain_name_index
                .insert(domain_name_str, (index, recursion));
        }
        Ok(())
    }

    pub(super) fn domain_name(&mut self, domain_name: &DomainName) -> EncodeResult<()> {
        let mut domain_name_index = HashMap::new();
        for (label, domain_name_str) in domain_name.iter() {
            if let Some(recursion) = self.compress(domain_name_str)? {
                self.merge_domain_name_index(domain_name_index, recursion + 1)?;
                return Ok(());
            }

            let index = self.label(label)?;
            if index <= MAX_OFFSET {
                domain_name_index.insert(domain_name_str.to_string(), index);
            }
        }
        self.string("")?;
        self.merge_domain_name_index(domain_name_index, 0)?;
        Ok(())
    }
}

impl DomainName {
    fn iter(&self) -> DomainNameIter {
        DomainNameIter {
            domain_name_str: self.as_str(),
        }
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

struct DomainNameIter<'a> {
    domain_name_str: &'a str,
}

impl<'a> Iterator for DomainNameIter<'a> {
    type Item = (&'a str, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.domain_name_str.find('.')?;
        let (label, remain) = self.domain_name_str.split_at(index);
        let remain = remain.get(1..)?;
        let domain_name_str = self.domain_name_str;
        self.domain_name_str = remain;
        if label.is_empty() {
            None
        } else {
            Some((label, domain_name_str))
        }
    }
}

impl_encode!(DomainName, domain_name);
