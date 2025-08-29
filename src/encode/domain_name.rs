use crate::domain_name::DOMAIN_NAME_MAX_RECURSION;
use crate::encode::Encoder;
use crate::label::Label;
use crate::{DomainName, EncodeError, EncodeResult};
use std::collections::HashMap;

const MAX_OFFSET: u16 = 0b0011_1111_1111_1111;
const COMPRESSION_BITS: u16 = 0b1100_0000_0000_0000;

impl Encoder {
    #[inline]
    fn compress(&mut self, domain_name: &DomainName) -> EncodeResult<Option<usize>> {
        if let Some((index, recursion)) = self.domain_name_index.get(domain_name) {
            let index = *index;
            if MAX_OFFSET < index {
                return Err(EncodeError::Compression(index));
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
    fn label(&mut self, label: &Label) -> EncodeResult<u16> {
        let index = self.get_offset()?;
        self.string_with_len(label.as_ref())?;
        Ok(index)
    }

    #[inline]
    fn merge_domain_name_index(
        &mut self,
        domain_name_index: HashMap<DomainName, u16>,
        recursion: usize,
    ) -> EncodeResult<()> {
        if recursion > DOMAIN_NAME_MAX_RECURSION {
            return Err(EncodeError::MaxRecursion(recursion));
        }

        for (domain_name_str, index) in domain_name_index {
            self.domain_name_index
                .insert(domain_name_str, (index, recursion));
        }
        Ok(())
    }

    pub(super) fn domain_name(&mut self, domain_name: &DomainName) -> EncodeResult<()> {
        let mut domain_name_index = HashMap::new();
        for (label, domain_name) in domain_name.iter() {
            if let Some(recursion) = self.compress(&domain_name)? {
                self.merge_domain_name_index(domain_name_index, recursion + 1)?;
                return Ok(());
            }

            let index = self.label(&label)?;
            if index <= MAX_OFFSET {
                domain_name_index.insert(domain_name, index);
            }
        }
        self.string_with_len("")?;
        self.merge_domain_name_index(domain_name_index, 0)?;
        Ok(())
    }
}

impl DomainName {
    fn iter(&self) -> DomainNameIter<'_> {
        DomainNameIter { labels: &self.0 }
    }
}

struct DomainNameIter<'a> {
    labels: &'a [Label],
}

impl<'a> Iterator for DomainNameIter<'a> {
    type Item = (Label, DomainName);

    fn next(&mut self) -> Option<Self::Item> {
        if self.labels.is_empty() {
            return None;
        }

        let label = self.labels[0].clone();
        let domain_name = DomainName(self.labels.to_vec());
        self.labels = &self.labels[1..];
        Some((label, domain_name))
    }
}
impl_encode!(DomainName, domain_name);
