use crate::encode::Encoder;
use crate::rr::{AlgorithmType, DigestType, Type, DNSKEY, DS, NSEC};
use crate::EncodeResult;
use std::collections::BTreeMap;

impl Encoder {
    fn rr_algorithm_type(&mut self, algorithm_type: AlgorithmType) {
        self.u8(algorithm_type as u8);
    }

    fn rr_digest_type(&mut self, digest_type: DigestType) {
        self.u8(digest_type as u8);
    }

    pub(super) fn rr_dnskey(&mut self, dnskey: &DNSKEY) -> EncodeResult<()> {
        self.domain_name(&dnskey.domain_name)?;
        self.rr_type(&Type::DNSKEY);
        self.rr_class(&dnskey.class);
        self.u32(dnskey.ttl);
        let length_index = self.create_length_index();
        self.u16(dnskey.get_flags());
        self.u8(3);
        self.rr_algorithm_type(dnskey.algorithm_type);
        self.vec(&dnskey.public_key);
        self.set_length_index(length_index)
    }

    pub(super) fn rr_ds(&mut self, ds: &DS) -> EncodeResult<()> {
        self.domain_name(&ds.domain_name)?;
        self.rr_type(&Type::DS);
        self.rr_class(&ds.class);
        self.u32(ds.ttl);
        let length_index = self.create_length_index();
        self.u16(ds.key_tag);
        self.rr_algorithm_type(ds.algorithm_type);
        self.rr_digest_type(ds.digest_type);
        self.vec(&ds.digest);
        self.set_length_index(length_index)
    }

    pub(super) fn rr_nsec(&mut self, nsec: &NSEC) -> EncodeResult<()> {
        self.domain_name(&nsec.domain_name)?;
        self.rr_type(&Type::NSEC);
        self.rr_class(&nsec.class);
        self.u32(nsec.ttl);
        let length_index = self.create_length_index();
        self.domain_name_without_compression(&nsec.next_domain_name)?;

        let mut windows: BTreeMap<u8, [u8; 32]> = BTreeMap::new();
        for type_ in &nsec.type_bit_maps {
            let type_value = *type_ as u16;
            let window = (type_value / 256) as u8;
            let offset = (type_value % 256) as u8;
            let bitmap = windows.entry(window).or_insert([0u8; 32]);
            let byte_index = (offset / 8) as usize;
            let bit_index = offset % 8;
            bitmap[byte_index] |= 0x80 >> bit_index;
        }

        for (window, bitmap) in windows {
            let mut length = bitmap.len();
            while length > 0 && bitmap[length - 1] == 0 {
                length -= 1;
            }
            if length == 0 {
                continue;
            }
            self.u8(window);
            self.u8(length as u8);
            self.vec(&bitmap[..length]);
        }

        self.set_length_index(length_index)
    }
}
