use crate::{
    encode::{helpers::BitMap, Encoder},
    rr::{AlgorithmType, DigestType, NonEmptyBTreeSet, Type, DNSKEY, DS, NSEC},
    EncodeResult,
};
use bytes::BytesMut;
use std::{collections::btree_set::Iter, iter::Peekable};

impl Encoder {
    fn rr_nsec_type_bit_map(
        &mut self,
        iter: &mut Peekable<Iter<Type>>,
        window_block_number: u8,
    ) -> EncodeResult<()> {
        let start = (window_block_number as u16) << u8::BITS;
        let end = start + u8::MAX as u16;

        let mut bit_map = BitMap::default();
        while let Some(&r#type) = iter.next_if(|&&x| start <= x as u16 && x as u16 <= end) {
            let index = (r#type as u16 - start) as usize;
            bit_map.set_bit(index);
        }
        let bytes: BytesMut = bit_map.into();
        self.bytes.extend(bytes);
        Ok(())
    }

    fn rr_nsec_type_bit_maps(&mut self, types: &NonEmptyBTreeSet<Type>) -> EncodeResult<()> {
        let mut iter = types.iter().peekable();
        if let Some(&&r#type) = iter.peek() {
            let window_block_number = (r#type as u16 >> u8::BITS) as u8;
            self.u8(window_block_number);
            let length_index = self.create_length_index_u8();
            self.rr_nsec_type_bit_map(&mut iter, window_block_number)?;
            self.set_length_index_u8(length_index)?;
        }
        Ok(())
    }

    pub(super) fn rr_nsec(&mut self, nsec: &NSEC) -> EncodeResult<()> {
        self.domain_name(&nsec.domain_name)?;
        self.rr_type(&Type::NSEC);
        self.rr_class(&nsec.class);
        self.u32(nsec.ttl);
        let length_index = self.create_length_index_u16();
        self.domain_name(&nsec.next_domain_name)?;
        self.rr_nsec_type_bit_maps(&nsec.types)?;
        self.set_length_index_u16(length_index)
    }

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
        let length_index = self.create_length_index_u16();
        self.u16(dnskey.get_flags());
        self.u8(3);
        self.rr_algorithm_type(dnskey.algorithm_type);
        self.vec(&dnskey.public_key);
        self.set_length_index_u16(length_index)
    }

    pub(super) fn rr_ds(&mut self, ds: &DS) -> EncodeResult<()> {
        self.domain_name(&ds.domain_name)?;
        self.rr_type(&Type::DS);
        self.rr_class(&ds.class);
        self.u32(ds.ttl);
        let length_index = self.create_length_index_u16();
        self.u16(ds.key_tag);
        self.rr_algorithm_type(ds.algorithm_type);
        self.rr_digest_type(ds.digest_type);
        self.vec(&ds.digest);
        self.set_length_index_u16(length_index)
    }
}
