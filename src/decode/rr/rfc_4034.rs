use super::Header;
use crate::{
    rr::{
        AlgorithmType, DigestType, NonEmptyBTreeSet, Type, DNSKEY, DNSKEY_ZERO_MASK, DS, NSEC,
        SECURE_ENTRY_POINT_FLAG, ZONE_KEY_FLAG,
    },
    DecodeResult,
    {
        decode::{helpers::BitMap, Decoder},
        DecodeError,
    },
};
use std::collections::BTreeSet;

impl<'a, 'b: 'a> Decoder<'b, 'b> {
    fn rr_nsec_type_window_block(
        &mut self,
        window_block_number: u8,
    ) -> DecodeResult<NonEmptyBTreeSet<Type>> {
        let mut types = BTreeSet::new();
        let window_block_number = (window_block_number as u16) << u8::BITS;
        let bit_map: BitMap = self.bytes()?.into();
        for index in bit_map {
            let r#type = window_block_number | index as u16;
            match Type::try_from(r#type) {
                Ok(r#type) => {
                    types.insert(r#type);
                }
                Err(r#type) => return Err(DecodeError::NSECUnknownType(r#type)),
            }
        }
        types
            .try_into()
            .map_err(|_| DecodeError::NSECTypeBitMapsEmpty)
    }

    fn rr_nsec_type_bit_map(
        &mut self,
        previous_window_block_number: &mut Option<u8>,
    ) -> DecodeResult<NonEmptyBTreeSet<Type>> {
        let window_block_number = self.u8()?;
        if let Some(previous_window_block_number) = previous_window_block_number {
            if window_block_number <= *previous_window_block_number {
                return Err(DecodeError::NSECTypeBitMapsNonIncreasingOrder);
            }
        }

        let bit_map_length = self.u8()?;
        if bit_map_length == 0 {
            return Err(DecodeError::NSECTypeBitMapsWindowBlockEmpty);
        }

        if 32 < bit_map_length {
            return Err(DecodeError::NSECTypeBitMapsWindowBlockTooBig(
                bit_map_length,
            ));
        }

        let mut bit_map = self.sub(bit_map_length as u16)?;
        let new_types = bit_map.rr_nsec_type_window_block(window_block_number)?;

        *previous_window_block_number = Some(window_block_number);

        Ok(new_types)
    }

    fn rr_nsec_type_bit_maps(&'a mut self) -> DecodeResult<NonEmptyBTreeSet<Type>> {
        let mut types = BTreeSet::new();
        let mut previous_window_block_number = None;
        while !self.is_finished()? {
            let mut new_types = self.rr_nsec_type_bit_map(&mut previous_window_block_number)?;
            types.append(new_types.as_mut());
        }
        types
            .try_into()
            .map_err(|_| DecodeError::NSECTypeBitMapsEmpty)
    }

    pub(super) fn rr_nsec(&mut self, header: Header) -> DecodeResult<NSEC> {
        let class = header.get_class()?;
        let next_domain_name = self.domain_name()?;
        let types = self.rr_nsec_type_bit_maps()?;
        let nsec = NSEC {
            domain_name: header.domain_name,
            ttl: header.ttl,
            class,
            next_domain_name,
            types,
        };
        Ok(nsec)
    }

    fn rr_algorithm_type(&mut self) -> DecodeResult<AlgorithmType> {
        let buffer = self.u8()?;
        match AlgorithmType::try_from(buffer) {
            Ok(algorithm_type) => Ok(algorithm_type),
            Err(buffer) => Err(DecodeError::AlgorithmType(buffer)),
        }
    }

    pub(super) fn rr_dnskey(&mut self, header: Header) -> DecodeResult<DNSKEY> {
        let class = header.get_class()?;
        let flags = self.u16()?;
        if flags & DNSKEY_ZERO_MASK != 0 {
            return Err(DecodeError::DNSKEYZeroFlags(flags));
        }
        let zone_key_flag = (flags & ZONE_KEY_FLAG) == ZONE_KEY_FLAG;
        let secure_entry_point_flag = (flags & SECURE_ENTRY_POINT_FLAG) == SECURE_ENTRY_POINT_FLAG;
        let protocol = self.u8()?;
        if protocol != 3 {
            return Err(DecodeError::DNSKEYProtocol(protocol));
        }
        let algorithm_type = self.rr_algorithm_type()?;
        let public_key = self.vec()?;
        let dnskey = DNSKEY {
            domain_name: header.domain_name,
            ttl: header.ttl,
            class,
            zone_key_flag,
            secure_entry_point_flag,
            algorithm_type,
            public_key,
        };
        Ok(dnskey)
    }

    fn rr_digest_type(&mut self) -> DecodeResult<DigestType> {
        let buffer = self.u8()?;
        match DigestType::try_from(buffer) {
            Ok(digest_type) => Ok(digest_type),
            Err(buffer) => Err(DecodeError::DigestType(buffer)),
        }
    }

    pub(super) fn rr_ds(&mut self, header: Header) -> DecodeResult<DS> {
        let class = header.get_class()?;
        let key_tag = self.u16()?;
        let algorithm_type = self.rr_algorithm_type()?;
        let digest_type = self.rr_digest_type()?;
        let digest = self.vec()?;
        let ds = DS {
            domain_name: header.domain_name,
            ttl: header.ttl,
            class,
            key_tag,
            algorithm_type,
            digest_type,
            digest,
        };
        Ok(ds)
    }
}
