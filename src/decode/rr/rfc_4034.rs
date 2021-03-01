use super::Header;
use crate::rr::{
    AlgorithmType, DigestType, DNSKEY, DNSKEY_ZERO_MASK, DS, SECURE_ENTRY_POINT_FLAG, ZONE_KEY_FLAG,
};
use crate::DecodeResult;
use crate::{decode::Decoder, DecodeError};
use std::convert::TryFrom;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    fn rr_algorithm_type(&mut self) -> DecodeResult<AlgorithmType> {
        let buffer = self.u8()?;
        match AlgorithmType::try_from(buffer) {
            Ok(algorithm_type) => Ok(algorithm_type),
            Err(buffer) => Err(DecodeError::AlgorithmType(buffer)),
        }
    }

    fn rr_digest_type(&mut self) -> DecodeResult<DigestType> {
        let buffer = self.u8()?;
        match DigestType::try_from(buffer) {
            Ok(digest_type) => Ok(digest_type),
            Err(buffer) => Err(DecodeError::DigestType(buffer)),
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
