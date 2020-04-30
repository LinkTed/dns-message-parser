use bytes::BytesMut;

use crate::{Class, DomainName, Type};

use std::collections::HashMap;
use std::mem::size_of;

use super::{encode_string, encode_u16, encode_u32, EncodeError, EncodeResult};

pub(super) struct EncodeData<'a> {
    pub(super) bytes: &'a mut BytesMut,
    pub(super) bytes_rdata: BytesMut,
    pub(super) class: &'a Class,
    pub(super) ttl: u32,
}

impl<'a> EncodeData<'a> {
    pub(super) fn new(bytes: &'a mut BytesMut, class: &'a Class, ttl: u32) -> EncodeData<'a> {
        EncodeData {
            bytes,
            bytes_rdata: BytesMut::new(),
            class,
            ttl,
        }
    }

    pub(super) fn encode_generic_rr_header(&mut self, type_: Type) -> EncodeResult {
        type_.encode(self.bytes)?;
        self.class.encode(self.bytes)?;
        encode_u32(self.bytes, self.ttl);
        Ok(())
    }

    pub(super) fn get_offset(&self) -> usize {
        self.bytes.len() + size_of::<u16>()
    }

    pub(super) fn encode_domain(
        &mut self,
        type_: Type,
        domain_name: &DomainName,
        compression: &mut HashMap<String, usize>,
    ) -> EncodeResult {
        self.encode_generic_rr_header(type_)?;
        let offset = self.get_offset();
        domain_name.encode(&mut self.bytes_rdata, &offset, compression)
    }

    pub(super) fn encode_u16_domain(
        &mut self,
        type_: Type,
        u: u16,
        domain_name: &DomainName,
        compression: &mut HashMap<String, usize>,
    ) -> EncodeResult {
        self.encode_generic_rr_header(type_)?;
        let offset = self.get_offset();
        encode_u16(&mut self.bytes_rdata, u);
        domain_name.encode(&mut self.bytes_rdata, &offset, compression)
    }

    pub(super) fn encode_domain_domain(
        &mut self,
        type_: Type,
        domain_name_1: &DomainName,
        domain_name_2: &DomainName,
        compression: &mut HashMap<String, usize>,
    ) -> EncodeResult {
        self.encode_generic_rr_header(type_)?;
        let offset = self.get_offset();
        domain_name_1.encode(&mut self.bytes_rdata, &offset, compression)?;
        domain_name_2.encode(&mut self.bytes_rdata, &offset, compression)
    }

    pub(super) fn encode_vec(&mut self, type_: Type, vec: &[u8]) -> EncodeResult {
        self.encode_generic_rr_header(type_)?;
        self.bytes_rdata.extend(vec);
        Ok(())
    }

    pub(super) fn encode_string(&mut self, type_: Type, string: &str) -> EncodeResult {
        self.encode_generic_rr_header(type_)?;
        encode_string(&mut self.bytes_rdata, string)
    }

    pub(super) fn add_rdata(&mut self) -> EncodeResult {
        let length = self.bytes_rdata.len();
        if (std::u16::MAX as usize) < length {
            return Err(EncodeError::TooMuchData);
        }
        encode_u16(self.bytes, length as u16);
        self.bytes.extend(&self.bytes_rdata);
        Ok(())
    }
}
