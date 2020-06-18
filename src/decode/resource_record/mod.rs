mod decode;
mod decode_data;
mod r_data;

use crate::{DomainName, RData, Type, RR};
use decode_data::DecodeData;
use std::ops::Deref;

use super::{
    decode_ipv4_addr, decode_ipv6_addr, decode_string, decode_u16, decode_u32, decode_u8,
    DecodeError, DecodeResult,
};

impl RR {
    pub fn decode<T>(bytes: &T, offset: &mut usize) -> DecodeResult<RR>
    where
        T: Deref<Target = [u8]>,
    {
        let domain_name = DomainName::decode(bytes, offset)?;
        let type_ = Type::decode(bytes, offset)?;
        let (class, ttl, rdata) = RData::decode(bytes, offset, &type_)?;

        Ok(RR {
            domain_name,
            class,
            ttl,
            rdata,
        })
    }
}
