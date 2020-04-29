mod decode;
use decode::DecodeData;

mod r_data;

use bytes::Bytes;

use crate::{DomainName, RData, Type, RR};

use super::{
    decode_ipv4_addr, decode_ipv6_addr, decode_string, decode_u16, decode_u32, decode_u8,
    DecodeError, DecodeResult,
};

impl RR {
    pub fn decode(bytes: &Bytes, offset: &mut usize) -> DecodeResult<RR> {
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
