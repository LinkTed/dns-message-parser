mod dns;

mod domain_name;

mod error;
pub use error::DecodeError;

mod question;

mod resource_record;

#[cfg(test)]
mod tests;

mod value;
use value::{decode_ipv4_addr, decode_ipv6_addr, decode_string, decode_u16, decode_u32, decode_u8};

pub type DecodeResult<T> = std::result::Result<T, DecodeError>;

use bytes::Bytes;

use crate::{Class, Type};

use num_traits::FromPrimitive;

impl Class {
    pub fn decode(bytes: &Bytes, offset: &mut usize) -> DecodeResult<Class> {
        let buffer = decode_u16(bytes, offset)?;
        if let Some(class) = Class::from_u16(buffer) {
            Ok(class)
        } else {
            Err(DecodeError::ClassError)
        }
    }
}

impl Type {
    pub fn decode(bytes: &Bytes, offset: &mut usize) -> DecodeResult<Type> {
        let buffer = decode_u16(bytes, offset)?;
        if let Some(type_) = Type::from_u16(buffer) {
            Ok(type_)
        } else {
            Err(DecodeError::TypeError)
        }
    }
}
