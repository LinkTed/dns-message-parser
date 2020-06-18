mod dns;
mod domain_name;
mod error;
mod question;
mod resource_record;
#[cfg(test)]
mod tests;
mod value;

use crate::{Class, Type};
pub use error::DecodeError;
use num_traits::FromPrimitive;
use std::ops::Deref;
use value::{decode_ipv4_addr, decode_ipv6_addr, decode_string, decode_u16, decode_u32, decode_u8};

pub type DecodeResult<T> = std::result::Result<T, DecodeError>;

impl Class {
    pub fn decode<T>(bytes: &T, offset: &mut usize) -> DecodeResult<Class>
    where
        T: Deref<Target = [u8]>,
    {
        let buffer = decode_u16(bytes, offset)?;
        if let Some(class) = Class::from_u16(buffer) {
            Ok(class)
        } else {
            Err(DecodeError::ClassError)
        }
    }
}

impl Type {
    pub fn decode<T>(bytes: &T, offset: &mut usize) -> DecodeResult<Type>
    where
        T: Deref<Target = [u8]>,
    {
        let buffer = decode_u16(bytes, offset)?;
        if let Some(type_) = Type::from_u16(buffer) {
            Ok(type_)
        } else {
            Err(DecodeError::TypeError)
        }
    }
}
