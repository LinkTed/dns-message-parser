mod dns;

mod domain_name;

mod error;
pub use error::EncodeError;

mod question;

mod value;
use value::{encode_ipv4_addr, encode_ipv6_addr, encode_string, encode_u16, encode_u32, encode_u8};

mod resource_record;

#[cfg(test)]
mod tests;

pub type EncodeResult = std::result::Result<(), EncodeError>;

use bytes::BytesMut;

use crate::{AFSDBSubtype, Class, SSHFPAlgorithm, SSHFPType, Type};

use num_traits::ToPrimitive;

impl Type {
    pub fn encode(&self, bytes: &mut BytesMut) -> EncodeResult {
        if let Some(n) = self.to_u16() {
            encode_u16(bytes, n);
            Ok(())
        } else {
            Err(EncodeError::TypeError)
        }
    }
}

impl Class {
    pub fn encode(&self, bytes: &mut BytesMut) -> EncodeResult {
        if let Some(n) = self.to_u16() {
            encode_u16(bytes, n);
            Ok(())
        } else {
            Err(EncodeError::ClassError)
        }
    }
}

impl AFSDBSubtype {
    fn encode(&self, bytes: &mut BytesMut) -> EncodeResult {
        if let Some(n) = self.to_u16() {
            encode_u16(bytes, n);
            Ok(())
        } else {
            Err(EncodeError::AFSDBSubtypeError)
        }
    }
}

impl SSHFPAlgorithm {
    fn encode(&self, bytes: &mut BytesMut) -> EncodeResult {
        if let Some(n) = self.to_u8() {
            encode_u8(bytes, n);
            Ok(())
        } else {
            Err(EncodeError::SSHFPAlgorithmError)
        }
    }
}

impl SSHFPType {
    fn encode(&self, bytes: &mut BytesMut) -> EncodeResult {
        if let Some(n) = self.to_u8() {
            encode_u8(bytes, n);
            Ok(())
        } else {
            Err(EncodeError::SSHFPTypeError)
        }
    }
}
