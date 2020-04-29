use bytes::Bytes;

use crate::{Class, DomainName, QClass, QClass_, QType, QType_, Question, Type};

use num_traits::FromPrimitive;

use super::{decode_u16, DecodeError, DecodeResult};

impl QType {
    pub fn decode(bytes: &Bytes, offset: &mut usize) -> DecodeResult<QType> {
        let buffer = decode_u16(bytes, offset)?;
        if let Some(type_) = Type::from_u16(buffer) {
            Ok(QType::Type(type_))
        } else if let Some(qtype_) = QType_::from_u16(buffer) {
            Ok(QType::QType(qtype_))
        } else {
            Err(DecodeError::TypeError)
        }
    }
}

impl QClass {
    pub fn decode(bytes: &Bytes, offset: &mut usize) -> DecodeResult<QClass> {
        let buffer = decode_u16(bytes, offset)?;
        if let Some(class) = Class::from_u16(buffer) {
            Ok(QClass::Class(class))
        } else if let Some(qclass_) = QClass_::from_u16(buffer) {
            Ok(QClass::QClass(qclass_))
        } else {
            Err(DecodeError::ClassError)
        }
    }
}

impl Question {
    pub fn decode(bytes: &Bytes, offset: &mut usize) -> DecodeResult<Question> {
        let domain_name = DomainName::decode(bytes, offset)?;
        let qtype = QType::decode(bytes, offset)?;
        let qclass = QClass::decode(bytes, offset)?;

        Ok(Question {
            domain_name,
            qtype,
            qclass,
        })
    }
}
