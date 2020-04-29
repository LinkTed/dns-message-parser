use bytes::BytesMut;

use crate::{QClass, QClass_, QType, QType_, Question};

use num_traits::ToPrimitive;

use super::{encode_u16, EncodeError};

use std::collections::HashMap;

impl QType_ {
    pub fn encode(&self, bytes: &mut BytesMut) -> Result<(), EncodeError> {
        if let Some(n) = self.to_u16() {
            encode_u16(bytes, n);
            Ok(())
        } else {
            Err(EncodeError::QTypeError)
        }
    }
}

impl QType {
    pub fn encode(&self, bytes: &mut BytesMut) -> Result<(), EncodeError> {
        match self {
            QType::Type(type_) => type_.encode(bytes),
            QType::QType(qtype_) => qtype_.encode(bytes),
        }
    }
}

impl QClass_ {
    pub fn encode(&self, bytes: &mut BytesMut) -> Result<(), EncodeError> {
        if let Some(n) = self.to_u16() {
            encode_u16(bytes, n);
            Ok(())
        } else {
            Err(EncodeError::QClassError)
        }
    }
}

impl QClass {
    pub fn encode(&self, bytes: &mut BytesMut) -> Result<(), EncodeError> {
        match self {
            QClass::Class(class) => class.encode(bytes),
            QClass::QClass(qclass) => qclass.encode(bytes),
        }
    }
}

impl Question {
    pub fn encode(
        &self,
        bytes: &mut BytesMut,
        compression: &mut HashMap<String, usize>,
    ) -> Result<(), EncodeError> {
        let offset = 0;
        self.domain_name.encode(bytes, &offset, compression)?;
        self.qtype.encode(bytes)?;
        self.qclass.encode(bytes)
    }
}
