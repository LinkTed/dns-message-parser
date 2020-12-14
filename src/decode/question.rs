use crate::decode::Decoder;
use crate::{DecodeError, DecodeResult, QClass, QType, Question};
use std::convert::TryFrom;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    pub fn q_type(&mut self) -> DecodeResult<QType> {
        let buffer = self.u16()?;
        match QType::try_from(buffer) {
            Ok(q_type) => Ok(q_type),
            Err(buffer) => Err(DecodeError::QType(buffer)),
        }
    }

    pub fn q_class(&mut self) -> DecodeResult<QClass> {
        let buffer = self.u16()?;
        match QClass::try_from(buffer) {
            Ok(q_class) => Ok(q_class),
            Err(buffer) => Err(DecodeError::QClass(buffer)),
        }
    }

    pub fn question(&mut self) -> DecodeResult<Question> {
        let domain_name = self.domain_name()?;
        let q_type = self.q_type()?;
        let q_class = self.q_class()?;

        Ok(Question {
            domain_name,
            q_type,
            q_class,
        })
    }
}

impl_decode!(QType, q_type);

impl_decode!(QClass, q_class);

impl_decode!(Question, question);
