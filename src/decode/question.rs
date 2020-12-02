use crate::decode::Decoder;
use crate::{DecodeError, DecodeResult, QClass, QType, Question};
use num_traits::FromPrimitive;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    pub fn q_type(&mut self) -> DecodeResult<QType> {
        let buffer = self.u16()?;
        if let Some(q_type) = QType::from_u16(buffer) {
            Ok(q_type)
        } else {
            Err(DecodeError::QTypeError(buffer))
        }
    }

    pub fn q_class(&mut self) -> DecodeResult<QClass> {
        let buffer = self.u16()?;
        if let Some(q_class) = QClass::from_u16(buffer) {
            Ok(q_class)
        } else {
            Err(DecodeError::QClassError(buffer))
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
