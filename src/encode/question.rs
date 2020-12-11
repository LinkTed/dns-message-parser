use crate::encode::Encoder;
use crate::{EncodeError, EncodeResult, QClass, QType, Question};
use num_traits::ToPrimitive;

impl Encoder {
    fn question_type(&mut self, q_type: &QType) -> EncodeResult<()> {
        if let Some(buffer) = q_type.to_u16() {
            self.u16(buffer);
            Ok(())
        } else {
            Err(EncodeError::QType(q_type.clone()))
        }
    }

    fn question_class(&mut self, q_class: &QClass) -> EncodeResult<()> {
        if let Some(buffer) = q_class.to_u16() {
            self.u16(buffer);
            Ok(())
        } else {
            Err(EncodeError::QClass(q_class.clone()))
        }
    }

    pub(super) fn question(&'_ mut self, question: &Question) -> EncodeResult<()> {
        // TODO CHECK A only A
        self.domain_name(&question.domain_name)?;
        self.question_type(&question.q_type)?;
        self.question_class(&question.q_class)
    }
}

impl_encode!(QType, question_type);

impl_encode!(QClass, question_class);

impl_encode!(Question, question);
