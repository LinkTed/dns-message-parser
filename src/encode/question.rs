use crate::encode::Encoder;
use crate::question::{QClass, QType, Question};
use crate::EncodeResult;

impl Encoder {
    #[inline]
    fn question_type(&mut self, q_type: &QType) {
        self.u16(q_type.clone() as u16);
    }

    #[inline]
    fn question_class(&mut self, q_class: &QClass) {
        self.u16(q_class.clone() as u16);
    }

    pub(super) fn question(&'_ mut self, question: &Question) -> EncodeResult<()> {
        // TODO CHECK A only A
        self.domain_name(&question.domain_name)?;
        self.question_type(&question.q_type);
        self.question_class(&question.q_class);
        Ok(())
    }
}

impl_encode_without_result!(QType, question_type);

impl_encode_without_result!(QClass, question_class);

impl_encode!(Question, question);
