use crate::encode::Encoder;
use crate::{EncodeResult, QClass, QType, Question};
use bytes::BytesMut;

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

impl QType {
    pub fn encode(&self) -> BytesMut {
        let mut encoder = Encoder::default();
        encoder.question_type(self);
        encoder.bytes
    }
}

impl QClass {
    pub fn encode(&self) -> BytesMut {
        let mut encoder = Encoder::default();
        encoder.question_class(self);
        encoder.bytes
    }
}

impl_encode!(Question, question);
