use bytes::BytesMut;

use crate::{Dns, Flags};

use num_traits::ToPrimitive;

use super::{encode_u16, encode_u8, EncodeError, EncodeResult};

use std::collections::HashMap;

impl Flags {
    pub fn encode(&self, bytes: &mut BytesMut) -> EncodeResult {
        let mut buffer = 0u8;
        if self.qr {
            buffer |= 0b1000_0000;
        }
        if let Some(opcode) = self.opcode.to_u8() {
            buffer |= opcode << 3;
        } else {
            return Err(EncodeError::OpcodeError);
        }
        if self.aa {
            buffer |= 0b0000_0100;
        }
        if self.tc {
            buffer |= 0b0000_0010;
        }
        if self.rd {
            buffer |= 0b0000_0001;
        }
        encode_u8(bytes, buffer);

        buffer = 0;
        if self.ra {
            buffer |= 0b1000_0000;
        }
        if self.ad {
            buffer |= 0b0010_0000;
        }
        if self.cd {
            buffer |= 0b0001_0000;
        }
        if let Some(rcode) = self.rcode.to_u8() {
            buffer |= rcode;
        } else {
            return Err(EncodeError::RCodeError);
        }
        encode_u8(bytes, buffer);

        Ok(())
    }
}

impl Dns {
    pub fn encode(&self, bytes: &mut BytesMut) -> EncodeResult {
        encode_u16(bytes, self.id);
        self.flags.encode(bytes)?;
        encode_u16(bytes, self.questions.len() as u16);
        encode_u16(bytes, self.answers.len() as u16);
        encode_u16(bytes, self.authorities.len() as u16);
        encode_u16(bytes, self.additionals.len() as u16);

        let mut compression = HashMap::new();

        for question in &self.questions {
            question.encode(bytes, &mut compression)?;
        }

        for answer in &self.answers {
            answer.encode(bytes, &mut compression)?;
        }

        for authority in &self.authorities {
            authority.encode(bytes, &mut compression)?;
        }

        for additional in &self.additionals {
            additional.encode(bytes, &mut compression)?;
        }

        Ok(())
    }
}
