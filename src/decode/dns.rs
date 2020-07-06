use super::{decode_u16, decode_u8, DecodeError, DecodeResult};
use crate::{Dns, Flags, Opcode, Question, RCode, MAXIMUM_DNS_PACKET_SIZE, RR};
use num_traits::FromPrimitive;
use std::ops::Deref;

impl Flags {
    pub fn decode<T>(bytes: &T, offset: &mut usize) -> DecodeResult<Flags>
    where
        T: Deref<Target = [u8]>,
    {
        let buffer = decode_u8(bytes, offset)?;
        let qr = (buffer & 0b1000_0000) != 0;
        let opcode = if let Some(opcode) = Opcode::from_u8((buffer & 0b0111_1000) >> 3) {
            opcode
        } else {
            return Err(DecodeError::OpcodeError);
        };
        let aa = (buffer & 0b0000_0100) != 0;
        let tc = (buffer & 0b0000_0010) != 0;
        let rd = (buffer & 0b0000_0001) != 0;
        let buffer = decode_u8(bytes, offset)?;
        let ra = (buffer & 0b1000_0000) != 0;
        if (buffer & 0b0100_0000) != 0 {
            return Err(DecodeError::ZNotZeroes);
        }
        let ad = (buffer & 0b0010_0000) != 0;
        let cd = (buffer & 0b0001_0000) != 0;
        if let Some(rcode) = RCode::from_u8(buffer & 0b0000_1111) {
            Ok(Flags {
                qr,
                opcode,
                aa,
                tc,
                rd,
                ra,
                ad,
                cd,
                rcode,
            })
        } else {
            Err(DecodeError::RCodeError)
        }
    }
}

impl Dns {
    pub fn decode<T>(bytes: &T) -> DecodeResult<Dns>
    where
        T: Deref<Target = [u8]>,
    {
        let bytes_len = bytes.len();
        if bytes_len < 12 {
            return Err(DecodeError::NotEnoughData);
        } else if bytes_len > MAXIMUM_DNS_PACKET_SIZE {
            return Err(DecodeError::TooMuchData);
        }

        let mut offset: usize = 0;
        let id = decode_u16(bytes, &mut offset)?;
        let flags = Flags::decode(bytes, &mut offset)?;
        let question_count = decode_u16(bytes, &mut offset)?;
        let answer_count = decode_u16(bytes, &mut offset)?;
        let authority_count = decode_u16(bytes, &mut offset)?;
        let additional_count = decode_u16(bytes, &mut offset)?;

        let mut questions = Vec::with_capacity(question_count as usize);
        for _ in 0..question_count {
            questions.push(Question::decode(bytes, &mut offset)?);
        }
        let mut answers = Vec::with_capacity(answer_count as usize);
        for _ in 0..answer_count {
            answers.push(RR::decode(bytes, &mut offset)?);
        }
        let mut authorities = Vec::with_capacity(authority_count as usize);
        for _ in 0..authority_count {
            authorities.push(RR::decode(bytes, &mut offset)?);
        }
        let mut additionals = Vec::with_capacity(additional_count as usize);
        for _ in 0..additional_count {
            additionals.push(RR::decode(bytes, &mut offset)?);
        }

        Ok(Dns {
            id,
            flags,
            questions,
            answers,
            authorities,
            additionals,
        })
    }
}
