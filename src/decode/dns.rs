use crate::decode::Decoder;
use crate::{DecodeError, DecodeResult, Dns, Flags, Opcode, RCode, MAXIMUM_DNS_PACKET_SIZE};
use num_traits::FromPrimitive;

impl<'a, 'b: 'a> Decoder<'a, 'b> {
    fn flags(&mut self) -> DecodeResult<Flags> {
        let buffer = self.u8()?;
        let qr = (buffer & 0b1000_0000) != 0;
        let opcode = (buffer & 0b0111_1000) >> 3;
        let opcode = if let Some(opcode) = Opcode::from_u8(opcode) {
            opcode
        } else {
            return Err(DecodeError::Opcode(opcode));
        };
        let aa = (buffer & 0b0000_0100) != 0;
        let tc = (buffer & 0b0000_0010) != 0;
        let rd = (buffer & 0b0000_0001) != 0;
        let buffer = self.u8()?;
        let ra = (buffer & 0b1000_0000) != 0;
        let z = buffer & 0b0100_0000;
        if z != 0 {
            return Err(DecodeError::ZNotZeroes(z));
        }
        let ad = (buffer & 0b0010_0000) != 0;
        let cd = (buffer & 0b0001_0000) != 0;
        let rcode = buffer & 0b0000_1111;
        if let Some(rcode) = RCode::from_u8(rcode) {
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
            Err(DecodeError::RCode(rcode))
        }
    }
}

impl<'a, 'b: 'a> Decoder<'b, 'b> {
    fn dns(&'a mut self) -> DecodeResult<Dns> {
        if self.offset != 0 {
            return Err(DecodeError::Offset(self.offset));
        }

        let bytes_len = self.bytes.len();
        if bytes_len < 12 {
            return Err(DecodeError::NotEnoughBytes(bytes_len, 12));
        } else if bytes_len > MAXIMUM_DNS_PACKET_SIZE {
            return Err(DecodeError::DnsPacketTooBig(bytes_len));
        }

        let id = self.u16()?;
        let flags = self.flags()?;
        let question_count = self.u16()?;
        let answer_count = self.u16()?;
        let authority_count = self.u16()?;
        let additional_count = self.u16()?;

        let mut questions = Vec::with_capacity(question_count as usize);
        for _ in 0..question_count {
            questions.push(self.question()?);
        }
        let mut answers = Vec::with_capacity(answer_count as usize);
        for _ in 0..answer_count {
            answers.push(self.rr()?);
        }
        let mut authorities = Vec::with_capacity(authority_count as usize);
        for _ in 0..authority_count {
            authorities.push(self.rr()?);
        }
        let mut additionals = Vec::with_capacity(additional_count as usize);
        for _ in 0..additional_count {
            additionals.push(self.rr()?);
        }

        let is_finished = self.is_finished()?;
        let dns = Dns {
            id,
            flags,
            questions,
            answers,
            authorities,
            additionals,
        };

        if is_finished {
            Ok(dns)
        } else {
            Err(DecodeError::RemainingBytes(self.offset, dns))
        }
    }
}

impl_decode!(Flags, flags);

impl_decode!(Dns, dns);
