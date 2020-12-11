use crate::encode::Encoder;
use crate::{Dns, EncodeError, EncodeResult, Flags};
use num_traits::ToPrimitive;

impl Encoder {
    pub(super) fn flags(&mut self, flags: &Flags) -> EncodeResult<()> {
        let mut buffer = 0u8;
        if flags.qr {
            buffer |= 0b1000_0000;
        }
        if let Some(opcode) = flags.opcode.to_u8() {
            buffer |= opcode << 3;
        } else {
            return Err(EncodeError::Opcode(flags.opcode.clone()));
        }
        if flags.aa {
            buffer |= 0b0000_0100;
        }
        if flags.tc {
            buffer |= 0b0000_0010;
        }
        if flags.rd {
            buffer |= 0b0000_0001;
        }
        self.u8(buffer);

        buffer = 0;
        if flags.ra {
            buffer |= 0b1000_0000;
        }
        if flags.ad {
            buffer |= 0b0010_0000;
        }
        if flags.cd {
            buffer |= 0b0001_0000;
        }
        if let Some(rcode) = flags.rcode.to_u8() {
            buffer |= rcode;
        } else {
            return Err(EncodeError::RCode(flags.rcode.clone()));
        }
        self.u8(buffer);

        Ok(())
    }

    pub(super) fn dns(&mut self, dns: &Dns) -> EncodeResult<()> {
        self.u16(dns.id);
        self.flags(&dns.flags)?;
        self.u16(dns.questions.len() as u16);
        self.u16(dns.answers.len() as u16);
        self.u16(dns.authorities.len() as u16);
        self.u16(dns.additionals.len() as u16);

        for question in &dns.questions {
            self.question(question)?;
        }

        for answer in &dns.answers {
            self.rr(answer)?;
        }

        for authority in &dns.authorities {
            self.rr(authority)?;
        }

        for additional in &dns.additionals {
            self.rr(additional)?;
        }

        Ok(())
    }
}

impl_encode!(Flags, flags);

impl_encode!(Dns, dns);
