use crate::encode::Encoder;
use crate::{Dns, EncodeResult, Flags};
use bytes::BytesMut;

impl Encoder {
    pub(super) fn flags(&mut self, flags: &Flags) {
        let mut buffer = 0u8;
        if flags.qr {
            buffer |= 0b1000_0000;
        }
        let opcode = flags.opcode.clone() as u8;
        buffer |= opcode << 3;
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

        let mut buffer = 0u8;
        if flags.ra {
            buffer |= 0b1000_0000;
        }
        if flags.ad {
            buffer |= 0b0010_0000;
        }
        if flags.cd {
            buffer |= 0b0001_0000;
        }
        let rcode = flags.rcode.clone() as u8;
        buffer |= rcode;
        self.u8(buffer);
    }

    pub(super) fn dns(&mut self, dns: &Dns) -> EncodeResult<()> {
        self.u16(dns.id);
        self.flags(&dns.flags);
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

impl Flags {
    pub fn encode(&self) -> BytesMut {
        let mut encoder = Encoder::default();
        encoder.flags(self);
        encoder.bytes
    }
}

impl_encode!(Dns, dns);
