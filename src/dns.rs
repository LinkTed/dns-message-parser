use crate::{Opcode, Question, RCode, RR};

#[derive(Debug, Getters, Setters, PartialEq)]
pub struct Flags {
    #[get = "pub with_prefix"]
    pub(crate) qr: bool,
    #[get = "pub with_prefix"]
    pub(crate) opcode: Opcode,
    #[get = "pub with_prefix"]
    pub(crate) aa: bool,
    #[get = "pub with_prefix"]
    pub(crate) tc: bool,
    #[get = "pub with_prefix"]
    pub(crate) rd: bool,
    #[get = "pub with_prefix"]
    pub(crate) ra: bool,
    #[get = "pub with_prefix"]
    pub(crate) ad: bool, // RFC2535 6.1 The AD and CD Header Bits
    #[get = "pub with_prefix"]
    pub(crate) cd: bool, // RFC2535 6.1 The AD and CD Header Bits
    #[get = "pub with_prefix"]
    pub(crate) rcode: RCode,
}

impl Flags {
    pub fn new(
        qr: bool,
        opcode: Opcode,
        aa: bool,
        tc: bool,
        rd: bool,
        ra: bool,
        ad: bool,
        cd: bool,
        rcode: RCode,
    ) -> Flags {
        Flags {
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            ad,
            cd,
            rcode,
        }
    }
}

#[derive(Debug, Getters, Setters, PartialEq)]
pub struct Dns {
    #[get = "pub with_prefix"]
    #[set = "pub with_prefix"]
    pub(crate) id: u16,
    #[get = "pub with_prefix"]
    pub(crate) flags: Flags,
    #[get = "pub with_prefix"]
    pub(crate) questions: Vec<Question>,
    #[get = "pub with_prefix"]
    pub(crate) answers: Vec<RR>,
    #[get = "pub with_prefix"]
    pub(crate) authorities: Vec<RR>,
    #[get = "pub with_prefix"]
    pub(crate) additionals: Vec<RR>,
}

impl Dns {
    pub fn new(
        id: u16,
        flags: Flags,
        questions: Vec<Question>,
        answers: Vec<RR>,
        authorities: Vec<RR>,
        additionals: Vec<RR>,
    ) -> Dns {
        Dns {
            id,
            flags,
            questions,
            answers,
            authorities,
            additionals,
        }
    }

    pub fn is_response(&self) -> bool {
        self.flags.qr
    }
}
