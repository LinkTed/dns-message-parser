use crate::{Opcode, Question, RCode, RR};

use std::fmt::{Display, Formatter, Result as FmtResult};

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

impl Display for Flags {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        if self.qr {
            write!(f, "qr ")?;
        }

        write!(f, "{:?} ", self.opcode)?;

        if self.aa {
            write!(f, "aa ")?;
        }

        if self.tc {
            write!(f, "tc ")?;
        }

        if self.rd {
            write!(f, "rd ")?;
        }

        if self.ra {
            write!(f, "ra ")?;
        }

        if self.ad {
            write!(f, "ad ")?;
        }

        if self.cd {
            write!(f, "cd ")?;
        }

        write!(f, "{:?}", self.rcode)
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

fn print_slice<T>(f: &mut Formatter<'_>, slice: &[T]) -> FmtResult
where
    T: Display,
{
    write!(f, "[")?;
    for e in slice {
        write!(f, "{}, ", e)?;
    }
    write!(f, "]")?;
    Ok(())
}

impl Display for Dns {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{} {} ", self.id, self.flags)?;

        if !self.questions.is_empty() {
            write!(f, "questions ")?;
            print_slice(f, &self.questions)?;
            write!(f, " ")?;
        }

        if !self.answers.is_empty() {
            write!(f, "answers ")?;
            print_slice(f, &self.answers)?;
            write!(f, " ")?;
        }

        if !self.authorities.is_empty() {
            write!(f, "authorities ")?;
            print_slice(f, &self.authorities)?;
            write!(f, " ")?;
        }

        if !self.additionals.is_empty() {
            write!(f, "additionals ")?;
            print_slice(f, &self.additionals)?;
        }

        Ok(())
    }
}
