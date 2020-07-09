use crate::{Opcode, Question, RCode, RR};
use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug, Copy, Clone, Getters, Setters, PartialEq)]
pub struct Flags {
    pub qr: bool,
    pub opcode: Opcode,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub ad: bool, // RFC2535 6.1 The AD and CD Header Bits
    pub cd: bool, // RFC2535 6.1 The AD and CD Header Bits
    pub rcode: RCode,
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

#[derive(Debug, Clone, Getters, Setters, PartialEq)]
pub struct Dns {
    pub id: u16,
    pub flags: Flags,
    pub questions: Vec<Question>,
    pub answers: Vec<RR>,
    pub authorities: Vec<RR>,
    pub additionals: Vec<RR>,
}

impl Dns {
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
