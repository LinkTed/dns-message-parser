use crate::{Class, DomainName, Type};

use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug, Clone, FromPrimitive, ToPrimitive, PartialEq, Eq, Hash)]
pub enum QType_ {
    AXFR = 252,
    MAILB = 253,
    MAILA = 254,
    ALL = 255,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum QType {
    Type(Type),
    QType(QType_),
}

impl Display for QType {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            QType::Type(t) => write!(f, "{:?}", t),
            QType::QType(t) => write!(f, "{:?}", t),
        }
    }
}

#[derive(Debug, Clone, FromPrimitive, ToPrimitive, PartialEq, Eq, Hash)]
pub enum QClass_ {
    ANY = 255,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum QClass {
    Class(Class),
    QClass(QClass_),
}

impl Display for QClass {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            QClass::Class(c) => write!(f, "{:?}", c),
            QClass::QClass(c) => write!(f, "{:?}", c),
        }
    }
}

#[derive(Debug, Getters, Clone, PartialEq, Eq, Hash)]
pub struct Question {
    #[get = "pub with_prefix"]
    pub(crate) domain_name: DomainName,
    #[get = "pub with_prefix"]
    pub(crate) qtype: QType,
    #[get = "pub with_prefix"]
    pub(crate) qclass: QClass,
}

impl Question {
    pub fn new(domain_name: DomainName, qclass: QClass, qtype: QType) -> Question {
        Question {
            domain_name,
            qclass,
            qtype,
        }
    }
}

impl Display for Question {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{} {} {}", self.domain_name, self.qclass, self.qtype)
    }
}
