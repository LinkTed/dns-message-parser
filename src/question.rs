use crate::{Class, DomainName, Type};

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

#[derive(Debug, Clone, FromPrimitive, ToPrimitive, PartialEq, Eq, Hash)]
pub enum QClass_ {
    ANY = 255,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum QClass {
    Class(Class),
    QClass(QClass_),
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
