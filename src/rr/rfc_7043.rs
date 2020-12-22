use crate::rr::Class;
use crate::DomainName;
use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EUI48 {
    pub domain_name: DomainName,
    pub ttl: u32,
    pub class: Class,
    pub eui_48: [u8; 6],
}

impl Display for EUI48 {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} {} {} EUI48 {:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
            self.domain_name,
            self.ttl,
            self.class,
            self.eui_48[0],
            self.eui_48[1],
            self.eui_48[2],
            self.eui_48[3],
            self.eui_48[4],
            self.eui_48[5]
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EUI64 {
    pub domain_name: DomainName,
    pub ttl: u32,
    pub class: Class,
    pub eui_64: [u8; 8],
}

impl Display for EUI64 {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} {} {} EUI64 {:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
            self.domain_name,
            self.ttl,
            self.class,
            self.eui_64[0],
            self.eui_64[1],
            self.eui_64[2],
            self.eui_64[3],
            self.eui_64[4],
            self.eui_64[5],
            self.eui_64[6],
            self.eui_64[7]
        )
    }
}
