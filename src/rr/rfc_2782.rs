use super::Class;
use crate::DomainName;
use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SRV {
    pub domain_name: DomainName,
    pub ttl: u32,
    pub class: Class,
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: DomainName,
}

impl_to_type!(SRV);

impl Display for SRV {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} {} {} SRV {} {} {} {}",
            self.domain_name,
            self.ttl,
            self.class,
            self.priority,
            self.weight,
            self.port,
            self.target
        )
    }
}
