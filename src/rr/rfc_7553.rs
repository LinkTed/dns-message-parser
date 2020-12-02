use super::Class;
use crate::DomainName;
use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct URI {
    pub domain_name: DomainName,
    pub ttl: u32,
    pub class: Class,
    pub priority: u16,
    pub weight: u16,
    pub uri: String,
}

impl_to_type!(URI);

impl Display for URI {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} {} {} URI {} {} {}",
            self.domain_name, self.ttl, self.class, self.priority, self.weight, self.uri,
        )
    }
}
