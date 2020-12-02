use super::Class;
use crate::DomainName;
use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PX {
    pub domain_name: DomainName,
    pub ttl: u32,
    pub class: Class,
    pub preference: u16,
    pub map822: DomainName,
    pub mapx400: DomainName,
}

impl_to_type!(PX);

impl Display for PX {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} {} {} PX {} {} {}",
            self.domain_name, self.ttl, self.class, self.preference, self.map822, self.mapx400,
        )
    }
}
